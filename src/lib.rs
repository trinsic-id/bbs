use std::ops::{Mul, Neg};

use bls12_381_plus::{
    multi_miller_loop, pairing, ExpandMsg, ExpandMsgXmd, G1Affine, G1Projective, G2Affine,
    G2Prepared, G2Projective, Gt, Scalar,
};
use encoding::{I2OSP, OS2IP};
use hashing::{hash_to_scalar, EncodeForHash};
use hkdf::Hkdf;
use sha2::{digest::generic_array::typenum::private::IsEqualPrivate, Digest, Sha256};

mod encoding;
mod hashing;

type SecretKey = Scalar;
type PublicKey = G2Projective;
type OctetString = Vec<u8>;

struct Generators {
    base_point: G1Projective,
    Q1: G1Projective,
    Q2: G1Projective,
    message_generators: Vec<G1Projective>,
}

fn create_generators(count: usize) -> Generators {
    if count < 2 {
        panic!("count must be greater than 1");
    }

    let generator_seed = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_MESSAGE_GENERATOR_SEED";
    let hash_to_curve_suite = b"BLS12381G1_XMD:SHA-256_SSWU_RO_";
    let seed_dst = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_SIG_GENERATOR_SEED_";
    let generator_dst = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_SIG_GENERATOR_DST_";
    const seed_len: usize = 48;

    let mut bytes = [0u8; 48];
    hex::decode_to_slice("8533b3fbea84e8bd9ccee177e3c56fbe1d2e33b798e491228f6ed65bb4d1e0ada07bcc4489d8751f8ba7a1b69b6eecd7", &mut bytes);

    let P1: G1Projective = G1Affine::from_compressed(&bytes).unwrap().into();

    // 1.  v = expand_message(generator_seed, seed_dst, seed_len)
    let mut v = [0u8; seed_len];
    ExpandMsgXmd::<Sha256>::expand_message(generator_seed.as_slice(), seed_dst, &mut v);

    // 2.  n = 1
    let mut n = 1i32;

    // 3.  for i in range(1, count):
    let mut generators = Vec::new();
    while generators.len() < count {
        // 4.     v = expand_message(v || I2OSP(n, 4), seed_dst, seed_len)
        ExpandMsgXmd::<Sha256>::expand_message(
            [v.to_vec(), n.to_osp(4)].concat().as_slice(),
            seed_dst,
            &mut v,
        );

        // 5.     n = n + 1
        n += 1;

        // 6.     generator_i = Identity_G1
        // 7.     candidate = hash_to_curve_g1(v, generator_dst)
        let candidate = G1Projective::hash::<ExpandMsgXmd<Sha256>>(&v, generator_dst);

        // 8.     if candidate in (generator_1, ..., generator_i):
        // 9.        go back to step 4
        if !generators.contains(&candidate) && candidate != G1Projective::identity() {
            // 10.    generator_i = candidate
            generators.push(candidate);
        }
    }

    // 11. return (generator_1, ..., generator_count)
    Generators {
        base_point: P1,
        Q1: generators[0],
        Q2: generators[1],
        message_generators: generators[2..].to_vec(),
    }
}

struct Signature {
    pub A: G1Projective,
    pub s: Scalar,
    pub e: Scalar,
}

enum Error {
    InvalidSignature,
}

impl Signature {
    // https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-00.html#name-signaturetooctets
    pub fn to_octet_string(&self) -> OctetString {
        [
            self.A.encode_for_hash(),
            self.e.to_osp(48),
            self.s.to_osp(48),
        ]
        .concat()
    }

    pub fn from_octet_string(octet_string: &OctetString) -> Result<Signature, Error> {
        let A = G1Affine::from_compressed(&octet_string[0..48].try_into().unwrap())
            .unwrap()
            .into();
        let e = Scalar::from_osp(&octet_string[48..96].to_vec());
        let s = Scalar::from_osp(&octet_string[96..144].to_vec());

        Ok(Signature { A, s, e })
    }
}

fn key_gen<T: AsRef<[u8]>>(ikm: T, key_info: &[u8]) -> SecretKey {
    let L = 48i16; // ceil((3 * ceil(log2(q))) / 16) // TODO: double check the value
    if ikm.as_ref().len() < 32 {
        panic!("Input Keying Material (IKM) too short, MUST be at least 32 bytes");
    }

    // 1. salt = INITSALT
    let mut salt = b"BBS-SIG-KEYGEN-SALT-";
    // 2. SK = 0
    let mut sk = Scalar::zero();
    // 3. while SK == 0:
    // 4.     salt = hash(salt)
    let salt_hashed = Sha256::digest(salt);

    // 5.     PRK = HKDF-Extract(salt, IKM || I2OSP(0, 1))
    let (prk, hk) = Hkdf::<Sha256>::extract(
        Some(salt_hashed[..].as_ref()),
        vec![ikm.as_ref(), 0u8.to_be_bytes().as_ref()]
            .concat()
            .as_slice(),
    );
    // 6.     OKM = HKDF-Expand(PRK, key_info || I2OSP(L, 2), L)
    let mut okm = [0u8; 48];
    hk.expand(
        vec![key_info.as_ref()[..].as_ref(), L.to_be_bytes().as_slice()]
            .concat()
            .as_slice(),
        &mut okm,
    )
    .expect("42 is a valid length for Sha256 to output");

    Scalar::from_okm(&okm)
}

// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-00.html#name-sktopk
fn sk_to_pk(sk: &SecretKey) -> PublicKey {
    G2Projective::generator() * sk
}
const ciphersuite_id: &[u8] = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_";
fn sign(sk: SecretKey, header: Option<Vec<u8>>, messages: Option<Vec<Scalar>>) -> Signature {
    let PK = sk_to_pk(&sk);

    let header = header.unwrap_or_default();
    let messages = messages.unwrap_or_default();
    let L = messages.len();

    // 2. (Q_1, Q_2, H_1, ..., H_L) = create_generators(generator_seed, L+2)
    let generators = create_generators(L + 2);

    // 1.  dom_array = (PK, L, Q_1, Q_2, H_1, ..., H_L, ciphersuite_id, header)
    // 2.  dom_for_hash = encode_for_hash(dom_array)
    let dom_for_hash = [
        PK.encode_for_hash(),
        L.encode_for_hash(),
        generators.Q1.encode_for_hash(),
        generators.Q2.encode_for_hash(),
        generators
            .message_generators
            .iter()
            .map(|g| g.encode_for_hash())
            .flatten()
            .collect::<Vec<u8>>(),
        ciphersuite_id.to_vec(),
        header.as_slice().encode_for_hash(),
    ]
    .concat();

    // 4.  domain = hash_to_scalar(dom_for_hash, 1)
    let domain = hash_to_scalar(dom_for_hash.as_slice(), 1);
    assert_eq!(domain.len(), 1, "incorrect domain scalar length");

    let domain = domain[0];

    // 5.  e_s_for_hash = encode_for_hash((SK, domain, msg_1, ..., msg_L))
    let e_s_for_hash = vec![
        sk.encode_for_hash(),
        domain.encode_for_hash(),
        messages
            .iter()
            .map(|x| x.encode_for_hash())
            .flatten()
            .collect(),
    ]
    .concat();

    // 7.  (e, s) = hash_to_scalar(e_s_for_hash, 2)
    let e_s = hash_to_scalar(e_s_for_hash.as_slice(), 2);
    assert_eq!(e_s.len(), 2, "incorrect e_s scalar length");
    let e = e_s[0];
    let s = e_s[1];

    // 8.  B = P1 + Q_1 * s + Q_2 * domain + H_1 * msg_1 + ... + H_L * msg_L
    let B = generators.base_point
        + generators.Q1 * s
        + generators.Q2 * domain
        + generators
            .message_generators
            .iter()
            .zip(messages.iter())
            .map(|(g, m)| g * m)
            .sum::<G1Projective>();

    // 9.  A = B * (1 / (SK + e))
    let A = B * (sk + e).invert().unwrap();

    Signature { A: A, s: s, e: e }
}

fn verify(
    pk: &PublicKey,
    signature: &Signature,
    header: Option<Vec<u8>>,
    messages: Option<Vec<Scalar>>,
) -> bool {
    let header = header.unwrap_or_default();
    let messages = messages.unwrap_or_default();

    let L = messages.len();
    let generators = create_generators(L + 2);

    // 6.  dom_array = (PK, L, Q_1, Q_2, H_1, ..., H_L, ciphersuite_id, header)
    // 7.  dom_for_hash = encode_for_hash(dom_array)
    let dom_for_hash = [
        pk.encode_for_hash(),
        L.encode_for_hash(),
        generators.Q1.encode_for_hash(),
        generators.Q2.encode_for_hash(),
        generators
            .message_generators
            .iter()
            .map(|g| g.encode_for_hash())
            .flatten()
            .collect::<Vec<u8>>(),
        ciphersuite_id.to_vec(),
        header.as_slice().encode_for_hash(),
    ]
    .concat();

    // 9.  domain = hash_to_scalar(dom_for_hash, 1)
    let domain = hash_to_scalar(dom_for_hash.as_slice(), 1);
    assert_eq!(domain.len(), 1, "incorrect domain scalar length");

    let domain = domain[0];

    // 10. B = P1 + Q_1 * s + Q_2 * domain + H_1 * msg_1 + ... + H_L * msg_L
    let B = generators.base_point
        + generators.Q1 * signature.s
        + generators.Q2 * domain
        + generators
            .message_generators
            .iter()
            .zip(messages.iter())
            .map(|(g, m)| g * m)
            .sum::<G1Projective>();

    // 11. if e(A, W + P2 * e) * e(B, -P2) != Identity_GT, return INVALID
    multi_miller_loop(&[
        (
            &G1Affine::from(signature.A),
            &G2Prepared::from(G2Affine::from(pk + G2Projective::generator() * signature.e)),
        ),
        (
            &G1Affine::from(B),
            &G2Prepared::from(G2Affine::from(G2Projective::generator().neg())),
        ),
    ])
    .final_exponentiation()
        == Gt::identity()
}

#[cfg(test)]
mod tests {
    use std::vec;

    use bls12_381_plus::G2Affine;

    use crate::hashing::map_message_to_scalar_as_hash;

    use super::*;

    #[test]
    fn to_octet_string_test() {
        let i = 42usize;

        assert_eq!(i.to_osp(1).len(), 1);
        assert_eq!(i.to_osp(3).len(), 3);
        assert_eq!(i.to_osp(3), vec![0, 0, 42]);
    }

    #[test]
    fn create_generators_test() {
        let generators = create_generators(12);

        println!(
            "base point: {:?}",
            hex::encode(generators.base_point.encode_for_hash())
        );
        println!("Q1: {:?}", hex::encode(generators.Q1.encode_for_hash()));
        println!("Q2: {:?}", hex::encode(generators.Q2.encode_for_hash()));
        for g in generators.message_generators {
            println!("generator: {:?}", hex::encode(g.encode_for_hash()));
        }
    }

    #[test]
    fn sign_test() {
        let sk_bytes =
            hex::decode("47d2ede63ab4c329092b342ab526b1079dbc2595897d4f2ab2de4d841cbe7d56")
                .unwrap();
        let sk = Scalar::from_osp(&sk_bytes);
        let messages = vec![Scalar::from(1u64), Scalar::from(2u64)];

        let signature = sign(sk, None, Some(messages));

        //println!("signature: {:?}", hex::encode(signature.to_octet_string()));
    }
    #[test]
    fn gen_sk_fixture() {
        let ikm = hex::decode("746869732d49532d6a7573742d616e2d546573742d494b4d2d746f2d67656e65726174652d246528724074232d6b6579").unwrap();

        let sk = key_gen(ikm, vec![].as_slice());

        let mut bytes = sk.to_bytes();
        bytes.reverse();

        println!("secret key: {:?}", hex::encode(bytes));
    }

    #[test]
    fn sk_to_pk_fixture() {
        let i = 0usize.to_be_bytes()[4..].to_vec();
        println!("i: {:?}", i);

        let mut sk =
            hex::decode("47d2ede63ab4c329092b342ab526b1079dbc2595897d4f2ab2de4d841cbe7d56")
                .unwrap();
        sk.reverse();

        let mut bytes = sk.as_slice();
        // let mut tmp = Scalar([0, 0, 0, 0]);

        // 93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8
        // 93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8

        let a = u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[0..8]).unwrap());
        let b = u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[8..16]).unwrap());
        let c = u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[16..24]).unwrap());
        let d = u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[24..32]).unwrap());

        let sk1 = Scalar::from_raw([a, b, c, d]);

        let secret_key = SecretKey::from_bytes(sk.as_slice().try_into().expect("msg")).unwrap();
        println!("secret key: {:x?}", secret_key.to_bytes());
        let pk = sk_to_pk(&sk1);

        let p: G2Affine = pk.into();

        println!("public key: {:x?}", hex::encode(p.to_compressed()));

        println!(
            "gen: {:?}",
            hex::encode(G2Affine::generator().to_compressed())
        );
    }

    #[test]
    fn signature_test() {
        let mut bytes =
            hex::decode("47d2ede63ab4c329092b342ab526b1079dbc2595897d4f2ab2de4d841cbe7d56")
                .unwrap();
        bytes.reverse();
        let sk = Scalar::from_osp(&bytes);
        let pk = sk_to_pk(&sk);
        println!("sk: {:?}", hex::encode(sk.encode_for_hash()));

        let header = b"11223344556677889900aabbccddeeff".to_vec();
        let messages = [b"9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"];

        let expected = hex::decode("90ab57c8670fb86df30e5ab93222a7a93b829564a18aeee36064b53ddef6fa443f6f59e0ac48e60641113b39dde4112404ded0d1d1302a884565b5b1f3ba1d56c40ea63fc632193ef3cb4ee01192a9525c134821981eebc89c2c890d3a137816cc3b58ea2d7f3608b3d0362488a52f44").unwrap();

        let actual = sign(
            sk,
            Some(header.clone()),
            Some(
                messages
                    .iter()
                    .map(|m| map_message_to_scalar_as_hash(m.as_slice()))
                    .collect(),
            ),
        );

        let verify = verify(
            &pk,
            &actual,
            Some(header),
            Some(
                messages
                    .iter()
                    .map(|m| map_message_to_scalar_as_hash(m.as_slice()))
                    .collect(),
            ),
        );

        println!("verify: {:?}", verify);

        println!("actual: {:?}", hex::encode(actual.to_octet_string()));
        println!("expected: {:?}", hex::encode(expected));
        //assert_eq!(actual, expected);
    }
}
