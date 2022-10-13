use std::ops::Neg;

use bls12_381_plus::{
    multi_miller_loop, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Gt, Scalar,
};

use crate::{ciphersuite::*, encoding::*, generators::*, hashing::*, *};

pub(crate) struct Signature {
    pub A: G1Projective,
    pub s: Scalar,
    pub e: Scalar,
}

impl Signature {
    // https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-00.html#name-signaturetooctets
    pub fn to_octet_string(&self) -> OctetString {
        [
            self.A.encode_for_hash(),
            self.e.to_osp(OCTET_POINT_LENGTH),
            self.s.to_osp(OCTET_POINT_LENGTH),
        ]
        .concat()
    }

    pub fn from_octet_string(octet_string: &OctetString) -> Result<Signature, Error> {
        let A = G1Affine::from_compressed(&octet_string[0..OCTET_POINT_LENGTH].try_into().unwrap())
            .unwrap()
            .into();
        let e =
            Scalar::from_osp(&octet_string[OCTET_POINT_LENGTH..OCTET_POINT_LENGTH * 2].to_vec());
        let s = Scalar::from_osp(
            &octet_string[OCTET_POINT_LENGTH * 2..OCTET_POINT_LENGTH * 3].to_vec(),
        );

        Ok(Signature { A, s, e })
    }
}

fn sign<'a, T: BbsCiphersuite<'a>>(
    sk: SecretKey,
    header: Option<Vec<u8>>,
    messages: Option<Vec<Scalar>>,
) -> Signature {
    let PK = sk_to_pk(&sk);

    let header = header.unwrap_or_default();
    let messages = messages.unwrap_or_default();
    let L = messages.len();

    // 2. (Q_1, Q_2, H_1, ..., H_L) = create_generators(generator_seed, L+2)
    let generators = create_generators::<T>(None, L + 2);

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
        T::CIPHERSUITE_ID.to_vec(),
        header.as_slice().encode_for_hash(),
    ]
    .concat();

    // 4.  domain = hash_to_scalar(dom_for_hash, 1)
    let domain = hash_to_scalar::<Bls12381Sha256>(dom_for_hash.as_slice(), 1, None);
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
    let e_s = hash_to_scalar::<Bls12381Sha256>(e_s_for_hash.as_slice(), 2, None);
    assert_eq!(e_s.len(), 2, "incorrect e_s scalar length");
    let e = e_s[0];
    let s = e_s[1];

    // 8.  B = P1 + Q_1 * s + Q_2 * domain + H_1 * msg_1 + ... + H_L * msg_L
    let B = generators.BP
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

fn verify<'a, T: BbsCiphersuite<'a>>(
    pk: &PublicKey,
    signature: &Signature,
    header: Option<Vec<u8>>,
    messages: Option<Vec<Scalar>>,
) -> bool {
    let header = header.unwrap_or_default();
    let messages = messages.unwrap_or_default();

    let L = messages.len();
    let generators = create_generators::<T>(None, L + 2);

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
        T::CIPHERSUITE_ID.to_vec(),
        header.as_slice().encode_for_hash(),
    ]
    .concat();

    // 9.  domain = hash_to_scalar(dom_for_hash, 1)
    let domain = hash_to_scalar::<Bls12381Sha256>(dom_for_hash.as_slice(), 1, None);
    assert_eq!(domain.len(), 1, "incorrect domain scalar length");

    let domain = domain[0];

    // 10. B = P1 + Q_1 * s + Q_2 * domain + H_1 * msg_1 + ... + H_L * msg_L
    let B = generators.BP
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
mod test {
    use bls12_381_plus::Scalar;

    use crate::{
        ciphersuite::Bls12381Sha256,
        encoding::OS2IP,
        hashing::{map_message_to_scalar_as_hash, EncodeForHash},
        signature::verify,
        sk_to_pk, SecretKey,
    };

    use super::sign;

    #[test]
    fn signature_test() {
        let bytes = hex::decode("47d2ede63ab4c329092b342ab526b1079dbc2595897d4f2ab2de4d841cbe7d56")
            .unwrap();
        let sk = SecretKey::from_osp(&bytes);
        let pk = sk_to_pk(&sk);

        let header = b"11223344556677889900aabbccddeeff".to_vec();
        let messages = [b"9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"];

        let expected = hex::decode("90ab57c8670fb86df30e5ab93222a7a93b829564a18aeee36064b53ddef6fa443f6f59e0ac48e60641113b39dde4112404ded0d1d1302a884565b5b1f3ba1d56c40ea63fc632193ef3cb4ee01192a9525c134821981eebc89c2c890d3a137816cc3b58ea2d7f3608b3d0362488a52f44").unwrap();

        let actual = sign::<Bls12381Sha256>(
            sk,
            Some(header.clone()),
            Some(
                messages
                    .iter()
                    .map(|m| map_message_to_scalar_as_hash::<Bls12381Sha256>(m.as_slice(), None))
                    .collect(),
            ),
        );

        let verify = verify::<Bls12381Sha256>(
            &pk,
            &actual,
            Some(header),
            Some(
                messages
                    .iter()
                    .map(|m| map_message_to_scalar_as_hash::<Bls12381Sha256>(m.as_slice(), None))
                    .collect(),
            ),
        );

        println!("verify: {:?}", verify);

        println!("actual: {:?}", hex::encode(actual.to_octet_string()));
        println!("expected: {:?}", hex::encode(expected));
        //assert_eq!(actual, expected);
    }
}
