use std::fmt::{self, Debug, Display, Formatter};

use bls12_381_plus::{
    multi_miller_loop, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Gt, Scalar,
};

use crate::{ciphersuite::*, encoding::*, generators::*, hashing::*, key::sk_to_pk, *};

/// BBS Signature
#[derive(Clone, PartialEq, Default)]
pub struct Signature {
    pub(crate) A: G1Projective,
    pub(crate) e: Scalar,
    pub(crate) s: Scalar,
}

impl Signature {
    /// Specification [4.4.2. OctetsToSignature](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-00.html#name-signaturetooctets)
    pub fn to_bytes(&self) -> Vec<u8> {
        [
            self.A.encode_for_hash(),
            self.e.i2osp(SCALAR_LEN),
            self.s.i2osp(SCALAR_LEN),
        ]
        .concat()
    }

    /// Specification [4.4.1. OctetsToSignature](https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-octetstosignature)
    pub fn from_bytes(buf: &[u8]) -> Result<Signature, Error> {
        let PL = POINT_LEN;
        let SL = SCALAR_LEN;

        if buf.len() != PL + 2 * SL {
            return Err(Error::InvalidSignature);
        }

        Ok(Signature {
            A: G1Affine::from_compressed(&buf[0..PL].try_into()?)
                .unwrap()
                .into(),
            e: Scalar::os2ip(&buf[PL..PL + SL].to_vec()),
            s: Scalar::os2ip(&buf[PL + SL..].to_vec()),
        })
    }
}

impl Debug for Signature {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let tmp = self.to_bytes();
        write!(f, "0x")?;
        for &b in tmp.iter() {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl Display for Signature {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<&[u8; 112]> for Signature {
    fn from(buf: &[u8; 112]) -> Self {
        Signature::from_bytes(buf).unwrap()
    }
}

// https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-sign
pub(crate) fn sign_impl<'a, T>(sk: &Scalar, header: &[u8], messages: &[Scalar]) -> Signature
where
    T: BbsCiphersuite<'a>,
{
    let PK = sk_to_pk(&sk);
    let L = messages.len();

    // 2. (Q_1, Q_2, H_1, ..., H_L) = create_generators(generator_seed, L+2)
    let generators = create_generators::<T>(&T::generator_seed(), L + 2);

    // 1.  dom_array = (PK, L, Q_1, Q_2, H_1, ..., H_L, ciphersuite_id, header)
    // 2.  dom_for_hash = encode_for_hash(dom_array)
    let dom_for_hash = [
        PK.encode_for_hash(),
        L.encode_for_hash(),
        generators.Q1.encode_for_hash(),
        generators.Q2.encode_for_hash(),
        generators.H.iter().map(|g| g.encode_for_hash()).concat(),
        T::CIPHERSUITE_ID.to_vec(),
        header.encode_for_hash(),
    ]
    .concat();

    // 4.  domain = hash_to_scalar(dom_for_hash, 1)
    let mut domain = [Scalar::zero()];
    hash_to_scalar::<T>(&dom_for_hash, &[], &mut domain);
    let domain = domain[0];

    // 5.  e_s_for_hash = encode_for_hash((SK, domain, msg_1, ..., msg_L))
    let e_s_for_hash = vec![
        sk.encode_for_hash(),
        domain.encode_for_hash(),
        messages.iter().map(|x| x.encode_for_hash()).concat(),
    ]
    .concat();

    // 7.  (e, s) = hash_to_scalar(e_s_for_hash, 2)
    let mut e_s = [Scalar::zero(); 2];
    hash_to_scalar::<T>(&e_s_for_hash, &[], &mut e_s);
    let [e, s] = e_s;

    // 8.  B = P1 + Q_1 * s + Q_2 * domain + H_1 * msg_1 + ... + H_L * msg_L
    let B = generators.P1
        + generators.Q1 * s
        + generators.Q2 * domain
        + generators
            .H
            .iter()
            .zip(messages.iter())
            .map(|(g, m)| g * m)
            .sum::<G1Projective>();

    // 9.  A = B * (1 / (SK + e))
    let A = B * (sk + e).invert().unwrap();

    Signature { A, s, e }
}

// https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-proofverify
pub fn verify_impl<'a, T: BbsCiphersuite<'a>>(
    pk: &G2Projective,
    signature: &Signature,
    header: &[u8],
    messages: &[Scalar],
) -> bool {
    let L = messages.len();
    let generators = create_generators::<T>(&[], L + 2);

    // 6.  dom_array = (PK, L, Q_1, Q_2, H_1, ..., H_L, ciphersuite_id, header)
    // 7.  dom_for_hash = encode_for_hash(dom_array)
    let dom_for_hash = [
        pk.encode_for_hash(),
        L.encode_for_hash(),
        generators.Q1.encode_for_hash(),
        generators.Q2.encode_for_hash(),
        generators
            .H
            .iter()
            .map(|g| g.encode_for_hash())
            .flatten()
            .collect::<Vec<u8>>(),
        T::CIPHERSUITE_ID.to_vec(),
        header.encode_for_hash(),
    ]
    .concat();

    // 9.  domain = hash_to_scalar(dom_for_hash, 1)
    let mut domain = [Scalar::zero()];
    hash_to_scalar::<T>(dom_for_hash.as_slice(), &[], &mut domain);
    let domain = domain[0];

    // 10. B = P1 + Q_1 * s + Q_2 * domain + H_1 * msg_1 + ... + H_L * msg_L
    let B = generators.P1
        + generators.Q1 * signature.s
        + generators.Q2 * domain
        + generators
            .H
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
            &G2Prepared::from(-G2Affine::generator()),
        ),
    ])
    .final_exponentiation()
        == Gt::identity()
}

#[cfg(test)]
mod test {
    use crate::prelude::*;
    use bls12_381_plus::{G2Affine, G2Projective};
    use fluid::prelude::*;
    use hex_literal::hex;

    #[theory]
    #[case("bls12-381-sha-256/signature/signature001.json")]
    #[case("bls12-381-sha-256/signature/signature002.json")]
    #[case("bls12-381-sha-256/signature/signature003.json")]
    #[case("bls12-381-sha-256/signature/signature004.json")]
    #[case("bls12-381-sha-256/signature/signature005.json")]
    #[case("bls12-381-sha-256/signature/signature006.json")]
    #[case("bls12-381-sha-256/signature/signature007.json")]
    #[case("bls12-381-sha-256/signature/signature008.json")]
    #[case("bls12-381-sha-256/signature/signature009.json")]
    fn signature_suite_1(file: &str) {
        let input = &fixture!(tests::Signature, file);
        let header = hex::decode(&input.header).unwrap();

        let bbs = Bbs::<Bls12381Sha256>::new(&header);
        signature_test::<Bls12381Sha256>(&input, bbs);
    }

    #[theory]
    #[case("bls12-381-shake-256/signature/signature001.json")]
    #[case("bls12-381-shake-256/signature/signature002.json")]
    #[case("bls12-381-shake-256/signature/signature003.json")]
    #[case("bls12-381-shake-256/signature/signature004.json")]
    #[case("bls12-381-shake-256/signature/signature005.json")]
    #[case("bls12-381-shake-256/signature/signature006.json")]
    #[case("bls12-381-shake-256/signature/signature007.json")]
    #[case("bls12-381-shake-256/signature/signature008.json")]
    #[case("bls12-381-shake-256/signature/signature009.json")]
    fn signature_suite_2(file: &str) {
        let input = &fixture!(tests::Signature, file);
        let header = hex::decode(&input.header).unwrap();

        let bbs = Bbs::<Bls12381Shake256>::new(&header);
        signature_test::<Bls12381Shake256>(&input, bbs);
    }

    fn signature_test<'a, T: BbsCiphersuite<'a> + Default>(
        input: &tests::Signature,
        bbs: Bbs<'a, T>,
    ) {
        let input = input.clone();

        let pk = PublicKey(G2Projective::from(
            G2Affine::from_compressed(
                from_hex!(input.signer_key_pair.public_key)
                    .as_slice()
                    .try_into()
                    .unwrap(),
            )
            .unwrap(),
        ));

        let messages = input
            .messages
            .iter()
            .map(|x| from_hex!(x.as_bytes()))
            .map(|x| bbs.message(x))
            .collect::<Vec<_>>();

        let signature = Signature::from_bytes(&from_hex!(input.signature)).unwrap();

        let verify = bbs.verify(&pk, &signature, &messages);

        assert_eq!(verify, input.result.valid);
    }

    #[test]
    fn signature_from_octets_succeeds() {
        let bytes = hex!("90ab57c8670fb86df30e5ab93222a7a93b829564a18aeee36064b53ddef6fa443f6f59e0ac48e60641113b39dde4112404ded0d1d1302a884565b5b1f3ba1d56c40ea63fc632193ef3cb4ee01192a9525c134821981eebc89c2c890d3a137816cc3b58ea2d7f3608b3d0362488a52f44");

        let signature = Signature::from(&bytes);

        matches!(signature, Signature { .. });
    }

    #[test]
    fn signature_from_octets_succeeds_slice() {
        let bytes = hex!("90ab57c8670fb86df30e5ab93222a7a93b829564a18aeee36064b53ddef6fa443f6f59e0ac48e60641113b39dde4112404ded0d1d1302a884565b5b1f3ba1d56c40ea63fc632193ef3cb4ee01192a9525c134821981eebc89c2c890d3a137816cc3b58ea2d7f3608b3d0362488a52f44");

        let signature = Signature::from_bytes(&bytes);

        matches!(signature, Ok(Signature { .. }));
    }

    #[test]
    fn signature_from_octets_fails_incorrect_size() {
        let signature = Signature::from_bytes(&[]);

        matches!(signature, Err(Error::InvalidSignature));
    }

    #[test]
    fn signature_to_octets_succeeds() {
        let signature = Signature::default();

        let bytes = signature.to_bytes();

        assert_eq!(112, bytes.len());
    }
}
