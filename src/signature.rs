use std::fmt::{self, Debug, Display, Formatter};

use bls12_381::{multi_miller_loop, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Gt, Scalar};

use crate::{ciphersuite::*, encoding::*, generators::*, hashing::*, key::sk_to_pk, utils::calculate_domain, *};

/// BBS Signature
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Signature {
    pub(crate) A: G1Projective,
    pub(crate) e: Scalar,
    pub(crate) s: Scalar,
}

impl Signature {
    /// Specification [4.4.2. OctetsToSignature](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-00.html#name-signaturetooctets)
    pub fn to_bytes(&self) -> Vec<u8> {
        [self.A.serialize(), self.e.i2osp(SCALAR_LEN), self.s.i2osp(SCALAR_LEN)].concat()
    }

    /// Specification [4.4.1. OctetsToSignature](https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-octetstosignature)
    pub fn from_bytes(buf: &[u8]) -> Result<Signature, Error> {
        let PL = POINT_LEN;
        let SL = SCALAR_LEN;

        if buf.len() != PL + 2 * SL {
            return Err(Error::InvalidSignature);
        }

        Ok(Signature {
            A: G1Affine::from_compressed(&buf[0..PL].try_into()?).unwrap().into(),
            e: Scalar::os2ip(&buf[PL..PL + SL]),
            s: Scalar::os2ip(&buf[PL + SL..]),
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
    let PK = sk_to_pk(sk);
    let L = messages.len();
    let expand_len = 32usize;

    // 1.  (Q_1, Q_2, H_1, ..., H_L) = create_generators(L+2)
    let generators = create_generators::<T>(&T::generator_seed(), L + 2);

    // 2.  domain = calculate_domain(PK, Q_1, Q_2, (H_1, ..., H_L), header)
    let domain = calculate_domain::<T>(&PK, &generators, header);

    // 4.  e_s_octs = serialize((SK, domain, msg_1, ..., msg_L))
    let e_s_octs = vec![sk.serialize(), domain.serialize(), messages.iter().map(|x| x.serialize()).concat()].concat();

    // 6.  e_s_expand = expand_message(e_s_octs, expand_dst, expand_len * 2)
    let e_s_expand = T::Expander::init_expand(&e_s_octs, &T::expand_dst(), 2 * expand_len).into_vec();

    // 8.  e = hash_to_scalar(e_s_expand[0..(expand_len - 1)])
    // 9.  s = hash_to_scalar(e_s_expand[expand_len..(expand_len * 2 - 1)])
    let e = hash_to_scalar::<T>(&e_s_expand[0..expand_len], &[]);
    let s = hash_to_scalar::<T>(&e_s_expand[expand_len..2 * expand_len], &[]);

    // 11. B = P1 + Q_1 * s + Q_2 * domain + H_1 * msg_1 + ... + H_L * msg_L
    let B = generators.P1
        + generators.Q1 * s
        + generators.Q2 * domain
        + generators.H.iter().zip(messages.iter()).map(|(g, m)| g * m).sum::<G1Projective>();

    // 12. A = B * (1 / (SK + e))
    let A = B * (sk + e).invert().unwrap();

    Signature { A, e, s }
}

// https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-proofverify
pub fn verify_impl<'a, T: BbsCiphersuite<'a>>(pk: &G2Projective, signature: &Signature, header: &[u8], messages: &[Scalar]) -> bool {
    let L = messages.len();

    // 1. (Q_1, Q_2, H_1, ..., H_L) = create_generators(L+2)
    let generators = create_generators::<T>(&[], L + 2);

    // 2. domain = calculate_domain(PK, Q_1, Q_2, (H_1, ..., H_L), header)
    let domain = calculate_domain::<T>(pk, &generators, header);

    // 4. B = P1 + Q_1 * s + Q_2 * domain + H_1 * msg_1 + ... + H_L * msg_L
    let B = generators.P1
        + generators.Q1 * signature.s
        + generators.Q2 * domain
        + generators.H.iter().zip(messages.iter()).map(|(g, m)| g * m).sum::<G1Projective>();

    // 5. if e(A, W + P2 * e) * e(B, -P2) != Identity_GT, return INVALID
    multi_miller_loop(&[
        (
            &G1Affine::from(signature.A),
            &G2Prepared::from(G2Affine::from(pk + G2Projective::generator() * signature.e)),
        ),
        (&G1Affine::from(B), &G2Prepared::from(-G2Affine::generator())),
    ])
    .final_exponentiation()
        == Gt::identity()
}

#[cfg(test)]
mod test {
    use crate::prelude::*;
    use fluid::prelude::*;

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
        let input = fixture!(tests::Signature, file);
        let header = hex!(&input.header);

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
        let input = fixture!(tests::Signature, file);
        let header = hex!(&input.header);

        let bbs = Bbs::<Bls12381Shake256>::new(&header);
        signature_test::<Bls12381Shake256>(&input, bbs);
    }

    fn signature_test<'a, 'b, T: BbsCiphersuite<'a> + Default>(input: &tests::Signature, bbs: Bbs<'a, T>) {
        let input = input.clone();

        let pk = PublicKey::from_bytes(hex!(input.signer_key_pair.public_key));

        let messages = input
            .messages
            .iter()
            .map(|x| hex!(x.as_bytes()))
            .map(|x| bbs.message(x))
            .collect::<Vec<_>>();

        let signature = Signature::from_bytes(&hex!(input.signature)).unwrap();

        let verify = bbs.verify(&pk, &signature, &messages);

        assert_eq!(verify, input.result.valid);
    }

    #[test]
    fn signature_from_octets_succeeds() {
        let bytes = hex!("90ab57c8670fb86df30e5ab93222a7a93b829564a18aeee36064b53ddef6fa443f6f59e0ac48e60641113b39dde4112404ded0d1d1302a884565b5b1f3ba1d56c40ea63fc632193ef3cb4ee01192a9525c134821981eebc89c2c890d3a137816cc3b58ea2d7f3608b3d0362488a52f44");

        let signature = Signature::from(&bytes.try_into().unwrap());

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
