use std::fmt::{self, Debug, Display, Formatter};

use bls12_381_plus::{
    multi_miller_loop, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Gt, Scalar,
};
use rand::{thread_rng, Rng};

use crate::{ciphersuite::*, encoding::*, generators::*, hashing::*, signature::*, Error};

#[derive(PartialEq, Clone)]
pub struct Proof {
    A_prime: G1Projective,
    A_bar: G1Projective,
    D: G1Projective,
    c: Scalar,
    e_hat: Scalar,
    r2_hat: Scalar,
    r3_hat: Scalar,
    s_hat: Scalar,
    m_hat: Vec<Scalar>,
}

impl Proof {
    pub fn to_bytes(&self) -> Vec<u8> {
        [
            &G1Affine::from(self.A_prime).to_compressed()[..],
            &G1Affine::from(self.A_bar).to_compressed(),
            &G1Affine::from(self.D).to_compressed(),
            &self.c.i2osp(SCALAR_LEN),
            &self.e_hat.i2osp(SCALAR_LEN),
            &self.r2_hat.i2osp(SCALAR_LEN),
            &self.r3_hat.i2osp(SCALAR_LEN),
            &self.s_hat.i2osp(SCALAR_LEN),
            &self
                .m_hat
                .iter()
                .map(|m| m.i2osp(SCALAR_LEN))
                .flatten()
                .collect::<Vec<u8>>(),
        ]
        .concat()
    }

    pub fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Result<Self, Error> {
        const P: usize = POINT_LEN;
        const S: usize = SCALAR_LEN;

        let bytes = bytes.as_ref();

        // courtesy of github copilot
        let A_prime = G1Affine::from_compressed(&<[u8; P]>::try_from(&bytes[..P])?)
            .map(G1Projective::from)
            .unwrap();
        let A_bar = G1Affine::from_compressed(&<[u8; P]>::try_from(&bytes[P..2 * P])?)
            .map(G1Projective::from)
            .unwrap();
        let D = G1Affine::from_compressed(&<[u8; P]>::try_from(&bytes[2 * P..3 * P])?)
            .map(G1Projective::from)
            .unwrap();
        let c = Scalar::os2ip(&bytes[3 * P..3 * P + S]);
        let e_hat = Scalar::os2ip(&bytes[3 * P + S..3 * P + 2 * S]);
        let r2_hat = Scalar::os2ip(&bytes[3 * P + 2 * S..3 * P + 3 * S]);
        let r3_hat = Scalar::os2ip(&bytes[3 * P + 3 * S..3 * P + 4 * S]);
        let s_hat = Scalar::os2ip(&bytes[3 * P + 4 * S..3 * P + 5 * S]);
        let mut m_hat = Vec::new();
        for i in 0..(bytes.len() - 3 * P - 5 * S) / S {
            m_hat.push(Scalar::os2ip(
                &bytes[3 * P + 5 * S + i * S..3 * P + 5 * S + (i + 1) * S],
            ));
        }

        Ok(Proof {
            A_prime,
            A_bar,
            D,
            c,
            e_hat,
            r2_hat,
            r3_hat,
            s_hat,
            m_hat,
        })
    }
}

impl Debug for Proof {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let tmp = self.to_bytes();
        write!(f, "0x")?;
        for &b in tmp.iter() {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl Display for Proof {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

// https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-proofgen
pub(crate) fn proof_gen_impl<'a, T: BbsCiphersuite<'a>>(
    pk: &G2Projective,
    signature: &Signature,
    header: &[u8],
    ph: &[u8],
    messages: &[Scalar],
    disclosed_indexes: &[usize],
) -> Proof {
    // L, is the non-negative integer representing the number of messages,
    //   i.e., L = length(messages). If no messages are supplied, the
    //   value of L MUST evaluate to zero (0).
    let L = messages.len();
    // R, is the non-negative integer representing the number of disclosed
    //   (revealed) messages, i.e., R = length(disclosed_indexes). If no
    //   messages are disclosed, R MUST evaluate to zero (0).
    let R = disclosed_indexes.len();
    // U, is the non-negative integer representing the number of undisclosed
    //   messages, i.e., U = L - R.
    let U = L - R;
    // r: 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    // prf_len = ceil(ceil(log2(r))/8), where r defined by the ciphersuite.
    const PRF_LEN: usize = 32;

    let generators = create_generators::<T>(&[], L + 2);

    // Precomputations:

    // 1. (i1, ..., iR) = disclosed_indexes
    let mut i = disclosed_indexes.to_vec();
    i.sort();

    // 2. (j1, ..., jU) = range(1, L) \ disclosed_indexes
    let j = (0..L).filter(|x| !i.contains(x)).collect::<Vec<usize>>();

    // Procedure:

    // 1.  signature_result = octets_to_signature(signature)
    // 2.  if signature_result is INVALID, return INVALID
    // 3.  (A, e, s) = signature_result
    let (A, e, s) = (signature.A, signature.e, signature.s);

    // 4.  dom_array = (PK, L, Q_1, Q_2, H_1, ..., H_L, ciphersuite_id, header)
    // 5.  dom_for_hash = encode_for_hash(dom_array)
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

    // 6.  if dom_for_hash is INVALID, return INVALID
    // 7.  domain = hash_to_scalar(dom_for_hash, 1)
    let mut domain = [Scalar::zero()];
    hash_to_scalar::<T>(&dom_for_hash, &[], &mut domain);
    let domain = domain[0];

    // 8.  (r1, r2, e~, r2~, r3~, s~) = hash_to_scalar(PRF(prf_len), 6)
    let mut buffer = [0u8; PRF_LEN];
    thread_rng().fill(&mut buffer);

    let mut scalars = [Scalar::zero(); 6];
    hash_to_scalar::<T>(&buffer, &[], &mut scalars);
    let [r1, r2, e_tilda, r2_tilda, r3_tilda, s_tilda] = scalars;

    // 9.  (m~_j1, ..., m~_jU) = hash_to_scalar(PRF(prf_len), U)
    let mut buffer = [0u8; PRF_LEN];
    thread_rng().fill(&mut buffer);

    let mut m_tilda = vec![Scalar::zero(); U];
    hash_to_scalar::<T>(&buffer, &[], &mut m_tilda);

    // 10. B = P1 + Q_1 * s + Q_2 * domain + H_1 * msg_1 + ... + H_L * msg_L
    let B = generators.P1
        + generators.Q1 * s
        + generators.Q2 * domain
        + generators
            .H
            .iter()
            .zip(messages.iter())
            .map(|(g, m)| g * m)
            .sum::<G1Projective>();

    // 11. r3 = r1 ^ -1 mod r
    let r3 = r1.invert().unwrap();

    // 12. A' = A * r1
    let A_prime = A * r1;

    // 13. Abar = A' * (-e) + B * r1
    let A_bar = A_prime * (-e) + B * r1;

    // 14. D = B * r1 + Q_1 * r2
    let D = B * r1 + generators.Q1 * r2;

    // 15. s' = r2 * r3 + s mod r
    let s_prime = r2 * r3 + s;

    // 16. C1 = A' * e~ + Q_1 * r2~
    let C1 = A_prime * e_tilda + generators.Q1 * r2_tilda;

    // 17. C2 = D * (-r3~) + Q_1 * s~ + H_j1 * m~_j1 + ... + H_jU * m~_jU
    let C2 = D * (-r3_tilda)
        + generators.Q1 * s_tilda
        + j.iter()
            .map(|x| generators.H[*x] * m_tilda[j.iter().position(|&y| y == *x).unwrap()])
            .sum::<G1Projective>();

    // 18. c_array = (A', Abar, D, C1, C2, R, i1, ..., iR, msg_i1, ..., msg_iR, domain, ph)
    // 19. c_for_hash = encode_for_hash(c_array)
    let c_for_hash = [
        A_prime.encode_for_hash(),
        A_bar.encode_for_hash(),
        D.encode_for_hash(),
        C1.encode_for_hash(),
        C2.encode_for_hash(),
        R.encode_for_hash(),
        i.iter().map(|i| i.encode_for_hash()).flatten().collect(),
        i.iter()
            .map(|i| messages[*i].encode_for_hash())
            .flatten()
            .collect(),
        domain.encode_for_hash(),
        ph.encode_for_hash(),
    ]
    .concat();

    // 20. if c_for_hash is INVALID, return INVALID
    // 21. c = hash_to_scalar(c_for_hash, 1)
    let mut c = [Scalar::zero()];
    hash_to_scalar::<T>(&c_for_hash, &[], &mut c);
    let c = c[0];

    // 22. e^ = c * e + e~ mod r
    let e_hat = c * e + e_tilda;

    // 23. r2^ = c * r2 + r2~ mod r
    let r2_hat = c * r2 + r2_tilda;

    // 24. r3^ = c * r3 + r3~ mod r
    let r3_hat = c * r3 + r3_tilda;

    // 25. s^ = c * s' + s~ mod r
    let s_hat = c * s_prime + s_tilda;

    // 26. for j in (j1, ..., jU): m^_j = c * msg_j + m~_j mod r
    let m_hat = j
        .iter()
        .map(|x| c * messages[*x] + m_tilda[j.iter().position(|&y| y == *x).unwrap()])
        .collect::<Vec<_>>();

    // 27. proof = (A', Abar, D, c, e^, r2^, r3^, s^, (m^_j1, ..., m^_jU))
    let proof = Proof {
        A_prime,
        A_bar,
        D,
        c,
        e_hat,
        r2_hat,
        r3_hat,
        s_hat,
        m_hat,
    };

    proof
}

// https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-proofverify
pub(crate) fn proof_verify_impl<'a, T: BbsCiphersuite<'a>>(
    pk: &G2Projective,
    proof: &Proof,
    signed_msg_count: usize,
    header: &[u8],
    ph: &[u8],
    disclosed_messages: &[Scalar],
    disclosed_indexes: &[usize],
) -> bool {
    // L (REQUIRED), non-negative integer. The number of signed messages.
    let L = signed_msg_count;
    // R, is the non-negative integer representing the number of disclosed
    //   (revealed) messages, i.e., R = length(disclosed_indexes). If no
    //    messages are disclosed, the value of R MUST evaluate to zero (0).
    let R = disclosed_messages.len();
    // U, is the non-negative integer representing the number of undisclosed
    //   messages, i.e., U = L - R.
    let U = L - R;

    // Parameters:

    // 1. (i1, ..., iR) = disclosed_indexes
    let mut i = disclosed_indexes.to_vec();
    i.sort();

    // 2. (j1, ..., jU) = range(1, L) \ disclosed_indexes
    let j = (0..L).filter(|x| !i.contains(x)).collect::<Vec<usize>>();

    if R != i.len() {
        return false;
    }

    if (U != j.len()) || (U != proof.m_hat.len()) {
        return false;
    }

    // 4. (Q_1, Q_2, MsgGenerators) = create_generators(L+2)
    let generators = create_generators::<T>(&[], L + 2);

    // Preconditions:

    // 1. for i in (i1, ..., iR), if i < 1 or i > L, return INVALID
    // 2. if length(disclosed_messages) != R, return INVALID
    if disclosed_messages.len() != R {
        panic!("disclosed_messages length must be equal to R");
    }

    // Procedure:

    // 1.  proof_result = octets_to_proof(proof)
    // 2.  if proof_result is INVALID, return INVALID
    // 3.  (A', Abar, D, c, e^, r2^, r3^, s^, (m^_j1,...,m^_jU)) = proof_result
    // 4.  W = octets_to_pubkey(PK)
    // 5.  if W is INVALID, return INVALID
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
            .collect::<Vec<_>>()
            .concat(),
        T::CIPHERSUITE_ID.to_vec(),
        header.encode_for_hash(),
    ]
    .concat();

    // 9.  domain = hash_to_scalar(dom_for_hash, 1)
    let mut domain = [Scalar::zero()];
    hash_to_scalar::<T>(&dom_for_hash, &[], &mut domain);
    let domain = domain[0];

    // 10. C1 = (Abar - D) * c + A' * e^ + Q_1 * r2^
    let C1 = (proof.A_bar - proof.D) * proof.c
        + proof.A_prime * proof.e_hat
        + generators.Q1 * proof.r2_hat;

    // 11. T = P1 + Q_2 * domain + H_i1 * msg_i1 + ... + H_iR * msg_iR
    let T = generators.P1
        + generators.Q2 * domain
        + i.iter()
            .zip(disclosed_messages.iter())
            .map(|(i, m)| generators.H[*i] * m)
            .sum::<G1Projective>();

    // 12. C2 = T * c - D * r3^ + Q_1 * s^ + H_j1 * m^_j1 + ... + H_jU * m^_jU
    let C2 = T * proof.c - proof.D * proof.r3_hat
        + generators.Q1 * proof.s_hat
        + j.iter()
            .zip(proof.m_hat.iter())
            .map(|(i, m)| generators.H[*i] * m)
            .sum::<G1Projective>();

    // 13. cv_array = (A', Abar, D, C1, C2, R, i1, ..., iR, msg_i1, ..., msg_iR, domain, ph)
    // 14. cv_for_hash = encode_for_hash(cv_array)
    let cv_for_hash = [
        proof.A_prime.encode_for_hash(),
        proof.A_bar.encode_for_hash(),
        proof.D.encode_for_hash(),
        C1.encode_for_hash(),
        C2.encode_for_hash(),
        R.encode_for_hash(),
        i.iter().map(|i| i.encode_for_hash()).flatten().collect(),
        disclosed_messages
            .iter()
            .map(|m| m.encode_for_hash())
            .flatten()
            .collect(),
        domain.encode_for_hash(),
        ph.encode_for_hash(),
    ]
    .concat();

    // 15. if cv_for_hash is INVALID, return INVALID
    // 16. cv = hash_to_scalar(cv_for_hash, 1)
    let mut cv = [Scalar::zero()];
    hash_to_scalar::<T>(&cv_for_hash, &[], &mut cv);
    let cv = cv[0];

    // 17. if c != cv, return INVALID
    if proof.c != cv {
        return false;
    }

    // 18. if A' == Identity_G1, return INVALID
    if proof.A_prime == G1Projective::identity() {
        return false;
    }

    // 19. if e(A', W) * e(Abar, -P2) != Identity_GT, return INVALID
    multi_miller_loop(&[
        (
            &G1Affine::from(proof.A_prime),
            &G2Prepared::from(G2Affine::from(pk)),
        ),
        (
            &G1Affine::from(proof.A_bar),
            &G2Prepared::from(G2Affine::from(-G2Affine::generator())),
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

    use super::Proof;

    #[theory]
    #[case("bls12-381-sha-256/proof/proof001.json")]
    #[case("bls12-381-sha-256/proof/proof002.json")]
    #[case("bls12-381-sha-256/proof/proof003.json")]
    #[case("bls12-381-sha-256/proof/proof004.json")]
    #[case("bls12-381-sha-256/proof/proof005.json")]
    #[case("bls12-381-sha-256/proof/proof006.json")]
    #[case("bls12-381-sha-256/proof/proof007.json")]
    #[case("bls12-381-sha-256/proof/proof008.json")]
    #[case("bls12-381-sha-256/proof/proof009.json")]
    #[case("bls12-381-sha-256/proof/proof010.json")]
    #[case("bls12-381-sha-256/proof/proof011.json")]
    #[case("bls12-381-sha-256/proof/proof012.json")]
    #[case("bls12-381-sha-256/proof/proof013.json")]
    fn proof_suite_1(file: &str) {
        let input = &fixture!(tests::Proof, file);
        let header = hex::decode(&input.header).unwrap();

        let bbs = Bbs::<Bls12381Sha256>::new(&header);
        proof_test::<Bls12381Sha256>(&input, bbs);
    }

    #[theory]
    #[case("bls12-381-shake-256/proof/proof001.json")]
    #[case("bls12-381-shake-256/proof/proof002.json")]
    #[case("bls12-381-shake-256/proof/proof003.json")]
    #[case("bls12-381-shake-256/proof/proof004.json")]
    #[case("bls12-381-shake-256/proof/proof005.json")]
    #[case("bls12-381-shake-256/proof/proof006.json")]
    #[case("bls12-381-shake-256/proof/proof007.json")]
    #[case("bls12-381-shake-256/proof/proof008.json")]
    #[case("bls12-381-shake-256/proof/proof009.json")]
    #[case("bls12-381-shake-256/proof/proof010.json")]
    #[case("bls12-381-shake-256/proof/proof011.json")]
    #[case("bls12-381-shake-256/proof/proof012.json")]
    #[case("bls12-381-shake-256/proof/proof013.json")]
    fn proof_suite_2(file: &str) {
        let input = &fixture!(tests::Proof, file);
        let header = hex::decode(&input.header).unwrap();

        let bbs = Bbs::<Bls12381Shake256>::new(&header);
        proof_test::<Bls12381Shake256>(&input, bbs);
    }

    fn proof_test<'a, T: BbsCiphersuite<'a> + Default>(input: &tests::Proof, bbs: Bbs<'a, T>) {
        let input = input.clone();

        let pk = PublicKey(G2Projective::from(
            G2Affine::from_compressed(
                from_hex!(input.signer_public_key)
                    .as_slice()
                    .try_into()
                    .unwrap(),
            )
            .unwrap(),
        ));

        let ph = from_hex!(input.presentation_header);

        let messages = input
            .revealed_messages
            .iter()
            .map(|(i, m)| (i, from_hex!(m.as_bytes())))
            .map(|(i, m)| (*i, bbs.message(m)))
            .collect::<Vec<_>>();

        let revealed = messages
            .iter()
            .map(|(i, _)| *i as usize)
            .collect::<Vec<_>>();
        let messages = messages.iter().map(|(_, m)| *m).collect::<Vec<_>>();

        let proof = Proof::from_bytes(&from_hex!(input.proof.as_bytes())).unwrap();

        let verify = bbs
            .verify_proof_with(
                &pk,
                &proof,
                input.total_message_count,
                &messages,
                &revealed,
                &ph,
            )
            .unwrap();

        assert_eq!(verify, input.result.valid);
    }

    #[test]
    fn test_proof_from_bytes() {
        let bytes = hex!("ad90ac0119119f58743e7a68bd80393dd95b0d4281c7ebe1550505e2c165ce1d328621da7a81a03c7637e4b37ece9ca2b5668f4e01d3d28bcb2bd983d9dd78aa52901fb8093dfb3397cf6e28f4addfdff361eca98c6b02d1140571bc748fbfd38bd7c1e0cbf50864d93b6952839aedae515fb353c827adc15991d1992eec075d608c74b0cd52a3a08870ddd5755054e526a1b407aa1952220ea961d5a6fbe16c496edb5343c9483a48ba077da729b148588b5fa5fbc142e7d3dcbde3de2df361e7ae7395a1136eea5fd70bec8dfc3d8f237ea8ca535d6e40d71be94b76f2c93f196715d0cc356f00f68b1fe5e5e342fd02c932a9775838e656f78847ced7f84e26d299af51a6a7c1bf51bb1e3e895d3555da0da7b8ccce37b20bd468bc04311782fca7088dc365786ed9910f5439f40921eae1f8d467245f86b4ec9ce908372b871d0edc4402173e52fc7100aca5738a1953a45253a1bf2ce1e2387bf8c33bafbf8f06ad41cdad5c07f823915c02962523856123045932d5eb731dc21439b27ed8283e6380d7a36db0a5946d799887e41e9210d68c368d261b15586bbaa6180bffb02a865a4fe043deb2bde498ce76e6616f7872f213b17e0bf4c86065fd021c031507b1697072a02f43310b819e02a741e9988f7ade4617050f518359e0ba0265bc6a62455b45655aff75d7d0d875c2");

        let proof = Proof::from_bytes(&bytes);

        assert!(proof.is_ok());
    }
}
