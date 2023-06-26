use std::fmt::{self, Debug, Display, Formatter};

use bls12_381::{multi_miller_loop, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Gt, Scalar};
#[cfg(not(test))]
use rand::{thread_rng, Rng};

use crate::{
    ciphersuite::*,
    encoding::*,
    generators::*,
    signature::*,
    utils::{calculate_challenge, calculate_domain},
    Error,
};

#[derive(PartialEq, Eq, Clone)]
pub struct Proof {
    A_bar: G1Projective,
    B_bar: G1Projective,
    c: Scalar,
    r2_hat: Scalar,
    r3_hat: Scalar,
    m_hat: Vec<Scalar>,
}

impl Proof {
    pub fn to_bytes(&self) -> Vec<u8> {
        [
            &G1Affine::from(self.A_bar).to_compressed()[..],
            &G1Affine::from(self.B_bar).to_compressed(),
            &self.c.i2osp(SCALAR_LEN),
            &self.r2_hat.i2osp(SCALAR_LEN),
            &self.r3_hat.i2osp(SCALAR_LEN),
            &self.m_hat.iter().flat_map(|m| m.i2osp(SCALAR_LEN)).collect::<Vec<u8>>(),
        ]
        .concat()
    }

    pub fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Result<Self, Error> {
        const P: usize = POINT_LEN;
        const S: usize = SCALAR_LEN;

        let bytes = bytes.as_ref();

        // courtesy of github copilot
        let A_bar = G1Affine::from_compressed(&<[u8; P]>::try_from(&bytes[..P])?)
            .map(G1Projective::from)
            .unwrap();
        let B_bar = G1Affine::from_compressed(&<[u8; P]>::try_from(&bytes[P..2 * P])?)
            .map(G1Projective::from)
            .unwrap();
        let c = Scalar::os2ip(&bytes[2 * P..2 * P + S]);
        let r2_hat = Scalar::os2ip(&bytes[2 * P + S..2 * P + 2 * S]);
        let r3_hat = Scalar::os2ip(&bytes[2 * P + 2 * S..2 * P + 3 * S]);
        let mut m_hat = Vec::new();

        for i in 0..(bytes.len() - 2 * P - 3 * S) / S {
            m_hat.push(Scalar::os2ip(&bytes[2 * P + 3 * S + i * S..2 * P + 3 * S + (i + 1) * S]));
        }

        Ok(Proof {
            A_bar,
            B_bar,
            c,
            r2_hat,
            r3_hat,
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

    // Precomputations:

    // 1. (i1, ..., iR) = disclosed_indexes
    let mut i = disclosed_indexes.to_vec();
    i.sort();

    // 2. (j1, ..., jU) = range(1, L) \ disclosed_indexes
    let j = (0..L).filter(|x| !i.contains(x)).collect::<Vec<usize>>();

    let (A, e) = (signature.A, signature.e);

    // Procedure:
    // 1.  (Q_1, MsgGenerators) = create_generators(L+1)
    let generators = create_generators::<T>(L + 1);

    // 4.  domain = calculate_domain(PK, Q_1, (H_1, ..., H_L), header)
    let domain = calculate_domain::<T>(pk, &generators, header);

    // 6.  random_scalars = calculate_random_scalars(3+U)
    #[cfg(not(test))]
    let scalars = calculate_random_scalars(3 + U);
    #[cfg(test)]
    let scalars = calculate_random_scalars::<T>(3 + U);

    // 7.  (r1, r2, r3, m~_j1, ..., m~_jU) = random_scalars
    let r1 = scalars[0];
    let r2 = scalars[1];
    let r3 = scalars[2];

    let mut m_tilda = vec![Scalar::zero(); U];
    for i in 3..3 + U {
        m_tilda[i - 3] = scalars[i];
    }

    // 8.  B = P1 + Q_1 * domain + H_1 * msg_1 + ... + H_L * msg_L
    let B = generators.P1 + generators.Q1 * domain + generators.H.iter().zip(messages.iter()).map(|(g, m)| g * m).sum::<G1Projective>();

    // 9.  Abar = A * r1
    let A_bar = A * r1;

    // 10. Bbar = B * r1 - Abar * e
    let B_bar = B * r1 - A_bar * e;

    // 11. C = Bbar * r2 + Abar * r3 + H_j1 * m~_j1 + ... + H_jU * m~_jU
    let C = B_bar * r2
        + A_bar * r3
        + j.iter()
            .map(|x| generators.H[*x] * m_tilda[j.iter().position(|&y| y == *x).unwrap()])
            .sum::<G1Projective>();

    // 12. c = calculate_challenge(Abar, Bbar, C, (i1, ..., iR), (msg_i1, ..., msg_iR), domain, ph)
    let disclosed_messages = i.iter().map(|x| messages[*x]).collect::<Vec<Scalar>>();
    let c = calculate_challenge::<T>(&A_bar, &B_bar, &C, disclosed_indexes, &disclosed_messages, &domain, ph);

    // 14. r4 = - r1^-1 (mod r)
    let r4 = -r1.invert().unwrap();

    // 15. r2^ = r2 + r4 * c (mod r)
    let r2_hat = r2 + r4 * c;

    // 16. r3^ = r3 + e * r4 * c (mod r)
    let r3_hat = r3 + e * r4 * c;

    // 17. for j in (j1, ..., jU): m^_j = m~_j + msg_j * c (mod r)
    let m_hat = j
        .iter()
        .map(|x| c * messages[*x] + m_tilda[j.iter().position(|&y| y == *x).unwrap()])
        .collect::<Vec<_>>();

    // 18. proof = (Abar, Bbar, c, r2^, r3^, (m^_j1, ..., m^_jU))
    Proof {
        A_bar,
        B_bar,
        c,
        r2_hat,
        r3_hat,
        m_hat,
    }
}

#[cfg(not(test))]
pub(crate) fn calculate_random_scalars(count: usize) -> Vec<Scalar> {
    let mut scalars = vec![Scalar::zero(); count];
    for scalar in scalars.iter_mut() {
        let mut buffer = [0u8; 64];
        thread_rng().fill(&mut buffer);
        *scalar = Scalar::from_okm(buffer[0..POINT_LEN].try_into().unwrap())
    }
    scalars
}

#[cfg(test)]
pub(crate) fn calculate_random_scalars<'a, T: BbsCiphersuite<'a>>(count: usize) -> Vec<Scalar> {
    let seed = hex::decode("332e313431353932363533353839373933323338343632363433333833323739").unwrap();

    let out_len = 48 * count;
    let dst = [T::CIPHERSUITE_ID, b"MOCK_RANDOM_SCALARS_DST_"].concat();

    let mut v = T::Expander::init_expand(&seed, &dst, out_len).into_vec();

    let mut scalars = vec![Scalar::zero(); count];
    for scalar in scalars.iter_mut() {
        *scalar = Scalar::from_okm(v[0..48].try_into().unwrap())
    }
    scalars
}

// https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-proofverify
pub(crate) fn proof_verify_impl<'a, T: BbsCiphersuite<'a>>(
    pk: &G2Projective,
    proof: &Proof,
    header: &[u8],
    ph: &[u8],
    disclosed_messages: &[Scalar],
    disclosed_indexes: &[usize],
) -> bool {
    // R, is the non-negative integer representing the number of disclosed
    //   (revealed) messages, i.e., R = length(disclosed_indexes). If no
    //    messages are disclosed, the value of R MUST evaluate to zero (0).
    let R = disclosed_messages.len();
    // U, is the non-negative integer representing the number of undisclosed
    //   messages, i.e., U = L - R.
    let U = proof.m_hat.len();
    // L (REQUIRED), non-negative integer. The number of signed messages.
    let L = R + U;

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

    // 1.  (Q_1, MsgGenerators) = create_generators(L+1)
    let generators = create_generators::<T>(L + 1);

    // Preconditions:

    // 1. for i in (i1, ..., iR), if i < 1 or i > L, return INVALID
    // 2. if length(disclosed_messages) != R, return INVALID
    if disclosed_messages.len() != R {
        panic!("disclosed_messages length must be equal to R");
    }

    // Procedure:
    // 5.  domain = calculate_domain(PK, Q_1, (H_1, ..., H_L), header)
    let domain = calculate_domain::<T>(pk, &generators, header);

    // 7.  D = P1 + Q_1 * domain + H_i1 * msg_i1 + ... + H_iR * msg_iR
    let D = generators.P1
        + generators.Q1 * domain
        + i.iter()
            .zip(disclosed_messages.iter())
            .map(|(i, m)| generators.H[*i] * m)
            .sum::<G1Projective>();

    // 8.  C = Bbar * r2^ + Abar * r3^ + H_j1 * m^_j1 + ... + H_jU * m^_jU + D * c
    let C = proof.B_bar * proof.r2_hat
        + proof.A_bar * proof.r3_hat
        + D * proof.c
        + j.iter().zip(proof.m_hat.iter()).map(|(i, m)| generators.H[*i] * m).sum::<G1Projective>();

    // 9.  cv = calculate_challenge(Abar, Bbar, C, (i1, ..., iR), (msg_i1, ..., msg_iR), domain, ph)
    let cv = calculate_challenge::<T>(&proof.A_bar, &proof.B_bar, &C, &i, disclosed_messages, &domain, ph);

    // 11. if c != cv, return INVALID
    if proof.c != cv {
        return false;
    }

    // 12. if e(Abar, W) * e(Bbar, -P2) != Identity_GT, return INVALID
    multi_miller_loop(&[
        (&G1Affine::from(proof.A_bar), &G2Prepared::from(G2Affine::from(pk))),
        (&G1Affine::from(proof.B_bar), &G2Prepared::from(-G2Affine::generator())),
    ])
    .final_exponentiation()
        == Gt::identity()
}

#[cfg(test)]
mod test {

    use crate::prelude::*;
    use fluid::prelude::*;

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
        let input = fixture!(tests::Proof, file);
        let header = hex!(&input.header);

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
        let input = fixture!(tests::Proof, file);
        let header = hex!(&input.header);

        let bbs = Bbs::<Bls12381Shake256>::new(&header);
        proof_test::<Bls12381Shake256>(&input, bbs);
    }

    fn proof_test<'a, T: BbsCiphersuite<'a> + Default>(input: &tests::Proof, bbs: Bbs<'a, T>) {
        let input = input.clone();

        let pk = PublicKey::from_bytes(hex!(input.signer_public_key));

        let ph = hex!(input.presentation_header);

        let messages = input
            .revealed_messages
            .iter()
            .map(|(i, m)| (i, hex!(m.as_bytes())))
            .map(|(i, m)| (*i, bbs.message(m)))
            .collect::<Vec<_>>();

        let revealed = messages.iter().map(|(i, _)| *i as usize).collect::<Vec<_>>();
        let messages = messages.iter().map(|(_, m)| *m).collect::<Vec<_>>();

        let proof = Proof::from_bytes(&hex!(input.proof.as_bytes())).unwrap();

        let verify = bbs.verify_proof_with(&pk, &proof, &messages, &revealed, &ph).unwrap();

        assert_eq!(verify, input.result.valid);
    }

    #[test]
    fn test_proof_from_bytes() {
        let bytes = hex!("8ffb2aeaa386e0240483b8b84d9af7084e62b09b8d0bbf76ba6bff1d308d82543a3f6b9eeb2493d2b7c36800ba055f7383a56ac1afc9de757ed23380a878f4da8c0c3fc3b0678efc97377d60299a4539fe9aa44ed6e1520956e7140c7f183f350990553621cea4d0531e33aa7a13d33d869a787d952a7a715a30e83bac952b13458e18413dc5361e81b5adacdbd2bb08eebf54d3e0103e5c1bd265506701aa53491fdc2bdba6f2e73c3a4a591330eafaea86e08baaf49d1cded3f70d8b1f3296");

        let proof = Proof::from_bytes(&bytes);

        assert!(proof.is_ok());
    }
}
