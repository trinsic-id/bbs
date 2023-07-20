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
    r2_hat: Scalar,
    r3_hat: Scalar,
    m_hat: Vec<Scalar>,
    c: Scalar,
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
    let L = messages.len();
    let R = disclosed_indexes.len();
    let U = L - R;

    let mut i = disclosed_indexes.to_vec();
    i.sort();

    let j = (0..L).filter(|x| !i.contains(x)).collect::<Vec<usize>>();

    let msg_i = (0..L).filter(|x| i.contains(x)).map(|x| messages[x]).collect::<Vec<Scalar>>();
    let msg_j = (0..L).filter(|x| j.contains(x)).map(|x| messages[x]).collect::<Vec<Scalar>>();

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

    // 10. T =  Abar * r2 + Bbar * r3 + H_j1 * m~_j1 + ... + H_jU * m~_jU
    let T = A_bar * r2 + B_bar * r3 + j.iter().zip(m_tilda.iter()).map(|(i, m)| generators.H[*i] * m).sum::<G1Projective>();

    let c = calculate_challenge::<T>(&A_bar, &B_bar, &T, disclosed_indexes, &msg_i, &domain, ph);

    // 14. r4 = - r1^-1 (mod r)
    let r4 = -r1.invert().unwrap();

    // 13. r2^ = r2 + e * r4 * c (mod r)
    let r2_hat = r2 + e * r4 * c;

    // 14. r3^ = r3 + r4 * c (mod r)
    let r3_hat = r3 + r4 * c;

    // 15. for j in (j1, ..., jU): m^_j = m~_j + msg_j * c (mod r)
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

// https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-proofverify
pub(crate) fn proof_verify_impl<'a, T: BbsCiphersuite<'a>>(
    pk: &G2Projective,
    proof: &Proof,
    header: &[u8],
    ph: &[u8],
    disclosed_messages: &[Scalar],
    disclosed_indexes: &[usize],
) -> bool {
    let R = disclosed_messages.len();
    let U = proof.m_hat.len();
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

    let generators = create_generators::<T>(L + 1);

    if disclosed_messages.len() != R {
        panic!("disclosed_messages length must be equal to R");
    }

    let domain = calculate_domain::<T>(pk, &generators, header);

    let D = generators.P1
        + generators.Q1 * domain
        + i.iter()
            .zip(disclosed_messages.iter())
            .map(|(i, m)| generators.H[*i] * m)
            .sum::<G1Projective>();

    // 7.  T =  Abar * r2^ + Bbar * r3^ + H_j1 * m^_j1 + ... +  H_jU * m^_jU
    // 8.  T = T + D * c
    let T = proof.A_bar * proof.r2_hat
        + proof.B_bar * proof.r3_hat
        + D * proof.c
        + j.iter().zip(proof.m_hat.iter()).map(|(i, m)| generators.H[*i] * m).sum::<G1Projective>();

    // 9.  cv = calculate_challenge(Abar, Bbar, C, (i1, ..., iR), (msg_i1, ..., msg_iR), domain, ph)
    let cv = calculate_challenge::<T>(&proof.A_bar, &proof.B_bar, &T, &i, disclosed_messages, &domain, ph);

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

impl Proof {
    pub fn to_bytes(&self) -> Vec<u8> {
        [
            &G1Affine::from(self.A_bar).to_compressed()[..],
            &G1Affine::from(self.B_bar).to_compressed(),
            &self.r2_hat.i2osp(SCALAR_LEN),
            &self.r3_hat.i2osp(SCALAR_LEN),
            &self.m_hat.iter().flat_map(|m| m.i2osp(SCALAR_LEN)).collect::<Vec<u8>>(),
            &self.c.i2osp(SCALAR_LEN),
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
        let r2_hat = Scalar::os2ip(&bytes[2 * P..2 * P + S]);
        let r3_hat = Scalar::os2ip(&bytes[2 * P + S..2 * P + 2 * S]);
        let mut m_hat = Vec::new();

        for i in 0..(bytes.len() - 2 * P - 3 * S) / S {
            m_hat.push(Scalar::os2ip(&bytes[2 * P + 2 * S + i * S..2 * P + 2 * S + (i + 1) * S]));
        }
        let c = Scalar::os2ip(&bytes[bytes.len() - S..]);

        Ok(Proof {
            A_bar,
            B_bar,
            r2_hat,
            r3_hat,
            m_hat,
            c,
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
        let header = hex_decode!(&input.header);

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
        let header = hex_decode!(&input.header);

        let bbs = Bbs::<Bls12381Shake256>::new(&header);
        proof_test::<Bls12381Shake256>(&input, bbs);
    }

    fn proof_test<'a, T: BbsCiphersuite<'a> + Default>(input: &tests::Proof, bbs: Bbs<'a, T>) {
        let input = input.clone();

        let pk = PublicKey::from_bytes(hex_decode!(input.signer_public_key));

        let ph = hex_decode!(input.presentation_header);

        let messages = input
            .revealed_messages
            .iter()
            .map(|(i, m)| (i, hex_decode!(m.as_bytes())))
            .map(|(i, m)| (*i, bbs.message(m)))
            .collect::<Vec<_>>();

        let revealed = messages.iter().map(|(i, _)| *i as usize).collect::<Vec<_>>();
        let messages = messages.iter().map(|(_, m)| *m).collect::<Vec<_>>();

        let proof = Proof::from_bytes(&hex_decode!(input.proof.as_bytes())).unwrap();

        let verify = bbs.verify_proof_with(&pk, &proof, &messages, &revealed, &ph).unwrap();

        assert_eq!(verify, input.result.valid);
    }

    #[test]
    fn test_proof_from_bytes() {
        let bytes = hex_decode!("8ffb2aeaa386e0240483b8b84d9af7084e62b09b8d0bbf76ba6bff1d308d82543a3f6b9eeb2493d2b7c36800ba055f7383a56ac1afc9de757ed23380a878f4da8c0c3fc3b0678efc97377d60299a4539fe9aa44ed6e1520956e7140c7f183f350990553621cea4d0531e33aa7a13d33d869a787d952a7a715a30e83bac952b13458e18413dc5361e81b5adacdbd2bb08eebf54d3e0103e5c1bd265506701aa53491fdc2bdba6f2e73c3a4a591330eafaea86e08baaf49d1cded3f70d8b1f3296");

        let proof = Proof::from_bytes(&bytes);

        assert!(proof.is_ok());
    }
}
