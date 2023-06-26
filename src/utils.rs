use bls12_381::{G1Projective, G2Projective, Scalar};
use itertools::Itertools;

use crate::{
    ciphersuite::BbsCiphersuite,
    encoding::I2OSP,
    generators::Generators,
    hashing::{hash_to_scalar, EncodeForHash},
};

pub(crate) fn calculate_domain<'a, T>(pk: &G2Projective, generators: &Generators, header: &[u8]) -> Scalar
where
    T: BbsCiphersuite<'a>,
{
    // 1.  L = length(H_Points)
    let L = generators.H.len();

    // 4.  dom_array = (L, Q_1, H_1, ..., H_L)
    let dom_array_serilized = [
        L.serialize(),
        generators.Q1.serialize(),
        generators.H.iter().map(|g| g.serialize()).concat(),
    ]
    .concat();

    // 5.  dom_octs = serialize(dom_array) || ciphersuite_id
    let dom_octs = [dom_array_serilized, T::CIPHERSUITE_ID.to_vec()].concat();

    // 7.  dom_input = PK || dom_octs || I2OSP(length(header), 8) || header
    let dom_input = [pk.serialize(), dom_octs, header.len().i2osp(8), header.to_vec()].concat();

    // 4.  domain = hash_to_scalar(dom_for_hash, 1)
    hash_to_scalar::<T>(&dom_input, &[])
}

pub(crate) fn calculate_challenge<'a, T>(
    A_bar: &G1Projective,
    B_bar: &G1Projective,
    C: &G1Projective,
    disclosed_indices: &[usize],
    disclosed_messages: &[Scalar],
    domain: &Scalar,
    ph: &[u8],
) -> Scalar
where
    T: BbsCiphersuite<'a>,
{
    /*
       Procedure:

       1.  R = length(i_array)
       2.  if R > 2^64 - 1 or R != length(msg_array), return INVALID
       3.  if length(ph) > 2^64 - 1, return INVALID
       4.  (i1, ..., iR) = i_array
       5.  (msg_i1, ..., msg_iR) = msg_array
       6.  c_array = (A', Abar, D, C1, C2, R, i1, ..., iR,
                                       msg_i1, ..., msg_iR, domain)
       7.  c_octs = serialize(c_array)
       8.  if c_octs is INVALID, return INVALID
       9.  c_input = c_octs || I2OSP(length(ph), 8) || ph
       10. challenge = hash_to_scalar(c_input)
       11. if challenge is INVALID, return INVALID
       12. return challenge
    */

    let R = disclosed_indices.len();
    let c_array = [
        A_bar.serialize(),
        B_bar.serialize(),
        C.serialize(),
        R.serialize(),
        disclosed_indices.iter().map(|x| x.serialize()).concat(),
        disclosed_messages.iter().map(|x| x.serialize()).concat(),
        domain.serialize(),
    ];
    let c_octs = c_array.concat();
    let c_input = [c_octs, ph.len().i2osp(8), ph.to_vec()].concat();

    let challenge = hash_to_scalar::<T>(&c_input, &[]);

    challenge
}
