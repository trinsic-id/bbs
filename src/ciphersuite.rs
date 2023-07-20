use bls12_381::{
    hash_to_curve::{ExpandMessage, ExpandMsgXmd, ExpandMsgXof},
    G1Affine, G1Projective,
};
use sha2::Sha256;
use sha3::Shake256;

pub(crate) const SCALAR_LEN: usize = 32;
pub(crate) const POINT_LEN: usize = 48;

// https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-bls12-381-g1
// r: 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
// k: 128
// seed_len = ceil((ceil(log2(r)) + k)/8), where r and k are defined by the ciphersuite.
pub(crate) const SEED_LEN: usize = 48;

pub trait BbsCiphersuite<'a> {
    const CIPHERSUITE_ID: &'a [u8];
    const BP: &'a [u8; 48];

    type Expander: ExpandMessage;

    fn bp_generator_seed() -> Vec<u8> {
        [Self::CIPHERSUITE_ID, b"BP_MESSAGE_GENERATOR_SEED"].concat()
    }

    fn generator_seed() -> Vec<u8> {
        [Self::CIPHERSUITE_ID, b"MESSAGE_GENERATOR_SEED"].concat()
    }

    fn keygen_dst() -> Vec<u8> {
        [Self::CIPHERSUITE_ID, b"KEYGEN_DST_"].concat()
    }

    fn generator_seed_dst() -> Vec<u8> {
        [Self::CIPHERSUITE_ID, b"SIG_GENERATOR_SEED_"].concat()
    }

    fn generator_dst() -> Vec<u8> {
        [Self::CIPHERSUITE_ID, b"SIG_GENERATOR_DST_"].concat()
    }

    fn hash_to_scalar_dst() -> Vec<u8> {
        [Self::CIPHERSUITE_ID, b"H2S_"].concat()
    }
    fn map_msg_to_scalar_as_hash_dst() -> Vec<u8> {
        [Self::CIPHERSUITE_ID, b"MAP_MSG_TO_SCALAR_AS_HASH_"].concat()
    }
    fn get_bp() -> G1Projective {
        G1Projective::from(G1Affine::from_compressed(Self::BP).unwrap())
    }
}

#[derive(Default)]
pub struct Bls12381Shake256;

#[derive(Default)]
pub struct Bls12381Sha256;

impl<'a> BbsCiphersuite<'a> for Bls12381Shake256 {
    const CIPHERSUITE_ID: &'a [u8] = b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_";
    type Expander = ExpandMsgXof<Shake256>;

    const BP: &'a [u8; 48] = &[
        137, 41, 223, 188, 126, 102, 66, 196, 237, 156, 186, 8, 86, 228, 147, 248, 185, 215, 213, 252, 176, 195, 30, 248, 253, 205, 52, 213, 6, 72,
        165, 108, 121, 94, 16, 110, 158, 173, 166, 224, 189, 163, 134, 180, 20, 21, 7, 85,
    ];
}

impl<'a> BbsCiphersuite<'a> for Bls12381Sha256 {
    const CIPHERSUITE_ID: &'a [u8] = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_";
    type Expander = ExpandMsgXmd<Sha256>;

    const BP: &'a [u8; 48] = &[
        168, 206, 37, 97, 2, 132, 8, 33, 163, 233, 78, 169, 2, 94, 70, 98, 178, 5, 118, 47, 151, 118, 179, 167, 102, 200, 114, 185, 72, 241, 253, 34,
        94, 124, 89, 105, 133, 136, 231, 13, 17, 64, 109, 22, 27, 78, 40, 201,
    ];
}

#[cfg(test)]
mod tests {
    use crate::hex_decode;

    #[test]
    fn get_bp() {
        let bp = hex_decode!("8fbd0548aada70863646feef018a867981b85ab22efb80a314dc96a4efaeaeef2e40f0d40524a0dcf5ae8fe5777d6d93");

        println!("{:?}", bp)
    }
}
