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
    const CIPHERSUITE_ID: &'a [u8] = b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_";
    type Expander = ExpandMsgXof<Shake256>;

    const BP: &'a [u8; 48] = &[
        143, 189, 5, 72, 170, 218, 112, 134, 54, 70, 254, 239, 1, 138, 134, 121, 129, 184, 90, 178, 46, 251, 128, 163, 20, 220, 150, 164, 239, 174,
        174, 239, 46, 64, 240, 212, 5, 36, 160, 220, 245, 174, 143, 229, 119, 125, 109, 147,
    ];
}

impl<'a> BbsCiphersuite<'a> for Bls12381Sha256 {
    const CIPHERSUITE_ID: &'a [u8] = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_";
    type Expander = ExpandMsgXmd<Sha256>;

    const BP: &'a [u8; 48] = &[
        134, 77, 243, 174, 117, 160, 35, 133, 43, 87, 124, 106, 164, 109, 22, 8, 215, 191, 183, 60, 89, 199, 61, 253, 71, 37, 14, 160, 28, 4, 236,
        26, 210, 5, 96, 232, 228, 172, 168, 34, 150, 202, 124, 78, 27, 124, 54, 32,
    ];
}

#[cfg(test)]
mod tests {
    use crate::hex;

    #[test]
    fn get_bp() {
        let bp = hex!("8fbd0548aada70863646feef018a867981b85ab22efb80a314dc96a4efaeaeef2e40f0d40524a0dcf5ae8fe5777d6d93");

        println!("{:?}", bp)
    }
}
