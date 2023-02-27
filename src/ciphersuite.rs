use bls12_381::hash_to_curve::{ExpandMessage, ExpandMsgXmd, ExpandMsgXof};
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

    type Expander: ExpandMessage;

    fn bp_generator_seed() -> Vec<u8> {
        [Self::CIPHERSUITE_ID, b"BP_MESSAGE_GENERATOR_SEED"].concat()
    }

    fn generator_seed() -> Vec<u8> {
        [Self::CIPHERSUITE_ID, b"MESSAGE_GENERATOR_SEED"].concat()
    }

    fn generator_seed_dst() -> Vec<u8> {
        [Self::CIPHERSUITE_ID, b"SIG_GENERATOR_SEED_"].concat()
    }

    fn generator_dst() -> Vec<u8> {
        [Self::CIPHERSUITE_ID, b"SIG_GENERATOR_DST_"].concat()
    }

    fn expand_dst() -> Vec<u8> {
        [Self::CIPHERSUITE_ID, b"SIG_DET_DST_"].concat()
    }

    fn hash_to_scalar_dst() -> Vec<u8> {
        [Self::CIPHERSUITE_ID, b"H2S_"].concat()
    }
    fn map_msg_to_scalar_as_hash_dst() -> Vec<u8> {
        [Self::CIPHERSUITE_ID, b"MAP_MSG_TO_SCALAR_AS_HASH_"].concat()
    }
}

#[derive(Default)]
pub struct Bls12381Shake256;

#[derive(Default)]
pub struct Bls12381Sha256;

impl<'a> BbsCiphersuite<'a> for Bls12381Shake256 {
    const CIPHERSUITE_ID: &'a [u8] = b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_";
    type Expander = ExpandMsgXof<Shake256>;
}

impl<'a> BbsCiphersuite<'a> for Bls12381Sha256 {
    const CIPHERSUITE_ID: &'a [u8] = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_";
    type Expander = ExpandMsgXmd<Sha256>;
}
