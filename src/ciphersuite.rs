use bls12_381_plus::{ExpandMsg, ExpandMsgXmd, ExpandMsgXof};
use sha2::Sha256;
use sha3::Shake256;

pub trait BbsCiphersuite<'a> {
    const CIPHERSUITE_ID: &'a [u8];

    type Expander: ExpandMsg;

    fn generator_seed() -> Vec<u8> {
        [Self::CIPHERSUITE_ID, b"MESSAGE_GENERATOR_SEED"].concat()
    }

    // The G1 base point generator seed
    fn bp_generator_seed() -> Vec<u8> {
        [Self::CIPHERSUITE_ID, b"MESSAGE_GENERATOR_SEED"].concat()
    }

    fn generator_seed_dst() -> Vec<u8> {
        [Self::CIPHERSUITE_ID, b"SIG_GENERATOR_SEED_"].concat()
    }

    fn generator_dst() -> Vec<u8> {
        [Self::CIPHERSUITE_ID, b"SIG_GENERATOR_DST_"].concat()
    }

    fn hash_to_scalar_dst() -> Vec<u8> {
        [Self::CIPHERSUITE_ID, b"HASH_TO_SCALAR_"].concat()
    }
}

pub struct Bls12381Shake256;
pub struct Bls12381Sha256;

impl<'a> BbsCiphersuite<'a> for Bls12381Shake256 {
    const CIPHERSUITE_ID: &'a [u8] = b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_";
    type Expander = ExpandMsgXof<Shake256>;
}

impl<'a> BbsCiphersuite<'a> for Bls12381Sha256 {
    const CIPHERSUITE_ID: &'a [u8] = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_";
    type Expander = ExpandMsgXmd<Sha256>;
}