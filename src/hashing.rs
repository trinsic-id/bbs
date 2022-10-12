use bls12_381_plus::{
    ExpandMsg, ExpandMsgXmd, G1Affine, G1Projective, G2Affine, G2Projective, Scalar,
};
use sha2::Sha256;

use crate::encoding::I2OSP;

const DST: &[u8] = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_MAP_MSG_TO_SCALAR_AS_HASH_";

#[allow(unused_comparisons)]
pub fn map_message_to_scalar_as_hash(message: &[u8]) -> Scalar {
    // 1. If length(dst) > 2^8 - 1 or length(msg) > 2^64 - 1, return INVALID
    if DST.len() > 0xFF || message.len() > 0xFFFF_FFFF_FFFF_FFFF {
        panic!("Invalid DST or message length");
    }
    // 2. dst_prime = I2OSP(length(dst), 1) || dst
    let dst_prime = [DST.len().to_osp(1), DST.to_vec()].concat();

    // 3. msg_prime = I2OSP(length(msg), 8) || msg
    let msg_prime = [message.len().to_osp(8), message.to_vec()].concat();

    // 4. result = hash_to_scalar(msg_prime || dst_prime, 1)
    let mut result = [0u8; 48];
    ExpandMsgXmd::<Sha256>::expand_message(
        [msg_prime, dst_prime].concat().as_slice(),
        DST,
        &mut result,
    );

    Scalar::from_okm(&result)
}

#[test]
fn t() {
    let i = (1 as u8).to_be_bytes();
    println!("{:?}", i);
}

pub(crate) trait EncodeForHash {
    fn encode_for_hash(&self) -> Vec<u8>;
}

impl EncodeForHash for &str {
    fn encode_for_hash(&self) -> Vec<u8> {
        [self.len().encode_for_hash(), self.as_bytes().to_vec()].concat()
    }
}

impl EncodeForHash for &[u8] {
    fn encode_for_hash(&self) -> Vec<u8> {
        [self.len().encode_for_hash(), self.to_vec()].concat()
    }
}

impl EncodeForHash for usize {
    fn encode_for_hash(&self) -> Vec<u8> {
        self.to_osp(8)
    }
}

impl EncodeForHash for u64 {
    fn encode_for_hash(&self) -> Vec<u8> {
        self.to_osp(8)
    }
}

impl EncodeForHash for u32 {
    fn encode_for_hash(&self) -> Vec<u8> {
        (*self as u64).to_osp(8)
    }
}

impl EncodeForHash for u8 {
    fn encode_for_hash(&self) -> Vec<u8> {
        (*self as u64).to_osp(8)
    }
}

impl EncodeForHash for i32 {
    fn encode_for_hash(&self) -> Vec<u8> {
        self.to_osp(8)
    }
}

impl EncodeForHash for G2Projective {
    fn encode_for_hash(&self) -> Vec<u8> {
        G2Affine::from(self).to_compressed().to_vec()
    }
}

impl EncodeForHash for G1Projective {
    fn encode_for_hash(&self) -> Vec<u8> {
        G1Affine::from(self).to_compressed().to_vec()
    }
}

impl EncodeForHash for G2Affine {
    fn encode_for_hash(&self) -> Vec<u8> {
        self.to_compressed().to_vec()
    }
}

impl EncodeForHash for G1Affine {
    fn encode_for_hash(&self) -> Vec<u8> {
        self.to_compressed().to_vec()
    }
}

impl EncodeForHash for Scalar {
    fn encode_for_hash(&self) -> Vec<u8> {
        let mut i = Scalar::to_bytes(self);
        // reverse the order of the bytes
        // to ensure they are in big endian
        i.reverse();
        i.to_vec()
    }
}
