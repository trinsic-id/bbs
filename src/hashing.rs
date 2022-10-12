use bls12_381_plus::{ExpandMsg, G1Affine, G1Projective, G2Affine, G2Projective, Scalar};

use crate::{
    ciphersuite::{BbsCiphersuite, Bls12381Sha256},
    encoding::I2OSP,
};

// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-00.html#name-mapmessagetoscalarashash
#[allow(unused_comparisons)]
pub fn map_message_to_scalar_as_hash<'a, T: BbsCiphersuite<'a>>(message: &[u8]) -> Scalar {
    let dst = T::hash_to_scalar_dst();

    // 1. If length(dst) > 2^8 - 1 or length(msg) > 2^64 - 1, return INVALID
    if dst.len() > 0xFF || message.len() > 0xFFFF_FFFF_FFFF_FFFF {
        panic!("Invalid DST or message length");
    }
    // 2. dst_prime = I2OSP(length(dst), 1) || dst
    let dst_prime = [dst.len().to_osp(1), dst.to_vec()].concat();

    // 3. msg_prime = I2OSP(length(msg), 8) || msg
    let msg_prime = [message.len().to_osp(8), message.to_vec()].concat();

    // 4. result = hash_to_scalar(msg_prime || dst_prime, 1)
    let result = hash_to_scalar::<Bls12381Sha256>([msg_prime, dst_prime].concat().as_slice(), 1);
    assert_eq!(1, result.len());

    result[0]
}

// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-00.html#section-4.3
pub(crate) fn hash_to_scalar<'a, T: BbsCiphersuite<'a>>(
    msg_octets: &[u8],
    count: usize,
) -> Vec<Scalar> {
    const EXPAND_LEN: usize = 48;

    // 1.  len_in_bytes = count * expand_len
    let len_in_bytes = count * EXPAND_LEN;

    // 2.  t = 0
    let mut t = 0;

    // 3.  msg_prime = msg_octets || I2OSP(t, 1) || I2OSP(count, 4)
    let msg_prime = [msg_octets.to_vec(), t.to_osp(1), count.to_osp(4)].concat();

    // 4.  uniform_bytes = expand_message(msg_prime, h2s_dst, len_in_bytes)
    let mut uniform_bytes = vec![0u8; len_in_bytes];
    T::Expander::expand_message(
        msg_prime.as_slice(),
        T::hash_to_scalar_dst().as_slice(),
        uniform_bytes.as_mut_slice(),
    );

    // 5.  for i in (1, ..., count):
    // 6.      tv = uniform_bytes[(i-1)*expand_len..i*expand_len-1]
    // 7.      scalar_i = OS2IP(tv) mod r
    // 8.  if 0 in (scalar_1, ..., scalar_count):
    // 9.      t = t + 1
    // 10.     go back to step 3
    let mut result = Vec::new();
    for i in 0..count {
        result.push(Scalar::from_okm(
            uniform_bytes[i * EXPAND_LEN..(i + 1) * EXPAND_LEN]
                .try_into()
                .unwrap(),
        ));
    }
    result
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
