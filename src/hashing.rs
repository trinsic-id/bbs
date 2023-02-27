use bls12_381::{
    hash_to_curve::{ExpandMessageState, HashToField, InitExpandMessage},
    G1Affine, G1Projective, G2Affine, G2Projective, Scalar,
};

use crate::{
    ciphersuite::{BbsCiphersuite, POINT_LEN},
    encoding::I2OSP,
};

// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-00.html#name-mapmessagetoscalarashash
#[allow(unused_comparisons)]
pub(crate) fn map_message_to_scalar_as_hash<'a, T>(message: &[u8], dst: &[u8]) -> Scalar
where
    T: BbsCiphersuite<'a>,
{
    let dst = if dst.is_empty() {
        T::map_msg_to_scalar_as_hash_dst()
    } else {
        dst.into()
    };

    // 1. if length(msg) > 2^64 - 1 or length(dst) > 255 return INVALID
    // 2. msg_scalar = hash_to_scalar(msg, 1, dst)
    // 3. if msg_scalar is INVALID, return INVALID
    // 4. return msg_scalar
    hash_to_scalar::<T>(message, &dst)
}

// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-00.html#section-4.3
pub(crate) fn hash_to_scalar<'a, T>(msg_octets: &[u8], dst: &[u8]) -> Scalar
where
    T: BbsCiphersuite<'a>,
{
    let dst = if dst.is_empty() { T::hash_to_scalar_dst() } else { dst.into() };

    // 2.  t = 0
    let mut t = 0usize;

    // 3.  msg_prime = msg_octets || I2OSP(t, 1) || I2OSP(count, 4)
    let msg_prime = [msg_octets, &0u8.i2osp(1)].concat();

    // 4.  uniform_bytes = expand_message(msg_prime, h2s_dst, len_in_bytes)
    let uniform_bytes = T::Expander::init_expand(&msg_prime, &dst, POINT_LEN).into_vec();

    // 5.  for i in (1, ..., count):
    // 6.      tv = uniform_bytes[(i-1)*expand_len..i*expand_len-1]
    // 7.      scalar_i = OS2IP(tv) mod r
    // 8.  if 0 in (scalar_1, ..., scalar_count):
    // 9.      t = t + 1
    // 10.     go back to step 3
    //let mut i = 0;
    Scalar::from_okm(uniform_bytes[0..POINT_LEN].try_into().unwrap())
}

pub trait EncodeForHash {
    fn encode_for_hash(&self) -> Vec<u8>;
}

impl EncodeForHash for dyn AsRef<[u8]> {
    fn encode_for_hash(&self) -> Vec<u8> {
        self.as_ref().into()
    }
}

impl EncodeForHash for usize {
    fn encode_for_hash(&self) -> Vec<u8> {
        self.i2osp(8)
    }
}

impl EncodeForHash for u64 {
    fn encode_for_hash(&self) -> Vec<u8> {
        self.i2osp(8)
    }
}

impl EncodeForHash for u8 {
    fn encode_for_hash(&self) -> Vec<u8> {
        (*self as u64).i2osp(8)
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
        self.i2osp(32)
    }
}

#[cfg(test)]
mod test {
    use bls12_381::Scalar;
    use fluid::prelude::*;

    use crate::{ciphersuite::*, encoding::*, fixture, hashing::*, hex, tests::*};

    #[theory]
    #[case("bls12-381-sha-256/MapMessageToScalarAsHash.json", Bls12381Sha256)]
    #[case("bls12-381-shake-256/MapMessageToScalarAsHash.json", Bls12381Shake256)]
    fn map_message_to_scalar_test<'a, T>(file: &str, _: T)
    where
        T: BbsCiphersuite<'a>,
    {
        let input = fixture!(MapMessageToScalar, file);
        let dst = hex!(input.dst);

        for c in input.cases {
            assert_eq!(map_message_to_scalar_as_hash::<T>(&hex!(c.message), &dst), Scalar::os2ip(&hex!(c.scalar)));
        }
    }

    #[theory]
    #[case("bls12-381-sha-256/h2s.json", Bls12381Sha256)]
    #[case("bls12-381-shake-256/h2s.json", Bls12381Shake256)]
    fn hash_to_scalar_test<'a, T>(file: &str, _: T)
    where
        T: BbsCiphersuite<'a>,
    {
        let input = fixture!(HashToScalar, file);
        let dst = hex!(input.dst);
        let message = hex!(input.message);

        let mut actual = hash_to_scalar::<T>(&message, &dst);

        assert_eq!(Scalar::os2ip(&hex!(input.scalar.as_bytes())), actual);
    }
}
