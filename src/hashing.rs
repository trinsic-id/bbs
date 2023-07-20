use bls12_381::{
    hash_to_curve::{ExpandMessageState, HashToField, InitExpandMessage},
    G1Affine, G1Projective, G2Affine, G2Projective, Scalar,
};

use crate::{ciphersuite::BbsCiphersuite, encoding::I2OSP};

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

    // uniform_bytes = expand_message(msg_prime, h2s_dst, len_in_bytes)
    let mut uniform_bytes = T::Expander::init_expand(&msg_octets, &dst, 48).into_vec();

    Scalar::from_okm(uniform_bytes[..].try_into().unwrap())
}

pub trait EncodeForHash {
    fn serialize(&self) -> Vec<u8>;
}

impl EncodeForHash for dyn AsRef<[u8]> {
    fn serialize(&self) -> Vec<u8> {
        self.as_ref().into()
    }
}

impl EncodeForHash for usize {
    fn serialize(&self) -> Vec<u8> {
        self.i2osp(8)
    }
}

impl EncodeForHash for u64 {
    fn serialize(&self) -> Vec<u8> {
        self.i2osp(8)
    }
}

impl EncodeForHash for u8 {
    fn serialize(&self) -> Vec<u8> {
        (*self as u64).i2osp(8)
    }
}

impl EncodeForHash for G2Projective {
    fn serialize(&self) -> Vec<u8> {
        G2Affine::from(self).to_compressed().to_vec()
    }
}

impl EncodeForHash for G1Projective {
    fn serialize(&self) -> Vec<u8> {
        G1Affine::from(self).to_compressed().to_vec()
    }
}

impl EncodeForHash for G2Affine {
    fn serialize(&self) -> Vec<u8> {
        self.to_compressed().to_vec()
    }
}

impl EncodeForHash for G1Affine {
    fn serialize(&self) -> Vec<u8> {
        self.to_compressed().to_vec()
    }
}

impl EncodeForHash for Scalar {
    fn serialize(&self) -> Vec<u8> {
        self.i2osp(32)
    }
}

#[cfg(test)]
mod test {
    use bls12_381::Scalar;
    use fluid::prelude::*;

    use crate::{ciphersuite::*, encoding::*, fixture, hashing::*, hex_decode, tests::*};

    #[theory]
    #[case("bls12-381-sha-256/MapMessageToScalarAsHash.json", Bls12381Sha256)]
    #[case("bls12-381-shake-256/MapMessageToScalarAsHash.json", Bls12381Shake256)]
    fn map_message_to_scalar_test<'a, T>(file: &str, _: T)
    where
        T: BbsCiphersuite<'a>,
    {
        let input = fixture!(MapMessageToScalar, file);
        let dst = hex_decode!(input.dst);

        for c in input.cases {
            assert_eq!(
                map_message_to_scalar_as_hash::<T>(&hex_decode!(c.message), &dst),
                Scalar::os2ip(&hex_decode!(c.scalar))
            );
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
        let dst = hex_decode!(input.dst);
        let message = hex_decode!(input.message);

        let mut actual = hash_to_scalar::<T>(&message, &dst);

        assert_eq!(Scalar::os2ip(&hex_decode!(input.scalar.as_bytes())), actual);
    }
}
