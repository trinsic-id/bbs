use bls12_381_plus::{ExpandMsg, G1Affine, G1Projective, G2Affine, G2Projective, Scalar};

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
        [T::CIPHERSUITE_ID, &T::map_msg_to_scalar_as_hash_dst()].concat()
    } else {
        dst.into()
    };

    // 1. msg_for_hash = encode_for_hash(msg)
    let msg_for_hash = message.encode_for_hash();

    // 2. if msg_for_hash is INVALID, return INVALID
    // 3. if length(dst) > 255, return INVALID
    // 4. return hash_to_scalar(msg_for_hash, 1, dst)
    let mut result = [Scalar::zero(); 1];
    hash_to_scalar::<T>(&msg_for_hash, &dst, &mut result);

    result[0]
}

// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-00.html#section-4.3
pub(crate) fn hash_to_scalar<'a, T>(msg_octets: &[u8], dst: &[u8], out: &mut [Scalar])
where
    T: BbsCiphersuite<'a>,
{
    let dst = if dst.is_empty() {
        [T::CIPHERSUITE_ID, &T::hash_to_scalar_dst()].concat()
    } else {
        dst.into()
    };
    let count = out.len();

    // 1.  len_in_bytes = count * expand_len
    let len_in_bytes = count * POINT_LEN;

    // 2.  t = 0
    let mut t = 0;

    // 3.  msg_prime = msg_octets || I2OSP(t, 1) || I2OSP(count, 4)
    let msg_prime = [msg_octets, &t.i2osp(1), &count.i2osp(4)].concat();

    // 4.  uniform_bytes = expand_message(msg_prime, h2s_dst, len_in_bytes)
    let mut uniform_bytes = vec![0u8; len_in_bytes];
    T::Expander::expand_message(&msg_prime, &dst, &mut uniform_bytes);

    // 5.  for i in (1, ..., count):
    // 6.      tv = uniform_bytes[(i-1)*expand_len..i*expand_len-1]
    // 7.      scalar_i = OS2IP(tv) mod r
    // 8.  if 0 in (scalar_1, ..., scalar_count):
    // 9.      t = t + 1
    // 10.     go back to step 3
    let mut i = 0;
    for item in out {
        *item = Scalar::from_okm(
            uniform_bytes[i * POINT_LEN..(i + 1) * POINT_LEN]
                .try_into()
                .unwrap(),
        );
        i += 1;
    }
}

pub trait EncodeForHash {
    fn encode_for_hash(&self) -> Vec<u8>;
}

impl EncodeForHash for dyn AsRef<[u8]> {
    fn encode_for_hash(&self) -> Vec<u8> {
        self.as_ref().into()
    }
}

impl EncodeForHash for &str {
    fn encode_for_hash(&self) -> Vec<u8> {
        [&self.len().encode_for_hash(), self.as_bytes()].concat()
    }
}

impl EncodeForHash for &[u8] {
    fn encode_for_hash(&self) -> Vec<u8> {
        [self.len().encode_for_hash(), self.to_vec()].concat()
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
    use bls12_381_plus::Scalar;
    use hex_literal::hex;

    use crate::{
        ciphersuite::{Bls12381Sha256, Bls12381Shake256},
        encoding::{I2OSP, OS2IP},
        hashing::hash_to_scalar,
    };

    use super::{map_message_to_scalar_as_hash, EncodeForHash};

    #[test]
    fn test_encode() {
        let s = "hello world".encode_for_hash();
        assert_eq!(11 + 8, s.len());
    }

    #[test]
    fn map_message_to_scalar_test() {
        let dst = hex!("4242535f424c53313233383147315f584d443a5348412d3235365f535357555f524f5f4d41505f4d4553534147455f544f5f5343414c41525f41535f484153485f");
        let message = hex!("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        let expected = hex!("45d23990955655bc3bcd91a3bc974df8ced44a35ab1043de0498d61e66f7af26");
        let expected_s = Scalar::os2ip(&expected);

        let actual = map_message_to_scalar_as_hash::<Bls12381Sha256>(&message, &dst);

        assert_eq!(expected_s, actual);
        assert_eq!(expected.as_slice(), actual.i2osp(32));
    }

    #[test]
    fn hash_to_curve_1_scalar_output_sha() {
        let dst =
            hex!("4242535f424c53313233383147315f584d443a5348412d3235365f535357555f524f5f4832535f");
        let message = hex!("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        let expected = hex!("3805512ad3be0b912c70fb460ee39085ee05eda69c9eea1be4977543c0db7af5");

        let mut actual = [Scalar::zero(); 1];
        hash_to_scalar::<Bls12381Sha256>(&message, &dst, &mut actual);

        assert_eq!(expected.as_slice(), actual[0].i2osp(32));
    }

    #[test]
    fn hash_to_curve_1_scalar_output_shake() {
        let dst = hex!(
            "4242535f424c53313233383147315f584f463a5348414b452d3235365f535357555f524f5f4832535f"
        );
        let message = hex!("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        let expected = hex!("260cab748e24ccc2bbd66f5b834d692622fa131f5ce898fa57217434c9ed14fa");

        let mut actual = [Scalar::zero(); 1];
        hash_to_scalar::<Bls12381Shake256>(&message, &dst, &mut actual);

        assert_eq!(expected.as_slice(), actual[0].i2osp(32));
    }

    #[test]
    fn hash_to_curve_10_scalar_output_shake() {
        let dst = hex!(
            "4242535f424c53313233383147315f584f463a5348414b452d3235365f535357555f524f5f4832535f"
        );
        let message = hex!("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        let expected = [
            hex!("5c6e62607c16397ee6d9624673be9a7ddacbc7b7dd290bdb853cf4c74a34de0a"),
            hex!("2a3524e43413a5d1b34c4c8ed119c4c5a2f9b84392ff0fea0d34e1be44ceafbc"),
            hex!("4b649b82eed1e62117d91cd8d22438e72f3f931a0f8ad683d1ade253333c472a"),
            hex!("64338965f1d37d17a14b6f431128c0d41a7c3924a5f484c282d20205afdfdb8f"),
            hex!("0dfe01c01ff8654e43a611b76aaf4faec618a50d85d34f7cc89879b179bde3d5"),
            hex!("6b6935016e64791f5d719f8206284fbe27dbb8efffb4141512c3fbfbfa861a0f"),
            hex!("0dfe13f85a36df5ebfe0efac3759becfcc2a18b134fd22485c151db85f981342"),
            hex!("5071751012c142046e7c3508decb0b7ba9a453d06ce7787189f4d93a821d538e"),
            hex!("5cdae3304e745553a75134d914db5b282cc62d295e3ed176fb12f792919fd85e"),
            hex!("32b67dfbba729831798279071a39021b66fd68ee2e68684a0f6901cd6fcb8256"),
        ];

        let mut actual = [Scalar::zero(); 10];
        hash_to_scalar::<Bls12381Shake256>(&message, &dst, &mut actual);

        for i in 0..10 {
            assert_eq!(expected[i].as_slice(), actual[i].i2osp(32));
        }
    }
}
