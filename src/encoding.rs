use std::fmt::{Debug, Display, Formatter, Result};

use bls12_381::Scalar;

#[derive(Clone, PartialEq, Eq, Copy)]
pub struct Message(pub(crate) Scalar);

impl Debug for Message {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "{:?}", self.0)
    }
}

impl Display for Message {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "{:?}", self.0)
    }
}

pub trait I2OSP {
    fn i2osp(&self, len: usize) -> Vec<u8>;
}

pub(crate) trait OS2IP {
    fn os2ip(buf: &[u8]) -> Self;
}

impl I2OSP for usize {
    fn i2osp(&self, len: usize) -> Vec<u8> {
        (*self as u64).i2osp(len)
    }
}

impl I2OSP for u8 {
    fn i2osp(&self, len: usize) -> Vec<u8> {
        (*self as u64).i2osp(len)
    }
}

impl I2OSP for u64 {
    fn i2osp(&self, len: usize) -> Vec<u8> {
        let i = self.to_be_bytes();
        if len > i.len() {
            let mut v = vec![0u8; len - i.len()];
            v.extend_from_slice(&i);
            v
        } else {
            i[i.len() - len..].to_vec()
        }
    }
}

impl I2OSP for Scalar {
    fn i2osp(&self, _: usize) -> Vec<u8> {
        let mut i = self.to_bytes();
        i.reverse();
        i.to_vec()
    }
}

impl OS2IP for Scalar {
    fn os2ip(buf: &[u8]) -> Self {
        let mut i = buf[..].to_vec();
        i.reverse();
        Scalar::from_bytes(i.as_slice().try_into().unwrap()).unwrap()
    }
}

#[cfg(test)]
mod test {
    use crate::{encoding::I2OSP, hashing::EncodeForHash, hex};

    #[test]
    fn to_octet_string_test() {
        let i = 42usize;

        assert_eq!(i.i2osp(1), [42]);
        assert_eq!(i.i2osp(10), [0, 0, 0, 0, 0, 0, 0, 0, 0, 42]);
        assert_eq!(i.i2osp(3), vec![0, 0, 42]);
    }
}
