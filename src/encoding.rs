use bls12_381_plus::Scalar;

use crate::OctetString;

pub(crate) trait I2OSP {
    fn to_osp(&self, len: usize) -> OctetString;
}

pub(crate) trait OS2IP {
    fn from_osp(octet_string: &OctetString) -> Self;
}

impl I2OSP for usize {
    fn to_osp(&self, len: usize) -> OctetString {
        (*self as u64).to_osp(len)
    }
}

impl I2OSP for i32 {
    fn to_osp(&self, len: usize) -> OctetString {
        (*self as u64).to_osp(len)
    }
}

impl I2OSP for u64 {
    fn to_osp(&self, len: usize) -> OctetString {
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
    fn to_osp(&self, _: usize) -> OctetString {
        let mut i = self.to_bytes()[..].to_vec();
        i.reverse();
        i
    }
}

impl OS2IP for Scalar {
    fn from_osp(octet_string: &OctetString) -> Self {
        let mut i = octet_string[..].to_vec();
        i.reverse();
        Scalar::from_bytes(i.as_slice().try_into().unwrap()).unwrap()
    }
}

#[cfg(test)]
mod test {
    use crate::encoding::I2OSP;

    #[test]
    fn to_octet_string_test() {
        let i = 42usize;

        assert_eq!(i.to_osp(1).len(), 1);
        assert_eq!(i.to_osp(3).len(), 3);
        assert_eq!(i.to_osp(3), vec![0, 0, 42]);
    }
}
