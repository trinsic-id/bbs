use core::fmt::{self, Debug, Display, Formatter};

use bls12_381::{hash_to_curve::HashToField, G2Affine, G2Projective, Scalar};
use hkdf::Hkdf;
use rand::{thread_rng, RngCore};
use sha2::{digest::generic_array::GenericArray, Digest, Sha256};

use crate::encoding::I2OSP;

#[derive(Clone, PartialEq, Eq)]
pub struct SecretKey(pub(crate) Scalar);

#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey(pub(crate) G2Projective);

impl PublicKey {
    pub fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Self {
        let bytes = bytes.as_ref();
        if bytes.len() != 96 {
            panic!("Invalid length");
        }
        let mut buf = [0u8; 96];
        buf.copy_from_slice(bytes);
        let g2 = &G2Affine::from_compressed(&buf).unwrap();
        PublicKey(g2.into())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        G2Affine::from(self.0).to_compressed().to_vec()
    }
}

impl SecretKey {
    /// Generate a new secret key deterministicaly using a seed and key info
    pub fn new<S, K>(salt: S, key_info: K) -> Self
    where
        S: AsRef<[u8]>,
        K: AsRef<[u8]>,
    {
        SecretKey(key_gen(salt.as_ref(), key_info.as_ref()))
    }

    /// Generate a new secret key using random parameters
    pub fn random() -> Self {
        SecretKey(key_gen(&[], &[]))
    }

    /// Get the public key associated with this secret key
    pub fn public_key(&self) -> PublicKey {
        PublicKey(sk_to_pk(&self.0))
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let tmp = G2Affine::from(&self.0).to_compressed();
        write!(f, "0x")?;
        for &b in tmp.iter() {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Debug for SecretKey {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl Display for SecretKey {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl<T: AsRef<[u8; 96]>> From<T> for PublicKey {
    fn from(buf: T) -> Self {
        PublicKey(G2Affine::from_compressed(buf.as_ref()).unwrap().into())
    }
}

pub(crate) fn key_gen(ikm: &[u8], key_info: &[u8]) -> Scalar {
    let ikm = if ikm.is_empty() {
        let mut seed = [0u8; 32];
        thread_rng().fill_bytes(&mut seed);
        seed.to_vec()
    } else {
        ikm.to_vec()
    };

    // r: 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    // L is the integer given by ceil((3 * ceil(log2(r))) / 16).
    const L: usize = 48;

    // INITSALT is the ASCII string "BBS-SIG-KEYGEN-SALT-"
    const INITSALT: &[u8; 20] = b"BBS-SIG-KEYGEN-SALT-";

    // 1. salt = INITSALT
    let mut salt = INITSALT.to_vec();

    // 2. SK = 0
    let mut sk = Scalar::zero();
    // 3. while SK == 0:
    while sk == Scalar::zero() {
        // 4.     salt = hash(salt)
        salt = Sha256::digest(&salt).to_vec();

        // 5.     PRK = HKDF-Extract(salt, IKM || I2OSP(0, 1))
        let (_, hk) = Hkdf::<Sha256>::extract(Some(&salt), &[ikm.clone(), 0u8.i2osp(1)].concat());

        // 6.     OKM = HKDF-Expand(PRK, key_info || I2OSP(L, 2), L)
        let mut okm = [0u8; L];
        hk.expand(&[key_info, &L.i2osp(2)].concat(), &mut okm).unwrap();

        // 7.     SK = OS2IP(OKM) mod r
        sk = Scalar::from_okm(GenericArray::from_slice(&okm));
    }

    // 8. return SK
    sk
}

// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-00.html#name-sktopk
pub(crate) fn sk_to_pk(sk: &Scalar) -> G2Projective {
    G2Projective::generator() * sk
}

#[cfg(test)]
mod test {
    use bls12_381::{G2Affine, G2Projective, Scalar};

    use crate::{encoding::OS2IP, hashing::EncodeForHash, hex};

    use super::{sk_to_pk, SecretKey};

    #[test]
    fn get_random_key() {
        let sk = SecretKey::random();

        assert_ne!(Scalar::zero(), sk.0);
    }

    #[test]
    fn gen_key_from_ikm() {
        let ikm = hex!("746869732d49532d6a7573742d616e2d546573742d494b4d2d746f2d67656e65726174652d246528724074232d6b6579");

        let sk = SecretKey::new(&ikm, &[]);
        let pk = sk.public_key();

        assert_ne!(Scalar::zero(), sk.0);
        assert_ne!(G2Projective::identity(), pk.0);

        println!("sk: {}", sk);
        println!("pk: {}", pk);
    }

    #[test]
    fn sk_to_pk_test() {
        let sk = hex!("47d2ede63ab4c329092b342ab526b1079dbc2595897d4f2ab2de4d841cbe7d56");
        let expected_pk = hex!("b65b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7");

        let actual_pk = sk_to_pk(&Scalar::os2ip(&sk));

        assert_eq!(expected_pk, G2Affine::from(actual_pk).to_compressed());
        assert_eq!(expected_pk.as_slice(), &actual_pk.encode_for_hash());
    }
}
