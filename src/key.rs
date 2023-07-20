use crate::{ciphersuite::BbsCiphersuite, encoding::I2OSP, hashing::hash_to_scalar, Error};
use bls12_381::{G2Affine, G2Projective, Scalar};
use core::fmt::{self, Debug, Display, Formatter};
use rand::Rng;
use serde::*;

#[derive(Clone, PartialEq, Eq)]
pub struct SecretKey(pub(crate) Scalar);

#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey(pub(crate) G2Projective);

pub(crate) fn key_gen<'a, T>(key_material: &[u8], key_info: &[u8], key_dst: &[u8]) -> Result<Scalar, Error>
where
    T: BbsCiphersuite<'a>,
{
    if key_material.len() < 32 {
        return Err(Error::KeyGenError);
    }
    if key_info.len() > 65535 {
        return Err(Error::KeyGenError);
    }

    let key_dst = if key_dst.len() == 0 { T::keygen_dst() } else { key_dst.into() };

    let derive_input = [key_material, &key_info.len().i2osp(2), key_info].concat();

    let sk = hash_to_scalar::<T>(&derive_input, key_dst.as_slice());

    return Ok(sk);
}

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

    pub fn to_bytes(&self) -> [u8; 96] {
        G2Affine::from(self.0).to_compressed()
    }
}

impl SecretKey {
    /// Generate a new secret key deterministicaly using a seed and key info
    pub fn new<'a, T>(salt: &[u8], key_info: Option<&[u8]>, key_dst: Option<&[u8]>) -> Self
    where
        T: BbsCiphersuite<'a>,
    {
        SecretKey(key_gen::<T>(salt, key_info.unwrap_or_default(), key_dst.unwrap_or_default()).unwrap())
    }

    /// Generate a new secret key using random parameters
    pub fn random<'a, T>() -> Self
    where
        T: BbsCiphersuite<'a>,
    {
        let random_bytes = rand::thread_rng().gen::<[u8; 32]>();
        SecretKey(key_gen::<T>(&random_bytes, &[], &[]).unwrap())
    }

    /// Get the public key associated with this secret key
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0 * G2Projective::generator())
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

impl Serialize for SecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0.to_bytes())
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes())
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
        write!(f, "{}", self.0)
    }
}

impl Display for SecretKey {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<T: AsRef<[u8; 96]>> From<T> for PublicKey {
    fn from(buf: T) -> Self {
        PublicKey(G2Affine::from_compressed(buf.as_ref()).unwrap().into())
    }
}

#[cfg(test)]
mod test {
    use bls12_381::{G2Projective, Scalar};

    use crate::{ciphersuite::*, fixture, hashing::*, hex_decode, tests};

    use super::SecretKey;
    use fluid::prelude::*;

    #[theory]
    #[case("bls12-381-sha-256/keypair.json", Bls12381Sha256)]
    #[case("bls12-381-shake-256/keypair.json", Bls12381Shake256)]
    fn keypair_test<'a, T>(file: &str, _: T)
    where
        T: BbsCiphersuite<'a>,
    {
        let input = fixture!(tests::KeyPairFixture, file);

        let sk = SecretKey::new::<T>(&hex_decode!(input.key_material), Some(&hex_decode!(input.key_info)), None);
        let pk = sk.public_key();

        assert_eq!(sk.0.serialize(), hex_decode!(input.key_pair.secret_key));
        assert_eq!(pk.0.serialize(), hex_decode!(input.key_pair.public_key));
    }

    #[test]
    fn get_random_key() {
        let sk = SecretKey::random::<Bls12381Sha256>();

        println!("{}", sk);

        assert_ne!(Scalar::zero(), sk.0);
    }

    #[test]
    fn gen_key_from_ikm() {
        let ikm = hex_decode!("746869732d49532d6a7573742d616e2d546573742d494b4d2d746f2d67656e65726174652d246528724074232d6b6579");

        let sk = SecretKey::new::<Bls12381Sha256>(&ikm, None, None);
        let pk = sk.public_key();

        assert_ne!(Scalar::zero(), sk.0);
        assert_ne!(G2Projective::identity(), pk.0);

        println!("sk: {}", sk);
        println!("pk: {}", pk);
    }
}
