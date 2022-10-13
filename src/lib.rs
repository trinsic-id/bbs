#![allow(dead_code)]
#![allow(non_snake_case)]
#![allow(unused_mut)]

use bls12_381_plus::{G2Projective, Scalar};
use ciphersuite::OCTET_POINT_LENGTH;

use hkdf::Hkdf;
use sha2::{Digest, Sha256};

mod ciphersuite;
mod encoding;
mod generators;
mod hashing;
mod signature;

type SecretKey = Scalar;
type PublicKey = G2Projective;
type OctetString = Vec<u8>;

enum Error {
    InvalidSignature,
}

fn key_gen<T: AsRef<[u8]>>(ikm: T, key_info: &[u8]) -> SecretKey {
    if ikm.as_ref().len() < 32 {
        panic!("Input Keying Material (IKM) too short, MUST be at least 32 bytes");
    }

    // 1. salt = INITSALT
    let mut salt = b"BBS-SIG-KEYGEN-SALT-";
    // 2. SK = 0
    let mut _sk = Scalar::zero();
    // 3. while SK == 0:
    // 4.     salt = hash(salt)
    let salt_hashed = Sha256::digest(salt);

    // 5.     PRK = HKDF-Extract(salt, IKM || I2OSP(0, 1))
    let (_prk, hk) = Hkdf::<Sha256>::extract(
        Some(salt_hashed[..].as_ref()),
        vec![ikm.as_ref(), 0u8.to_be_bytes().as_ref()]
            .concat()
            .as_slice(),
    );
    // 6.     OKM = HKDF-Expand(PRK, key_info || I2OSP(L, 2), L)
    let mut okm = [0u8; OCTET_POINT_LENGTH];
    hk.expand(
        vec![
            key_info.as_ref()[..].as_ref(),
            OCTET_POINT_LENGTH.to_be_bytes().as_slice(),
        ]
        .concat()
        .as_slice(),
        &mut okm,
    )
    .expect("42 is a valid length for Sha256 to output");

    Scalar::from_okm(&okm)
}

// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-00.html#name-sktopk
fn sk_to_pk(sk: &SecretKey) -> PublicKey {
    G2Projective::generator() * sk
}

#[cfg(test)]
mod tests {
    use std::vec;

    use bls12_381_plus::G2Affine;

    use super::*;

    #[test]
    fn gen_sk_fixture() {
        let ikm = hex::decode("746869732d49532d6a7573742d616e2d546573742d494b4d2d746f2d67656e65726174652d246528724074232d6b6579").unwrap();

        let sk = key_gen(ikm, vec![].as_slice());

        let mut bytes = sk.to_bytes();
        bytes.reverse();

        println!("secret key: {:?}", hex::encode(bytes));
    }

    #[test]
    fn sk_to_pk_fixture() {
        let i = 0usize.to_be_bytes()[4..].to_vec();
        println!("i: {:?}", i);

        let mut sk =
            hex::decode("47d2ede63ab4c329092b342ab526b1079dbc2595897d4f2ab2de4d841cbe7d56")
                .unwrap();
        sk.reverse();

        let mut bytes = sk.as_slice();
        // let mut tmp = Scalar([0, 0, 0, 0]);

        // 93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8
        // 93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8

        let a = u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[0..8]).unwrap());
        let b = u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[8..16]).unwrap());
        let c = u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[16..24]).unwrap());
        let d = u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[24..32]).unwrap());

        let sk1 = Scalar::from_raw([a, b, c, d]);

        let secret_key = SecretKey::from_bytes(sk.as_slice().try_into().expect("msg")).unwrap();
        println!("secret key: {:x?}", secret_key.to_bytes());
        let pk = sk_to_pk(&sk1);

        let p: G2Affine = pk.into();

        println!("public key: {:x?}", hex::encode(p.to_compressed()));

        println!(
            "gen: {:?}",
            hex::encode(G2Affine::generator().to_compressed())
        );
    }
}
