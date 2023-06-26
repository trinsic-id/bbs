#![allow(non_snake_case)]
#![allow(unused_mut)]

use std::array::TryFromSliceError;

use encoding::Message;
use itertools::Itertools;
use prelude::*;

mod ciphersuite;
mod encoding;
mod generators;
mod hashing;
mod key;
mod proof;
mod signature;
mod utils;
#[macro_use]
#[cfg(test)]
mod tests;

pub mod prelude {
    pub use crate::ciphersuite::*;
    pub use crate::key::*;
    pub use crate::proof::*;
    pub use crate::signature::*;
    pub use crate::*;
}

#[derive(Default)]
pub struct Bbs<'a, T>
where
    T: BbsCiphersuite<'a> + Default,
{
    _phantom: T,
    pub(crate) header: &'a [u8],
}

impl<'a, T> Bbs<'a, T>
where
    T: BbsCiphersuite<'a> + Default,
{
    pub fn new(header: &'a [u8]) -> Self {
        Self {
            header,
            ..Default::default()
        }
    }

    /// Map an octet string to a scalar message
    ///
    /// * See [MapMessageToScalarAsHash](https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-mapmessagetoscalarashash)
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```
    /// use bbs::prelude::*;
    ///
    /// let bbs = Bbs::<Bls12381Sha256>::default();
    /// let message = bbs.message("Hello, world!");
    /// ```
    ///
    /// Using with [`iter::map`](https://doc.rust-lang.org/std/iter/trait.Iterator.html#method.map):
    ///
    /// ```
    /// use bbs::prelude::*;
    ///
    /// let bbs = Bbs::<Bls12381Sha256>::default();
    /// let messages = ["hello", "world"]
    ///   .iter()
    ///   .map(|m| bbs.message(m))
    ///   .collect::<Vec<_>>();
    /// ```
    pub fn message<M: AsRef<[u8]>>(&self, buf: M) -> Message
    where
        M: AsRef<[u8]>,
    {
        Message(hashing::map_message_to_scalar_as_hash::<T>(buf.as_ref(), &[]))
    }

    /// Map an octet string to a scalar message using a domain separation tag
    ///
    /// * See [MapMessageToScalarAsHash](https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-mapmessagetoscalarashash)
    ///
    /// ## Examples
    /// ```
    /// use bbs::prelude::*;
    ///
    /// let bbs = Bbs::<Bls12381Sha256>::default();
    ///
    /// let message = bbs.message_with("Hello, world!", "MY DST");
    /// ```
    pub fn message_with<M, D>(&self, buf: M, dst: D) -> Message
    where
        M: AsRef<[u8]>,
        D: AsRef<[u8]>,
    {
        Message(hashing::map_message_to_scalar_as_hash::<T>(buf.as_ref(), dst.as_ref()))
    }

    /// Sign a vector of messages
    ///
    /// _Computes a deterministic signature from a secret key (SK) and optionally over a header and or a vector of messages_
    ///
    /// Specification [3.4.1. Sign](https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-sign)
    ///
    /// ## Examples
    ///
    /// ```
    /// use bbs::prelude::*;
    ///
    /// let sk = SecretKey::random::<Bls12381Sha256>();
    /// let bbs = Bbs::<Bls12381Sha256>::default();
    ///
    /// let data = [
    ///   bbs.message("Hello"),
    ///   bbs.message("World"),
    /// ];
    /// let signature = bbs.sign(&sk, &data);
    /// ```
    pub fn sign(&self, sk: &SecretKey, messages: &[Message]) -> Signature {
        signature::sign_impl::<T>(&sk.0, self.header, &messages.iter().map(|m| m.0).collect::<Vec<_>>())
    }

    /// Verify a signature
    ///
    /// > Checks that a signature is valid for a given header and vector of messages against a supplied public key (PK).
    /// > The messages MUST be supplied in this operation in the same order they were supplied to Sign when creating the signature
    ///
    /// Specification [3.4.2. Verify](https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-verify)
    /// ## Examples
    ///
    /// ```
    /// use bbs::prelude::*;
    ///
    /// let sk = SecretKey::random::<Bls12381Sha256>();
    /// let bbs = Bbs::<Bls12381Sha256>::default();
    ///
    /// let data = [
    ///   bbs.message("Hello"),
    ///   bbs.message("World"),
    /// ];
    /// let signature = bbs.sign(&sk, &data);
    ///
    /// let result = bbs.verify(&sk.public_key(), &signature, &data);
    /// ```
    pub fn verify(&self, pk: &PublicKey, signature: &Signature, messages: &[Message]) -> bool {
        signature::verify_impl::<T>(&pk.0, signature, self.header, &messages.iter().map(|m| m.0).collect::<Vec<_>>())
    }

    /// Create a proof of knowledge of a signature
    ///
    /// _Computes a zero-knowledge proof-of-knowledge of a signature,
    /// while optionally selectively disclosing from the original set of signed messages._
    ///
    /// Specification [3.4.3. ProofGen](https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-proofgen)
    pub fn create_proof(&self, pk: &PublicKey, signature: &Signature, messages: &[Message], revealed: &[usize]) -> Result<Proof, Error> {
        self.create_proof_with(pk, signature, messages, revealed, &[])
    }

    /// Create a proof of signature knowledge
    ///
    ///
    pub fn create_proof_with(
        &self,
        pk: &PublicKey,
        signature: &Signature,
        messages: &[Message],
        revealed: &[usize],
        ph: &[u8],
    ) -> Result<Proof, Error> {
        if revealed.len() > messages.len() || revealed.iter().any(|x| *x >= messages.len()) {
            return Err(Error::InvalidProof);
        }

        Ok(proof::proof_gen_impl::<T>(
            &pk.0,
            signature,
            self.header,
            ph,
            &messages.iter().map(|m| m.0).collect::<Vec<_>>(),
            &revealed.iter().unique().copied().collect::<Vec<_>>(),
        ))
    }

    pub fn verify_proof(&self, pk: &PublicKey, proof: &Proof, messages: &[Message], revealed: &[usize]) -> Result<bool, Error> {
        self.verify_proof_with(pk, proof, messages, revealed, &[])
    }

    pub fn verify_proof_with(&self, pk: &PublicKey, proof: &Proof, messages: &[Message], revealed: &[usize], ph: &[u8]) -> Result<bool, Error> {
        if revealed.len() != messages.len() {
            return Err(Error::InvalidProof);
        }

        Ok(proof::proof_verify_impl::<T>(
            &pk.0,
            proof,
            self.header,
            ph,
            &messages.iter().map(|m| m.0).collect::<Vec<_>>(),
            &revealed.iter().unique().copied().collect::<Vec<_>>(),
        ))
    }
}

#[derive(Debug)]
pub enum Error {
    InvalidSignature,
    InvalidProof,
    HkdfExpandError,
    SerializationError,
    KeyGenError,
}

impl From<TryFromSliceError> for Error {
    fn from(_: TryFromSliceError) -> Self {
        Error::SerializationError
    }
}

#[cfg(test)]
mod test {
    use bls12_381::G2Projective;

    use crate::{hashing::*, prelude::*};

    #[test]
    fn bbs_demo() {
        let sk = SecretKey::random::<Bls12381Sha256>();
        let pk = sk.0 * G2Projective::generator();

        let messages = ["one", "two", "three", "four"]
            .map(|m| map_message_to_scalar_as_hash::<Bls12381Sha256>(m.as_bytes(), &[]))
            .to_vec();

        // test sign and verify
        let signature = sign_impl::<Bls12381Sha256>(&sk.0, &[], &messages);
        let verify_result = verify_impl::<Bls12381Sha256>(&pk, &signature, &[], &messages);

        assert!(verify_result);

        // test proof_gen and proof_verify
        let proof = proof_gen_impl::<Bls12381Sha256>(&pk, &signature, &[], &[], &messages, &[1, 3]);

        let verify_result = proof_verify_impl::<Bls12381Sha256>(&pk, &proof, &[], &[], &[messages[1], messages[3]], &[1, 3]);

        assert!(verify_result);

        // test serialization
        let proof_bytes = proof.to_bytes();
        let proof_ = Proof::from_bytes(&proof_bytes).unwrap();

        println!("proof: {:#?}", proof);

        assert_eq!(proof, proof_);

        let signature_bytes = signature.to_bytes();
        let signature_ = Signature::from_bytes(&signature_bytes).unwrap();

        assert_eq!(signature, signature_);
    }
}
