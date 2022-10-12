# BBS Signatures

[WIP] Reference implementation of [BBS Signatures](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures) in Rust.

## Usage

```rust

use bbs::prelude::*;

// initialize the BBS ciphersuite
let bbs = Bbs::<Bls12381Sha256>::default();

// encoded message data
let data = [
    bbs.message("I ❤️ BBS"),
    bbs.message("I also ❤️ Rust"),
    bbs.message("Pie is better than cake"),
    bbs.message("Pineapple on pizza is a crime"),
    bbs.message("Blame copilot for these messages"),
];

// generate a random key
let sk = SecretKey::random();
let pk = sk.public_key();

// sign the messages
let signature = bbs.sign(&sk, &data);

// verify the signature
let res = bbs.verify(&pk, &data, &signature);

// create a proof by disclosing the messages at indices 1 and 3
let proof = bbs.create_proof(&pk, &signature, &data, &[1, 3]).unwrap();

let disclosed_data = [data[1], data[3]];

// verify the generated proof
let res = bbs.verify_proof(&pk, &proof, data.len(), &disclosed_data, &[1, 3]);
```