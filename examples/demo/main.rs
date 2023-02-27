use bbs::prelude::*;

fn main() {
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
    println!("messages: {:#?}", data);

    // generate a random key
    let sk = SecretKey::random();
    println!("secret key: {:?}", sk);

    let pk = sk.public_key();
    println!("public key: {:?}", pk);

    // sign the messages
    let signature = bbs.sign(&sk, &data);
    println!("signature: {:?}", signature);

    // verify the signature
    let res = bbs.verify(&pk, &signature, &data);
    println!("verify signature result: {:?}", res);

    // create a proof by disclosing the messages at indices 1 and 3
    let proof = bbs.create_proof(&pk, &signature, &data, &[1, 3]).unwrap();
    println!("proof: {:?}", proof);

    let disclosed_data = [data[1], data[3]];
    println!("disclosed messages: {:#?}", disclosed_data);

    // verify the generated proof
    let res = bbs.verify_proof(&pk, &proof, &disclosed_data, &[1, 3]);
    println!("verify proof result: {:?}", res.unwrap());
}
