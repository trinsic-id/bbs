use bbs::prelude::*;

fn main() {
    let sk = SecretKey::random::<Bls12381Sha256>();
    let pk = sk.public_key();

    println!("sk: {}", &sk);
    println!("pk: {}", &pk);
}
