use bbs::prelude::*;

fn main() {
    let sk = SecretKey::random();
    let pk = sk.public_key();

    println!("sk: {}", &sk);
    println!("pk: {}", &pk);
}
