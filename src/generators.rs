use crate::{
    ciphersuite::{BbsCiphersuite, OCTET_POINT_LENGTH},
    encoding::I2OSP,
};
pub use bls12_381_plus::{ExpandMsg, G1Projective};
pub(crate) struct Generators {
    pub(crate) base_point: G1Projective,
    pub(crate) Q1: G1Projective,
    pub(crate) Q2: G1Projective,
    pub(crate) message_generators: Vec<G1Projective>,
}

pub(crate) fn create_generators<'a, T: BbsCiphersuite<'a>>(count: usize) -> Generators {
    if count < 2 {
        panic!("count must be greater than 1");
    }

    let generator_seed = T::generator_seed();
    let seed_dst = T::generator_seed_dst();
    let generator_dst = T::generator_dst();

    let P1 = make_g1_base_point::<T>();

    // 1.  v = expand_message(generator_seed, seed_dst, seed_len)
    let mut v = [0u8; OCTET_POINT_LENGTH];
    T::Expander::expand_message(generator_seed.as_slice(), seed_dst.as_slice(), &mut v);

    // 2.  n = 1
    let mut n = 1i32;

    // 3.  for i in range(1, count):
    let mut generators = Vec::new();
    while generators.len() < count {
        // 4.     v = expand_message(v || I2OSP(n, 4), seed_dst, seed_len)
        T::Expander::expand_message(
            [v.to_vec(), n.to_osp(4)].concat().as_slice(),
            seed_dst.as_slice(),
            &mut v,
        );

        // 5.     n = n + 1
        n += 1;

        // 6.     generator_i = Identity_G1
        // 7.     candidate = hash_to_curve_g1(v, generator_dst)
        let candidate = G1Projective::hash::<T::Expander>(&v, generator_dst.as_slice());

        // 8.     if candidate in (generator_1, ..., generator_i):
        // 9.        go back to step 4
        if !generators.contains(&candidate) && candidate != G1Projective::identity() {
            // 10.    generator_i = candidate
            generators.push(candidate);
        }
    }

    // 11. return (generator_1, ..., generator_count)
    Generators {
        base_point: P1,
        Q1: generators[0],
        Q2: generators[1],
        message_generators: generators[2..].to_vec(),
    }
}

fn make_g1_base_point<'a, T: BbsCiphersuite<'a>>() -> G1Projective {
    let mut v = [0u8; OCTET_POINT_LENGTH];
    T::Expander::expand_message(&T::bp_generator_seed(), &T::generator_seed_dst(), &mut v);

    let extra = 1.to_osp(4);
    let buffer = [v.as_ref(), &extra].concat();

    T::Expander::expand_message(&buffer, &T::generator_seed_dst(), &mut v);

    G1Projective::hash::<T::Expander>(&v, &T::generator_dst())
}
