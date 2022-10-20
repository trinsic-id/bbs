use crate::{
    ciphersuite::{BbsCiphersuite, SEED_LEN},
    encoding::I2OSP,
};
pub use bls12_381_plus::{ExpandMsg, G1Projective};
pub(crate) struct Generators {
    pub(crate) P1: G1Projective,
    pub(crate) Q1: G1Projective,
    pub(crate) Q2: G1Projective,
    pub(crate) H: Vec<G1Projective>,
}

pub(crate) fn create_generators<'a, T: BbsCiphersuite<'a>>(
    seed: &[u8],
    count: usize,
) -> Generators {
    if count < 2 {
        panic!("count must be greater than 1");
    }

    let seed = if seed.is_empty() {
        T::generator_seed()
    } else {
        seed.to_vec()
    };

    let P1 = make_g1_base_point::<T>();

    // 1.  v = expand_message(generator_seed, seed_dst, seed_len)
    let mut v = [0u8; SEED_LEN];
    T::Expander::expand_message(&seed, &T::generator_seed_dst(), &mut v);

    // 2.  n = 1
    let mut n = 1usize;

    // 3.  for i in range(1, count):
    let mut generators = Vec::new();
    while generators.len() < count {
        // 4.     v = expand_message(v || I2OSP(n, 4), seed_dst, seed_len)
        T::Expander::expand_message(
            &[v.as_slice(), &n.i2osp(4)].concat(),
            &T::generator_seed_dst(),
            &mut v,
        );

        // 5.     n = n + 1
        n += 1;

        // 6.     generator_i = Identity_G1
        // 7.     candidate = hash_to_curve_g1(v, generator_dst)
        let candidate = G1Projective::hash::<T::Expander>(&v, &T::generator_dst());

        // 8.     if candidate in (generator_1, ..., generator_i):
        // 9.        go back to step 4
        if !generators.contains(&candidate) && candidate != G1Projective::identity() {
            // 10.    generator_i = candidate
            generators.push(candidate);
        }
    }

    // 11. return (generator_1, ..., generator_count)
    Generators {
        P1,
        Q1: generators[0],
        Q2: generators[1],
        H: generators[2..].to_vec(),
    }
}

fn make_g1_base_point<'a, T: BbsCiphersuite<'a>>() -> G1Projective {
    let mut v = [0u8; SEED_LEN];
    T::Expander::expand_message(&T::bp_generator_seed(), &T::generator_seed_dst(), &mut v);

    let extra = 1usize.i2osp(4);
    let buffer = [v.as_slice(), &extra].concat();

    T::Expander::expand_message(&buffer, &T::generator_seed_dst(), &mut v);

    G1Projective::hash::<T::Expander>(&v, &T::generator_dst())
}

#[cfg(test)]
mod test {

    use fluid::prelude::*;

    use crate::{ciphersuite::*, fixture, generators::*, hashing::*, hex, tests};

    #[theory]
    #[case("bls12-381-sha-256/generators.json", Bls12381Sha256)]
    #[case("bls12-381-shake-256/generators.json", Bls12381Shake256)]
    fn generators_test<'a, T>(file: &str, _: T)
    where
        T: BbsCiphersuite<'a>,
    {
        let input = fixture!(tests::Generators, file);

        let generators = create_generators::<T>(&[], input.msg_generators.len() + 2);

        assert_eq!(generators.P1.encode_for_hash(), hex!(input.bp));
        assert_eq!(generators.Q1.encode_for_hash(), hex!(input.q1));
        assert_eq!(generators.Q2.encode_for_hash(), hex!(input.q2));

        for i in 0..input.msg_generators.len() {
            assert_eq!(
                generators.H[i].encode_for_hash(),
                hex!(&input.msg_generators[i])
            );
        }
    }
}
