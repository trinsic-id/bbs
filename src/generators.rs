use crate::{
    ciphersuite::{BbsCiphersuite, SEED_LEN},
    encoding::I2OSP,
};
pub use bls12_381::{hash_to_curve::*, G1Projective};
pub(crate) struct Generators {
    pub(crate) P1: G1Projective,
    pub(crate) Q1: G1Projective,
    pub(crate) H: Vec<G1Projective>,
}

pub(crate) fn create_generators<'a, T: BbsCiphersuite<'a>>(count: usize) -> Generators {
    if count < 1 {
        panic!("count must be 1 or greater");
    }

    let P1 = T::get_bp();

    // 1.  v = expand_message(generator_seed, seed_dst, seed_len)
    let mut v = T::Expander::init_expand(&T::generator_seed(), &T::generator_seed_dst(), SEED_LEN).into_vec();

    // 2.  n = 1
    let mut n = 1usize;

    // 3.  for i in range(1, count):
    let mut generators = Vec::new();
    while generators.len() < count {
        // 4.     v = expand_message(v || I2OSP(n, 4), seed_dst, seed_len)
        v = T::Expander::init_expand(&[v.as_slice(), &n.i2osp(4)].concat(), &T::generator_seed_dst(), SEED_LEN).into_vec();

        // 5.     n = n + 1
        n += 1;

        // 6.     generator_i = Identity_G1
        // 7.     candidate = hash_to_curve_g1(v, generator_dst)
        let candidate = <G1Projective as HashToCurve<T::Expander>>::hash_to_curve(&v, &T::generator_dst());

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
        H: generators[1..count].to_vec(),
    }
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

        let generators = create_generators::<T>(input.msg_generators.len() + 1);

        assert_eq!(generators.P1.serialize(), hex!(input.bp));
        assert_eq!(generators.Q1.serialize(), hex!(input.q1));

        for i in 0..input.msg_generators.len() {
            assert_eq!(generators.H[i].serialize(), hex!(&input.msg_generators[i]));
        }
    }
}
