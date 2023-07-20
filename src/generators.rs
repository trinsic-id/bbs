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
    if count == 0 || count == usize::MAX {
        panic!("count must be greater than 0 or less than 2^64");
    }

    let P1 = T::get_bp();

    let generators = hash_to_generators::<T>(count);

    // 11. return (generator_1, ..., generator_count)
    Generators {
        P1,
        Q1: generators[0],
        H: generators[1..count].to_vec(),
    }
}

pub(crate) fn hash_to_generators<'a, T: BbsCiphersuite<'a>>(count: usize) -> Vec<G1Projective> {
    // 1.  v = expand_message(generator_seed, seed_dst, seed_len)
    let mut v = T::Expander::init_expand(&T::generator_seed(), &T::generator_seed_dst(), SEED_LEN).into_vec();

    // 2.  n = 1
    let mut n = 1usize;

    // 3.  for i in range(1, count):
    let mut generators = Vec::new();
    while generators.len() < count {
        // 4.     v = expand_message(v || I2OSP(n, 4), seed_dst, seed_len)
        v = T::Expander::init_expand(&[v.as_slice(), &n.i2osp(8)].concat(), &T::generator_seed_dst(), SEED_LEN).into_vec();

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

    generators
}

#[cfg(test)]
mod test {

    use fluid::prelude::*;

    use crate::{ciphersuite::*, fixture, generators::*, hashing::*, hex_decode, tests};

    #[theory]
    #[case("bls12-381-sha-256/generators.json", Bls12381Sha256)]
    #[case("bls12-381-shake-256/generators.json", Bls12381Shake256)]
    fn generators_test<'a, T>(file: &str, _: T)
    where
        T: BbsCiphersuite<'a>,
    {
        let input = fixture!(tests::Generators, file);

        let generators = create_generators::<T>(input.msg_generators.len() + 1);

        assert_eq!(generators.P1.serialize(), hex_decode!(input.bp));
        assert_eq!(generators.Q1.serialize(), hex_decode!(input.q1));

        for i in 0..input.msg_generators.len() {
            assert_eq!(generators.H[i].serialize(), hex_decode!(&input.msg_generators[i]));
        }
    }

    // #[theory]
    // #[case(
    //     Bls12381Sha256,
    //     b"a8ce256102840821a3e94ea9025e4662b205762f9776b3a766c872b948f1fd225e7c59698588e70d11406d161b4e28c9"
    // )]
    // #[case(
    //     Bls12381Shake256,
    //     b"8929dfbc7e6642c4ed9cba0856e493f8b9d7d5fcb0c31ef8fdcd34d50648a56c795e106e9eada6e0bda386b414150755"
    // )]
    // fn get_bp<'a, T>(_: T, expected: &[u8])
    // where
    //     T: BbsCiphersuite<'a>,
    // {
    //     let generators = hash_to_generators::<T>(1);

    //     println!("{:?}", hex_decode!(expected));

    //     assert!(generators.len() == 1);
    //     assert_eq!(generators[0].serialize(), hex_decode!(expected));
    // }
}
