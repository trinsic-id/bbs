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
    use bls12_381_plus::G1Affine;
    use hex_literal::hex;

    use crate::{
        ciphersuite::{Bls12381Sha256, Bls12381Shake256},
        generators::create_generators,
        hashing::EncodeForHash,
    };

    #[test]
    fn create_generators_sha() {
        let bp = hex!("8533b3fbea84e8bd9ccee177e3c56fbe1d2e33b798e491228f6ed65bb4d1e0ada07bcc4489d8751f8ba7a1b69b6eecd7");
        let q1 = hex!("b57ec5e001c28d4063e0b6f5f0a6eee357b51b64d789a21cf18fd11e73e73577910182d421b5a61812f5d1ca751fa3f0");
        let q2 = hex!("909573cbb9da401b89d2778e8a405fdc7d504b03f0158c31ba64cdb9b648cc35492b18e56088b44c8b4dc6310afb5e49");
        let h = [
            hex!("90248350d94fd550b472a54269e28b680757d8cbbe6bb2cb000742c07573138276884c2872a8285f4ecf10df6029be15"),
            hex!("8fb7d5c43273a142b6fc445b76a8cdfc0f96c5fdac7cdd73314ac4f7ec4990a0a6f28e4ad97fb0a3a22efb07b386e3ff"),
            hex!("8241e3e861aaac2a54a8d7093301143d7d3e9911c384a2331fcc232a3e64b4882498ce4d9da8904ffcbe5d6eadafc82b"),
            hex!("99bb19d202a4019c14a36933264ae634659994076bf02a94135e1026ea309c7d3fd6da60c7929d30b656aeaba7c0dcec"),
            hex!("81779fa5268e75a980799c0a01677a763e14ba82cbf0a66c653edc174057698636507ac58e73522a59585558dca80b42"),
            hex!("98a3f9af71d391337bc6ae5d26980241b6317d5d71570829ce03d63c17e0d2164e1ad793645e1762bfcc049a17f5994b"),
            hex!("aca6a84770bb1f515591b4b95d69777856ddc52d5439325839e31ce5b6237618a9bc01a04b0057d33eab14341504c7e9"),
            hex!("b96e206d6cf32b51d2f4d543972d488a4c4cbc5d994f6ebb0bdffbc5459dcb9a8e5ab045c5949dc7eb33b0545b62aae3"),
            hex!("8edf840b56ecf8d7c5a9c4a0aaf8a5525f3480df735743298dd2f4ae1cbb56f56ed6a04ef6fa7c92cd68d9101c7b8c8f"),
            hex!("86d4ae04738dc082eb37e753bc8ec35a8d982e463559214d0f777599f71aa1f95780b3dccbdcae45e146e5c7623dfe7d"),
        ].iter().map(|g| G1Affine::from_compressed(g).unwrap()).collect::<Vec<_>>();

        let generators = create_generators::<Bls12381Sha256>(&[], 12);

        assert_eq!(generators.P1.encode_for_hash(), bp);
        assert_eq!(generators.Q1.encode_for_hash(), q1);
        assert_eq!(generators.Q2.encode_for_hash(), q2);

        for i in 0..10 {
            assert_eq!(generators.H[i].encode_for_hash(), h[i].to_compressed());
        }
    }

    #[test]
    fn create_generators_shake() {
        let bp = hex!("91b784eaac4b2b2c6f9bfb2c9eae97e817dd12bba49a0821d175a50f1632465b319ca9fb81dda3fb0434412185e2cca5");
        let q1 = hex!("b60acd4b0dc13b580394d2d8bc6c07d452df8e2a7eff93bc9da965b57e076cae640c2858fb0c2eaf242b1bd11107d635");
        let q2 = hex!("ad03f655b4c94f312b051aba45977c924bc5b4b1780c969534c183784c7275b70b876db641579604328c0975eaa0a137");
        let h = [
            hex!("b63ae18d3edd64a2edd381290f0c68bebabaf3d37bc9dbb0bd5ad8daf03bbd2c48260255ba73f3389d2d5ad82303ac25"),
            hex!("b0b92b79a3e1fc59f39c6b9f78f00b873121c6a4c1814b94c07848efd172762fefbc48447a16f9ba8ed1b638e2933029"),
            hex!("b671ed7256777fb5b82f66d1268d03492a1cecc19fd327d56e100cce69c2e15fcd03dcdcfe6b2d42aa039edcd58092f4"),
            hex!("867009da287e1186884084ed71477ce9bd401e0bf4a7be48e2af0a3a4f2e7e21d2b7bb0ffdc4c03b5aa9672c3c76e0c9"),
            hex!("a3a10489bf1a244753e864454fd24ed8c312f737c0c2a529905222509199a0b48715a048cd93d134dac2cd4934c549bb"),
            hex!("81d548904ec8aa58b3f56f69c3f543fb73f339699a33df82c338cad9657b70c457b735c4ae96e8ea0c1ea0da65059d95"),
            hex!("b4bbc2a56104c2289fc7688fef30222746467df27698b6c2d53dad5477fd05b7ec8a84122b8122c1de2d2f16750d2a92"),
            hex!("ae22a4e89029d3507b8e40af3531b114b564cc77375c249036926e6973f69d21b356e734cdeda47fd320035781eda7df"),
            hex!("98b266b03b9cea3d466bafbcd2e1c600c40cba8817d52d46ea77612df911a6e6c040635211fc1bffd4ca914afca1ce55"),
            hex!("b458cd3d7af0b5ceea335436a66e2015b216467c204b850b15547f68f6f2a209e8229d154d4f998c7b96aa4f88cdca15"),
        ].iter().map(|g| G1Affine::from_compressed(g).unwrap()).collect::<Vec<_>>();

        let generators = create_generators::<Bls12381Shake256>(&[], 12);

        assert_eq!(generators.P1.encode_for_hash(), bp);
        assert_eq!(generators.Q1.encode_for_hash(), q1);
        assert_eq!(generators.Q2.encode_for_hash(), q2);

        for i in 0..10 {
            assert_eq!(generators.H[i].encode_for_hash(), h[i].to_compressed());
        }
    }
}
