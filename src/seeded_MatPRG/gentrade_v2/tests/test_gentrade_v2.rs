#[cfg(test)]
mod test {
    use crate::gadget::hashes::mimc7;
    use crate::gentrade_v2;
    use crate::gentrade_v2::circuit::GenTradeV2Circuit;
    use ark_bn254::Fr;
    use ark_ed_on_bn254::EdwardsProjective;
    use ark_ed_on_bn254::constraints::EdwardsVar;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
    use ark_std::rand::{RngCore, SeedableRng};
    use ark_std::test_rng;

    type C = EdwardsProjective;
    type GG = EdwardsVar;
    type F = Fr;

    #[test]
    fn test_gentrade_v2_constraints() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let rc: mimc7::Parameters<F> = mimc7::Parameters {
            round_constants: mimc7::parameters::get_bn256_round_constants(),
        };
        let circuit =
            <GenTradeV2Circuit<C, GG> as gentrade_v2::MockingCircuit<C, GG>>::generate_circuit(
                rc, &mut rng,
            )
            .unwrap();
        let cs = ConstraintSystem::<F>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }
}
