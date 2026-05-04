#[cfg(test)]
mod test {
    use crate::accepttrade_v2::circuit::AcceptTradeV2Circuit;
    use crate::gadget::hashes::mimc7;
    use crate::gadget::hybrid_key_transport::pack_bits_to_fields;
    use crate::{accepttrade_v2, register_MatPRG, register_seeded_matprg};
    use ark_bn254::Fr;
    use ark_ed_on_bn254::EdwardsProjective;
    use ark_ed_on_bn254::constraints::EdwardsVar;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
    use ark_std::rand::{RngCore, SeedableRng};
    use ark_std::test_rng;
    use ark_std::UniformRand;

    type C = EdwardsProjective;
    type GG = EdwardsVar;
    type F = Fr;

    #[test]
    fn test_accepttrade_v2_original_payload_constraints() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let rc: mimc7::Parameters<F> = mimc7::Parameters {
            round_constants: mimc7::parameters::get_bn256_round_constants(),
        };
        let payload: Vec<F> = (0..register_MatPRG::DATA_SET.Key_len)
            .map(|_| F::rand(&mut rng))
            .collect();
        let circuit = AcceptTradeV2Circuit::<C, GG>::generate_circuit_with_payload(
            rc,
            32,
            payload,
            &mut rng,
        )
        .unwrap();
        let cs = ConstraintSystem::<F>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_accepttrade_v2_seeded_payload_constraints() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let rc: mimc7::Parameters<F> = mimc7::Parameters {
            round_constants: mimc7::parameters::get_bn256_round_constants(),
        };
        assert_eq!(register_MatPRG::DATA_SET.N, register_seeded_matprg::DATA_SET.N);
        assert_eq!(register_MatPRG::DATA_SET.K, register_seeded_matprg::DATA_SET.K);
        assert_eq!(
            register_MatPRG::DATA_SET.Data_size,
            register_seeded_matprg::DATA_SET.Data_size
        );
        assert!(register_seeded_matprg::current_key_bits() < register_MatPRG::current_key_bits());

        let seed_bits: Vec<bool> = (0..register_seeded_matprg::DATA_SET.M1)
            .map(|_| (rng.next_u32() & 1) == 1)
            .collect();
        let payload = pack_bits_to_fields::<F>(&seed_bits, 248);
        let circuit = AcceptTradeV2Circuit::<C, GG>::generate_circuit_with_payload(
            rc,
            32,
            payload,
            &mut rng,
        )
        .unwrap();
        let cs = ConstraintSystem::<F>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_payload_lengths_original_vs_seeded() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let original_len = register_MatPRG::DATA_SET.Key_len;
        let seed_bits: Vec<bool> = (0..register_seeded_matprg::DATA_SET.M1)
            .map(|_| (rng.next_u32() & 1) == 1)
            .collect();
        let seeded_len = pack_bits_to_fields::<F>(&seed_bits, 248).len();
        assert!(original_len >= seeded_len);
    }

    #[test]
    fn test_accepttrade_v2_default_trait_constructor() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let rc: mimc7::Parameters<F> = mimc7::Parameters {
            round_constants: mimc7::parameters::get_bn256_round_constants(),
        };
        let circuit =
            <AcceptTradeV2Circuit<C, GG> as accepttrade_v2::MockingCircuit<C, GG>>::generate_circuit(
                rc, 32, &mut rng,
            )
            .unwrap();
        let cs = ConstraintSystem::<F>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }
}
