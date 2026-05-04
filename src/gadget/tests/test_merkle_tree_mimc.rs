
mod tests {
    use crate::gadget::hashes::mimc7;
    use crate::gadget::hashes::mimc7::Parameters;
    use crate::gadget::hashes::constraints::{CRHSchemeGadget, TwoToOneCRHSchemeGadget};

    use crate::gadget::merkle_tree::constraints::ConfigGadget;
    use crate::gadget::merkle_tree::{constraints::PathVar, Config, IdentityDigestConverter, MerkleTree};

    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_r1cs_std::uint32::UInt32;
    use ark_r1cs_std::R1CSVar;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::{test_rng, One, UniformRand};

    type F = ark_bn254::Fr;
    type H = mimc7::MiMC<F>;
    type HG = mimc7::constraints::MiMCGadget<F>;
    type TwoToOneH = mimc7::TwoToOneMiMC<F>;
    type TwoToOneHG = mimc7::constraints::TwoToOneMiMCGadget<F>;

    type LeafVar = [FpVar<F>];

    struct FieldMTConfig;
    impl Config for FieldMTConfig {
        type Leaf = [F];
        type LeafDigest = F;
        type LeafInnerDigestConverter = IdentityDigestConverter<F>;
        type InnerDigest = F;
        type LeafHash = H;
        type TwoToOneHash = TwoToOneH;
    }

    struct FieldMTConfigVar;

    impl ConfigGadget<FieldMTConfig, F> for FieldMTConfigVar {
        type Leaf = LeafVar;
        type LeafDigest = FpVar<F>;
        type LeafInnerConverter = IdentityDigestConverter<FpVar<F>>;
        type InnerDigest = FpVar<F>;
        type LeafHash = HG;
        type TwoToOneHash = TwoToOneHG;
    }

    type FieldMT = MerkleTree<FieldMTConfig>;

    fn merkle_tree_test_mimc(
        leaves: &[Vec<F>],
        use_bad_root: bool,
        update_query: Option<(usize, Vec<F>)>,
    ) {
        let leaf_crh_params = Parameters{ round_constants: mimc7::parameters::get_bn256_round_constants() };
        let two_to_one_params = leaf_crh_params.clone();
        let mut tree = FieldMT::new(
            &leaf_crh_params,
            &two_to_one_params,
            leaves.iter().map(|x| x.as_slice()),
        )
        .unwrap();
        let root = tree.root();
        for (i, leaf) in leaves.iter().enumerate() {
            println!("Current({}'th) leaf node: {:?}", i, leaf);
            let cs = ConstraintSystem::<F>::new_ref();
            let proof = tree.generate_proof(i).unwrap();
            assert!(proof
                .verify(&leaf_crh_params, &two_to_one_params, &root, leaf.as_slice())
                .unwrap());
            // Allocate MT root
            let root = FpVar::new_witness(cs.clone(), || {
                if use_bad_root {
                    Ok(root + F::one())
                } else {
                    Ok(root)
                }
            })
            .unwrap();

            let constraints_from_digest = cs.num_constraints();
            println!("constraints from digest: {}", constraints_from_digest);

            let leaf_crh_params_var = <HG as CRHSchemeGadget<H, _>>::ParametersVar::new_constant(
                ark_relations::ns!(cs, "leaf_crh_params"),
                &leaf_crh_params,
            )
            .unwrap();

            let two_to_one_crh_params_var =
                <TwoToOneHG as TwoToOneCRHSchemeGadget<TwoToOneH, _>>::ParametersVar::new_constant(
                    ark_relations::ns!(cs, "two_to_one_params"),
                    &leaf_crh_params,
                )
                .unwrap();

            let constraints_from_params = cs.num_constraints() - constraints_from_digest;
            println!("constraints from parameters: {}", constraints_from_params);

            // Allocate Leaf
            let leaf_g: Vec<_> = leaf
                .iter()
                .map(|x| FpVar::new_input(cs.clone(), || Ok(*x)).unwrap())
                .collect();

            let constraints_from_leaf =
                cs.num_constraints() - constraints_from_params - constraints_from_digest;
            println!("constraints from leaf: {}", constraints_from_leaf);

            // Allocate MT Path
            let mut cw = PathVar::<FieldMTConfig, F, FieldMTConfigVar>::new_witness(
                ark_relations::ns!(cs, "new_witness"),
                || Ok(&proof),
            )
            .unwrap();

            let constraints_from_path = cs.num_constraints()
                - constraints_from_params
                - constraints_from_digest
                - constraints_from_leaf;
            println!("constraints from path: {}", constraints_from_path);
            assert!(cs.is_satisfied().unwrap());

            // try replace the path index
            let leaf_pos = UInt32::new_witness(cs.clone(), || Ok(i as u32))
                .unwrap()
                .to_bits_le();
            cw.set_leaf_position(leaf_pos.clone());

            // check if get_leaf_position is correct
            let expected_leaf_pos = leaf_pos.value().unwrap();
            let mut actual_leaf_pos = cw.get_leaf_position().value().unwrap();
            actual_leaf_pos.extend((0..(32 - actual_leaf_pos.len())).map(|_| false));
            assert_eq!(expected_leaf_pos, actual_leaf_pos);

            assert!(cw
                .verify_membership(
                    &leaf_crh_params_var,
                    &two_to_one_crh_params_var,
                    &root,
                    &leaf_g
                )
                .unwrap()
                .value()
                .unwrap());

            let setup_constraints = constraints_from_leaf
                + constraints_from_digest
                + constraints_from_params
                + constraints_from_path;

            println!(
                "number of constraints for verification: {}",
                cs.num_constraints() - setup_constraints
            );

            assert!(
                cs.is_satisfied().unwrap(),
                "verification constraints not satisfied"
            );
        }

        // check update

        if let Some(update_query) = update_query {
            let cs = ConstraintSystem::<F>::new_ref();
            // allocate parameters for CRH
            let leaf_crh_params_var = <HG as CRHSchemeGadget<H, _>>::ParametersVar::new_constant(
                ark_relations::ns!(cs, "leaf_crh_params"),
                &leaf_crh_params,
            )
            .unwrap();

            let two_to_one_crh_params_var =
                <TwoToOneHG as TwoToOneCRHSchemeGadget<TwoToOneH, _>>::ParametersVar::new_constant(
                    ark_relations::ns!(cs, "two_to_one_params"),
                    &leaf_crh_params,
                )
                .unwrap();

            let old_leaf_var: Vec<_> = leaves[update_query.0]
                .iter()
                .map(|x| FpVar::new_input(cs.clone(), || Ok(*x)).unwrap())
                .collect();
            let new_leaf_var: Vec<_> = update_query
                .1
                .iter()
                .map(|x| FpVar::new_input(cs.clone(), || Ok(*x)).unwrap())
                .collect();

            let old_root = tree.root();
            let old_root_var = FpVar::new_input(cs.clone(), || Ok(old_root)).unwrap();

            let old_path = tree.generate_proof(update_query.0).unwrap();
            let old_path_var = PathVar::<FieldMTConfig, F, FieldMTConfigVar>::new_input(
                ark_relations::ns!(cs, "old_path"),
                || Ok(old_path),
            )
            .unwrap();
            let new_root = {
                tree.update(update_query.0, update_query.1.as_slice())
                    .unwrap();
                tree.root()
            };
            let new_root_var = FpVar::new_witness(cs.clone(), || Ok(new_root)).unwrap();

            assert!(old_path_var
                .update_and_check(
                    &leaf_crh_params_var,
                    &two_to_one_crh_params_var,
                    &old_root_var,
                    &new_root_var,
                    &old_leaf_var,
                    &new_leaf_var
                )
                .unwrap()
                .value()
                .unwrap());

            assert!(cs.is_satisfied().unwrap())
        }
    }

    #[test]
    fn good_root_test() {
        let mut rng = test_rng();
        let mut rand_leaves = || (0..2).map(|_| F::rand(&mut rng)).collect();

        let mut leaves: Vec<Vec<_>> = Vec::new();
        for _ in 0..128u8 {
            leaves.push(rand_leaves())
        }

        merkle_tree_test_mimc(&leaves, false, Some((3, rand_leaves())))
    }

    #[test]
    #[should_panic]
    fn bad_root_test() {
        let mut rng = test_rng();
        let mut rand_leaves = || (0..2).map(|_| F::rand(&mut rng)).collect();

        let mut leaves: Vec<Vec<_>> = Vec::new();
        for _ in 0..128u8 {
            leaves.push(rand_leaves())
        }

        merkle_tree_test_mimc(&leaves, true, Some((3, rand_leaves())))
    }
}
