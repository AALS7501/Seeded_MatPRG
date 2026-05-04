use crate::gadget::hashes::constraints::{CRHSchemeGadget, TwoToOneCRHSchemeGadget};
use crate::gadget::hashes::poseidon::constraints::{CRHGadget, CRHParametersVar, TwoToOneCRHGadget};
use crate::gadget::hashes::poseidon::{PoseidonHash, TwoToOneCRH};
use crate::gadget::hashes::TwoToOneCRHScheme;
use crate::Error;

use super::{MockingCircuit, DATA_SET};
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{OptimizationGoal::Weight, ConstraintSynthesizer, SynthesisError};
use ark_std::{marker::PhantomData, UniformRand};

pub type ConstraintF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;

#[allow(non_snake_case)]
#[derive(Clone)]
pub struct EncDataPoseidonCTRCircuit<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>>
where
    C::BaseField: PrimeField + Absorb,
{
    // Constants
    pub pc: PoseidonConfig<C::BaseField>,

    // Public input
    pub H_k: Option<C::BaseField>,

    // Witnesses — CT first (committed by CP-SNARK)
    pub CT: Option<Vec<C::BaseField>>,
    pub data: Option<Vec<C::BaseField>>,
    pub data_key: Option<C::BaseField>,
    pub sk_seller: Option<C::BaseField>,

    pub _curve_var: PhantomData<GG>,
}

#[allow(non_snake_case)]
impl<C, GG> ConstraintSynthesizer<C::BaseField> for EncDataPoseidonCTRCircuit<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
    C::BaseField: PrimeField + Absorb,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    fn generate_constraints(self, cs: ark_relations::r1cs::ConstraintSystemRef<C::BaseField>) -> Result<(), SynthesisError> {
        cs.set_optimization_goal(Weight);

        // Constants
        let pc = CRHParametersVar::<C::BaseField>::new_constant(
            ark_relations::ns!(cs, "poseidon params"),
            self.pc,
        )?;

        // Public input
        let h_k = FpVar::new_input(cs.clone(), || self.H_k.ok_or(SynthesisError::AssignmentMissing))?;

        // Witnesses — CT first (committed by CP-SNARK)
        let CT: Vec<FpVar<C::BaseField>> = Vec::new_witness(ark_relations::ns!(cs, "CT"), || self.CT.ok_or(SynthesisError::AssignmentMissing))?;
        let data: Vec<FpVar<C::BaseField>> = Vec::new_witness(ark_relations::ns!(cs, "data"), || self.data.ok_or(SynthesisError::AssignmentMissing))?;
        let data_key = FpVar::new_witness(cs.clone(), || self.data_key.ok_or(SynthesisError::AssignmentMissing))?;
        let sk_seller = FpVar::new_witness(cs.clone(), || self.sk_seller.ok_or(SynthesisError::AssignmentMissing))?;

        // 1. CT[i] = data[i] + TwoToOnePoseidon(data_key, i)
        for i in 0..DATA_SET.Data_size {
            let counter = FpVar::Constant(C::BaseField::from(i as u64));
            let pad = TwoToOneCRHGadget::<C::BaseField>::evaluate(&pc, &data_key, &counter)?;
            (data[i].clone() + pad).enforce_equal(&CT[i])?;
        }

        // 2. H_k = Poseidon([data_key, sk_seller])
        let check_h_k = CRHGadget::<C::BaseField>::evaluate(&pc, &[data_key, sk_seller])?;
        h_k.enforce_equal(&check_h_k)?;

        println!("Total Constraints: {}", cs.num_constraints());
        Ok(())
    }
}

#[allow(non_snake_case)]
impl<C, GG> MockingCircuit<C, GG> for EncDataPoseidonCTRCircuit<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
    C::BaseField: PrimeField + Absorb,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    type F = C::BaseField;
    type HashParam = PoseidonConfig<Self::F>;
    type H = PoseidonHash<Self::F>;
    type Output = Self;

    fn generate_circuit<R: ark_std::rand::Rng>(pc: Self::HashParam, rng: &mut R) -> Result<Self, Error> {
        use crate::gadget::hashes::CRHScheme;

        let data: Vec<C::BaseField> = (0..DATA_SET.Data_size).map(|_| C::BaseField::rand(rng)).collect();
        let data_key = C::BaseField::rand(rng);

        let CT: Vec<C::BaseField> = (0..DATA_SET.Data_size).map(|i| {
            let counter = C::BaseField::from(i as u64);
            let pad = TwoToOneCRH::<C::BaseField>::evaluate(&pc, data_key, counter)
                .expect("Poseidon eval failed");
            data[i] + pad
        }).collect();

        // H_k = Poseidon([data_key, sk_seller])
        let sk_seller = C::BaseField::rand(rng);
        let h_k = Self::H::evaluate(&pc, [data_key, sk_seller].as_ref())?;

        Ok(Self {
            pc,
            H_k: Some(h_k),
            CT: Some(CT),
            data: Some(data),
            data_key: Some(data_key),
            sk_seller: Some(sk_seller),
            _curve_var: PhantomData,
        })
    }
}
