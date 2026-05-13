use crate::gadget::hashes::{self, constraints::CRHSchemeGadget, mimc7::{self, constraints::{MiMCGadget, TwoToOneMiMCGadget}}};
use crate::gadget::hashes::constraints::TwoToOneCRHSchemeGadget;
use crate::gadget::hashes::TwoToOneCRHScheme;
use crate::Error;

use super::{MockingCircuit, DATA_SET};
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{OptimizationGoal::Weight, ConstraintSynthesizer, SynthesisError};
use ark_std::{marker::PhantomData, UniformRand};

pub type ConstraintF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;

#[allow(non_snake_case)]
#[derive(Clone)]
pub struct EncDataMiMCCTRCircuit<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>>
where
    C::BaseField: PrimeField + Absorb,
{
    // Constants
    pub rc: mimc7::Parameters<C::BaseField>,

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
impl<C, GG> ConstraintSynthesizer<C::BaseField> for EncDataMiMCCTRCircuit<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
    C::BaseField: PrimeField + Absorb,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    fn generate_constraints(self, cs: ark_relations::r1cs::ConstraintSystemRef<C::BaseField>) -> Result<(), SynthesisError> {
        cs.set_optimization_goal(Weight);

        // Constants
        let rc = mimc7::constraints::ParametersVar::new_constant(cs.clone(), self.rc)?;

        // Public input
        let h_k = FpVar::new_input(cs.clone(), || self.H_k.ok_or(SynthesisError::AssignmentMissing))?;

        // Witnesses — CT first (committed by CP-SNARK)
        let CT: Vec<FpVar<C::BaseField>> = Vec::new_witness(cs.clone(), || self.CT.ok_or(SynthesisError::AssignmentMissing))?;
        let data: Vec<FpVar<C::BaseField>> = Vec::new_witness(cs.clone(), || self.data.ok_or(SynthesisError::AssignmentMissing))?;
        let data_key = FpVar::new_witness(cs.clone(), || self.data_key.ok_or(SynthesisError::AssignmentMissing))?;
        let sk_seller = FpVar::new_witness(cs.clone(), || self.sk_seller.ok_or(SynthesisError::AssignmentMissing))?;

        // 1. CT[i] = data[i] + TwoToOneMiMC(data_key, i)
        for i in 0..DATA_SET.Data_size {
            let counter = FpVar::Constant(C::BaseField::from(i as u64));
            let pad = TwoToOneMiMCGadget::<C::BaseField>::evaluate(&rc, &data_key, &counter)?;
            (data[i].clone() + pad).enforce_equal(&CT[i])?;
        }

        // 2. H_k = MiMC(data_key || sk_seller)
        let check_h_k = MiMCGadget::<C::BaseField>::evaluate(&rc, &[data_key, sk_seller])?;
        h_k.enforce_equal(&check_h_k)?;

        println!("Total Constraints: {}", cs.num_constraints());
        Ok(())
    }
}

#[allow(non_snake_case)]
impl<C, GG> MockingCircuit<C, GG> for EncDataMiMCCTRCircuit<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
    C::BaseField: PrimeField + Absorb,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    type F = C::BaseField;
    type HashParam = mimc7::Parameters<Self::F>;
    type H = mimc7::MiMC<Self::F>;
    type Output = Self;

    fn generate_circuit<R: ark_std::rand::Rng>(rc: Self::HashParam, rng: &mut R) -> Result<Self, Error> {
        use crate::gadget::hashes::CRHScheme;

        let data: Vec<C::BaseField> = (0..DATA_SET.Data_size).map(|_| C::BaseField::rand(rng)).collect();
        let data_key = C::BaseField::rand(rng);

        let CT: Vec<C::BaseField> = (0..DATA_SET.Data_size).map(|i| {
            let counter = C::BaseField::from(i as u64);
            let pad = mimc7::TwoToOneMiMC::<C::BaseField>::evaluate(&rc, data_key, counter)
                .expect("MiMC eval failed");
            data[i] + pad
        }).collect();

        // H_k = MiMC(data_key || sk_seller)
        let sk_seller = C::BaseField::rand(rng);
        let h_k = Self::H::evaluate(&rc, vec![data_key, sk_seller])?;

        Ok(Self {
            rc,
            H_k: Some(h_k),
            CT: Some(CT),
            data: Some(data),
            data_key: Some(data_key),
            sk_seller: Some(sk_seller),
            _curve_var: PhantomData,
        })
    }
}
