use crate::gadget::hashes;
use crate::gadget::hashes::constraints::CRHSchemeGadget;
use crate::gadget::hashes::mimc7;
use crate::gadget::hashes::mimc7::constraints::MiMCGadget;
use crate::Error;

use crate::gadget::symmetric_encrytions::constraints::SymmetricEncryptionGadget;
use crate::gadget::symmetric_encrytions::symmetric;
use crate::gadget::symmetric_encrytions::symmetric::constraints::SymmetricEncryptionSchemeGadget;

use super::MockingCircuit;
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::AffineRepr;
use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::{fields::fp::FpVar, prelude::AllocVar};
use ark_relations::r1cs::OptimizationGoal::Weight;
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};
use ark_std::marker::PhantomData;
// use rand::distributions::weighted::alias_method::Weight;

pub type ConstraintF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;
#[allow(non_snake_case)]
#[derive(Clone)]

pub struct MimcCircuit<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>>
where
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
{
    // constant
    pub rc: mimc7::Parameters<C::BaseField>,

    // statement
    pub mimc_output: Option<Vec<C::BaseField>>,

    // witnesses
    pub mimc_input: Option<Vec<C::BaseField>>,

    // directionSelector
    // intermediateHashWires
    pub _curve_var: PhantomData<GG>,
}

#[allow(non_snake_case)]
impl<C, GG> ConstraintSynthesizer<C::BaseField> for MimcCircuit<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<C::BaseField>,
    ) -> Result<(), SynthesisError> {
        // cs.set_optimization_goal(Weight);
        // constants
        let rc = hashes::mimc7::constraints::ParametersVar::new_constant(
            ark_relations::ns!(cs, "round constants"),
            self.rc,
        )?;

        // statement
        let mimc_output: Vec<FpVar<C::BaseField>> =
            Vec::new_input(ark_relations::ns!(cs, "mimc_output"), || {
                self.mimc_output.ok_or(SynthesisError::AssignmentMissing)
            })?;

        // witness
        let mimc_input: Vec<FpVar<C::BaseField>> =
            Vec::new_witness(ark_relations::ns!(cs, "mimc_input"), || {
                self.mimc_input.ok_or(SynthesisError::AssignmentMissing)
            })?;

        // relation

        for i in 0..mimc_input.len() {
            let tmp = MiMCGadget::<C::BaseField>::evaluate(&rc, &[mimc_input[i].clone()].to_vec())
                .unwrap();
            mimc_output[i].enforce_equal(&tmp)?;
            println!("cat: {:?}", mimc_output[i].is_eq(&tmp)?.value());
        }

        println!("Total Constraints num = {:?}", cs.num_constraints());

        Ok(())
    }
}

#[allow(non_snake_case)]
impl<C, GG> MockingCircuit<C, GG> for MimcCircuit<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    type F = C::BaseField;
    type HashParam = mimc7::Parameters<Self::F>;
    type H = mimc7::MiMC<Self::F>;
    type Output = MimcCircuit<C, GG>;

    fn generate_circuit<R: ark_std::rand::Rng>(
        round_constants: Self::HashParam,
        rng: &mut R,
    ) -> Result<Self::Output, Error> {
        use crate::gadget::hashes::CRHScheme;

        use ark_std::One;
        use ark_std::UniformRand;

        let rc: mimc7::Parameters<<<C as CurveGroup>::Affine as AffineRepr>::BaseField> =
            round_constants;

        let Randome_num = 32400;

        let mut mimc_input: Vec<C::BaseField> = Vec::new();
        for i in 0..Randome_num {
            mimc_input.push(Self::F::rand(rng));
        }

        let mut mimc_output = Vec::new();

        for i in 0..Randome_num {
            let tmp = Self::H::evaluate(&rc.clone(), [mimc_input[i]].to_vec()).unwrap();
            mimc_output.push(tmp);
        }

        Ok(MimcCircuit {
            //constant
            rc: rc.clone(),
            // statement
            mimc_output: Some(mimc_output),

            //witness
            mimc_input: Some(mimc_input),

            _curve_var: std::marker::PhantomData,
        })
    }
}
