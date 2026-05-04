
use std::{ops::{AddAssign, Add}, marker::PhantomData};

use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, prelude::AllocVar};
use ark_relations::r1cs::SynthesisError;

use crate::gadget::hashes::constraints::{TwoToOneCRHSchemeGadget, CRHSchemeGadget};

use super::{Parameters, MiMC, TwoToOneMiMC};

#[derive(Clone)]
pub struct ParametersVar<F: PrimeField>
{
    params: Parameters<F>,
}

impl<F> AllocVar<Parameters<F>, F> for ParametersVar<F>
where
    F: PrimeField,
{
    fn new_variable<T: std::borrow::Borrow<Parameters<F>>>(
            _cs: impl Into<ark_relations::r1cs::Namespace<F>>,
            f: impl FnOnce() -> Result<T, SynthesisError>,
            _mode: ark_r1cs_std::prelude::AllocationMode,
        ) -> Result<Self, SynthesisError> {
        let params = f()?.borrow().clone();
        Ok( ParametersVar { params })
    }
}

pub struct MiMCGadget<F : PrimeField>
{
    _field: PhantomData<F>,
}


impl<F> MiMCGadget<F>
where
    F: PrimeField,
{
    fn round(xl: FpVar<F>, xr: FpVar<F>, rc: F) -> FpVar<F> {
        let mut xored = xl + xr;
        xored.add_assign(rc);

        let mut tmp = xored.clone();
        for _ in 0..2 {
            tmp *= tmp.clone();
            xored *= tmp.clone();
        }

        xored
    }

    fn encrypt(param : ParametersVar<F>, xl: FpVar<F>, xr: FpVar<F>) -> FpVar<F>
    {
        let mut res = Self::round(
            xl.clone(), 
            xr.clone(), 
            F::zero());

        for i in 1..param.params.round_constants.len() {
            res = Self::round(
                res.clone(), 
                xr.clone(), 
                param.params.round_constants[i]);
        }

        res.add(xr.clone())
    }
}

impl<F> CRHSchemeGadget<MiMC<F>, F> for MiMCGadget<F>
where
    F: PrimeField + Absorb,
{
    type ParametersVar = ParametersVar<F>;
    type InputVar = [FpVar<F>];
    type OutputVar = FpVar<F>;

    fn evaluate(
            parameter: &Self::ParametersVar,
            input: &Self::InputVar,
        ) -> Result<Self::OutputVar, SynthesisError> {
        let mut res: Self::OutputVar;
        if input.len() == 1 {
            let xl = input[0].clone();
            let xr = input[0].clone();
            res = Self::encrypt(parameter.clone(), xl, xr);
            res += input[0].clone() + input[0].clone();
        } else {
            res = input[0].clone();
            for i in 1..input.len() {
                let xl = res.clone();
                let xr = input[i].clone();

                res = Self::encrypt(parameter.clone(), xl.clone(), xr.clone());
                res += xl.clone() + input[i].clone();
            }
        }
        
        Ok(res)
    }

}

pub struct TwoToOneMiMCGadget<F : PrimeField>
{
    _field: PhantomData<F>,
}


impl<F> TwoToOneCRHSchemeGadget<TwoToOneMiMC<F>, F> for TwoToOneMiMCGadget<F>
where
    F: PrimeField + Absorb,
{
    type ParametersVar = ParametersVar<F>;
    type InputVar = FpVar<F>;
    type OutputVar = FpVar<F>;

    fn evaluate(
        parameters: &Self::ParametersVar,
        left_input: &Self::InputVar, 
        right_input: &Self::InputVar,
    ) -> Result<FpVar<F>, SynthesisError> {
        let xl = left_input.clone();
        let xr = right_input.clone();
        
        let mut res: Self::OutputVar = MiMCGadget::encrypt(parameters.clone(), xl, xr);
        res = res + left_input + right_input;
        
        Ok(res)
    }

    fn compress(
        parameters: &Self::ParametersVar,
        left_input: &Self::OutputVar,
        right_input: &Self::OutputVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        // TODO sponge
        <Self as TwoToOneCRHSchemeGadget<TwoToOneMiMC<F>, F>>::evaluate(parameters, left_input, right_input)
    }
}

#[cfg(test)]
mod tests {
    use ark_ff::{PrimeField};
    use ark_bn254::{Fr};
    use ark_r1cs_std::{fields::fp::FpVar, prelude::{AllocVar, EqGadget}, R1CSVar};
    use ark_relations::r1cs::ConstraintSystem;

    use crate::gadget::hashes::{mimc7::{self, parameters, constraints::{MiMCGadget, TwoToOneMiMCGadget, ParametersVar}}, TwoToOneCRHScheme, CRHScheme};

    use super::Parameters;

    fn print_hex(f: Fr) {
        let decimal_number = f.into_bigint().to_string();

        // Parse the decimal number as a BigUint
        let big_int = num_bigint::BigUint::parse_bytes(decimal_number.as_bytes(), 10).unwrap();

        // Convert the BigUint to a hexadecimal string
        let hex_string = format!("{:x}", big_int);

        println!("0x{}", hex_string);
    }

    #[test]
    fn test_mimc_twotoone_gadget() {
        use crate::gadget::hashes::constraints::TwoToOneCRHSchemeGadget;

        let rounc_constants = parameters::get_bn256_round_constants().clone();

        let param = Parameters {
            round_constants: rounc_constants,
        };

        let xl = Fr::from(111111);
        let xr = Fr::from(111111);

        let res: Fr = mimc7::TwoToOneMiMC::<Fr>::evaluate(&param, xl, xr).unwrap();
        print!("res:: ");
        print_hex(res);

        let cs = ConstraintSystem::<Fr>::new_ref();

        let xl_var = FpVar::new_witness(
            ark_relations::ns!(cs, "gadget_input"), 
            || Ok(&xl),
        ).unwrap();

        let xr_var = FpVar::new_witness(
            ark_relations::ns!(cs, "gadget_input"), 
            || Ok(&xr),
        ).unwrap();

        let expected_var = FpVar::new_input(
            ark_relations::ns!(cs, "gadget_output"), 
            || Ok(&res),
        ).unwrap();

        let param_var = ParametersVar::<Fr>::new_constant(
            ark_relations::ns!(cs, "gadget_const"), 
            &param,
        ).unwrap();
        let result_var = TwoToOneMiMCGadget::<Fr>::evaluate(&param_var, &xl_var, &xr_var).unwrap();

        expected_var.enforce_equal(&result_var).unwrap();

        print!("res:: ");
        print_hex(result_var.value().unwrap());

        assert_eq!(res, result_var.value().unwrap());

        assert!(cs.is_satisfied().unwrap());
    }
    #[test]
    fn test_mimc_hash_gadget() {
        use crate::gadget::hashes::constraints::CRHSchemeGadget;

        let rounc_constants = parameters::get_bn256_round_constants().clone();

        let param = Parameters {
            round_constants: rounc_constants,
        };

        let xl = Fr::from(111111);
        let xr = Fr::from(111111);

        let input_vec = [xl, xr].to_vec();

        let res: Fr = mimc7::MiMC::<Fr>::evaluate(&param, input_vec).unwrap();
        print!("res:: ");
        print_hex(res);

        let cs = ConstraintSystem::<Fr>::new_ref();

        let xl_var = FpVar::new_witness(
            ark_relations::ns!(cs, "gadget_input"), 
            || Ok(&xl),
        ).unwrap();

        let xr_var = FpVar::new_witness(
            ark_relations::ns!(cs, "gadget_input"), 
            || Ok(&xr),
        ).unwrap();

        let expected_var = FpVar::new_input(
            ark_relations::ns!(cs, "gadget_output"), 
            || Ok(&res),
        ).unwrap();

        let input_var_vec = [xl_var, xr_var].to_vec();
        let param_var = ParametersVar::<Fr>::new_constant(
            ark_relations::ns!(cs, "gadget_const"), 
            &param,
        ).unwrap();

        let result_var = MiMCGadget::<Fr>::evaluate(&param_var, &input_var_vec).unwrap();

        expected_var.enforce_equal(&result_var).unwrap();

        print!("res:: ");
        print_hex(result_var.value().unwrap());

        assert_eq!(res, result_var.value().unwrap());

        assert!(cs.is_satisfied().unwrap());
    }
}
