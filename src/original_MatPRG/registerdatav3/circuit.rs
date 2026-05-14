use crate::gadget::hashes;
use crate::gadget::hashes::constraints::CRHSchemeGadget;
use crate::gadget::hashes::mimc7::constraints::MiMCGadget;
use crate::gadget::hashes::mimc7::{self};
use crate::Error;
use core::borrow::Borrow;

use super::MockingCircuit;
use crate::registerdatav3::DATA_SET;
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, Field, PrimeField};
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    eq::EqGadget,
};
use ark_relations::r1cs::Namespace;
use ark_relations::r1cs::OptimizationGoal::Weight;
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::marker::PhantomData;

use ark_std::UniformRand;
use core::ops::Mul;
use std::iter::Iterator;
#[derive(Clone, Default, Debug, PartialEq, CanonicalDeserialize, CanonicalSerialize)]
pub struct Matrix<F: PrimeField> {
    pub matrix: Vec<Vec<F>>,
}

#[derive(Clone, Debug)]
pub struct MatrixVar<F: PrimeField> {
    pub matrix: Vec<Vec<FpVar<F>>>,
}

impl<F> AllocVar<Matrix<F>, F> for MatrixVar<F>
where
    F: PrimeField,
{
    fn new_variable<T: Borrow<Matrix<F>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let mut vec = Vec::new();

        let matrix_value = f()?.borrow().clone();

        for i in 0..matrix_value.matrix.len() {
            vec.push(Vec::new_variable(
                cs.clone(),
                || Ok(matrix_value.matrix[i].clone()),
                mode,
            )?)
        }

        Ok(Self { matrix: vec })
    }
}
impl<F: PrimeField> Matrix<F> {
    pub fn new(matrix: Vec<Vec<F>>) -> Matrix<F> {
        Matrix { matrix }
    }
}

impl<F: PrimeField> Mul<Matrix<F>> for Matrix<F> {
    type Output = Matrix<F>;

    fn mul(self, other: Matrix<F>) -> Matrix<F> {
        assert_eq!(
            self.matrix.first().unwrap().len(),
            other.matrix.len(),
            "Matrices cannot be multiplied"
        );

        let mut result = Matrix::new(vec![
            vec![F::ZERO; other.matrix.first().unwrap().len()];
            self.matrix.len()
        ]);

        for i in 0..self.matrix.len() {
            for j in 0..other.matrix.first().unwrap().len() {
                for k in 0..self.matrix.first().unwrap().len() {
                    result.matrix[i][j] += self.matrix[i][k] * other.matrix[k][j];
                }
            }
        }

        result
    }
}

impl<F: PrimeField> Mul<MatrixVar<F>> for MatrixVar<F> {
    type Output = MatrixVar<F>;

    fn mul(self, other: MatrixVar<F>) -> MatrixVar<F> {
        assert_eq!(
            self.matrix.first().unwrap().len(),
            other.matrix.len(),
            "Matrices cannot be multiplied"
        );

        let A = self.matrix;
        let B = other.matrix;

        let mut result = vec![vec![FpVar::<F>::zero(); B.first().unwrap().len()]; A.len()];

        for i in 0..A.len() {
            for j in 0..B.first().unwrap().len() {
                for k in 0..A.first().unwrap().len() {
                    result[i][j] += A[i][k].clone() * B[k][j].clone();
                }
            }
        }

        MatrixVar { matrix: result }
    }
}

pub type ConstraintF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;

// impl<F: PrimeField> MatrixVar<F> {
//     fn is_safe(&self, row: usize, col: usize, value: &FpVar<F>) -> bool {
//         for i in 0..16 {
//             if self.matrix[row][i] == *value || self.matrix[i][col] == *value {
//                 return false;
//             }
//         }

//         let start_row = row - row % 4;
//         let start_col = col - col % 4;
//         for i in 0..4 {
//             for j in 0..4 {
//                 if self.matrix[start_row + i][start_col + j] == *value {
//                     return false;
//                 }
//             }
//         }
//         true
//     }

//     pub fn solve(&mut self) -> bool {
//         if let Some((row, col)) = self.find_unassigned_location() {
//             for num in 1u8..=16 {
//                 let value = FpVar::Constant(F::from(num as u64));

//                 if self.is_safe(row, col, &value) {
//                     self.matrix[row][col] = value.clone();

//                     if self.solve() {
//                         return true;
//                     }

//                     self.matrix[row][col] = FpVar::Constant(F::zero());
//                 }
//             }
//             false
//         } else {
//             true
//         }
//     }

//     fn find_unassigned_location(&self) -> Option<(usize, usize)> {
//         for row in 0..16 {
//             for col in 0..16 {
//                 if self.matrix[row][col] == FpVar::Constant(F::zero()) {
//                     return Some((row, col));
//                 }
//             }
//         }
//         None
//     }
// }

#[allow(non_snake_case)]
#[derive(Clone)]

pub struct Registerdatav3Circuit<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>>
where
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
{
    // constant
    pub rc: mimc7::Parameters<C::BaseField>,

    // statement
    pub H_k: Option<C::BaseField>,
    pub matrix_A: Option<Matrix<C::BaseField>>,

    // witnesses
    pub CT: Option<Vec<C::BaseField>>,
    pub data: Option<Vec<C::BaseField>>,
    pub data_key: Option<Vec<C::BaseField>>,
    pub matrix_R: Option<Matrix<C::BaseField>>,
    pub gamma: Option<Matrix<C::BaseField>>,
    pub sk_seller: Option<C::BaseField>,

    pub _curve_var: PhantomData<GG>,
}

#[allow(non_snake_case)]
impl<C, GG> ConstraintSynthesizer<C::BaseField> for Registerdatav3Circuit<C, GG>
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
        cs.set_optimization_goal(Weight);
        // constants
        let rc = hashes::mimc7::constraints::ParametersVar::new_constant(
            ark_relations::ns!(cs, "round constants"),
            self.rc,
        )?;

        // statement
        let h_k = FpVar::new_input(cs.clone(), || {
            self.H_k.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let matrix_A = MatrixVar::new_witness(ark_relations::ns!(cs, "matrix_A"), || {
            self.matrix_A.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // witness

        let CT: Vec<FpVar<<<C as CurveGroup>::Affine as AffineRepr>::BaseField>> =
            Vec::new_witness(ark_relations::ns!(cs, "CT"), || {
                self.CT.ok_or(SynthesisError::AssignmentMissing)
            })?;

        let data: Vec<FpVar<<<C as CurveGroup>::Affine as AffineRepr>::BaseField>> =
            Vec::new_witness(ark_relations::ns!(cs, "data"), || {
                self.data.ok_or(SynthesisError::AssignmentMissing)
            })?;

        let mut data_key: Vec<FpVar<<<C as CurveGroup>::Affine as AffineRepr>::BaseField>> =
            Vec::new_witness(ark_relations::ns!(cs, "data_key"), || {
                self.data_key.ok_or(SynthesisError::AssignmentMissing)
            })?;

        let matrix_R = MatrixVar::new_witness(ark_relations::ns!(cs, "matrix_R"), || {
            self.matrix_R.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let gamma: MatrixVar<<<C as CurveGroup>::Affine as AffineRepr>::BaseField> =
            MatrixVar::new_witness(ark_relations::ns!(cs, "gamma"), || {
                self.gamma.ok_or(SynthesisError::AssignmentMissing)
            })?;

        let sk_seller = FpVar::new_witness(cs.clone(), || {
            self.sk_seller.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // relation

        // check A * K = R

        let mut data_key_binary: Vec<Boolean<<C as CurveGroup>::BaseField>> = Vec::new();

        for i in 0..DATA_SET.Key_len {
            let binary_size = data_key[i].clone().to_bits_le()?.len();
            data_key_binary.append(&mut data_key[i].clone().to_bits_le()?);
            for _ in 0..(256 - binary_size) {
                data_key_binary.push(Boolean::<<C as CurveGroup>::BaseField>::FALSE);
            }
        }

        let mut matrix_k = Vec::new();

        let N = DATA_SET.N;
        let M = DATA_SET.M;
        let K = DATA_SET.K;

        for i in 0..M {
            let mut matrix_k_i = Vec::new();
            for j in 0..K {
                matrix_k_i.push(FpVar::<<C as CurveGroup>::BaseField>::from(
                    data_key_binary[i * K + j].clone(),
                ));
            }
            matrix_k.push(matrix_k_i);
        }

        let matrix_K = MatrixVar { matrix: matrix_k };

        let K_Gamma = matrix_K.mul(gamma.clone());
        let A_K_Gamma = matrix_A.mul(K_Gamma);
        let R_gamma = matrix_R.clone().mul(gamma);

        for i in 0..N {
            A_K_Gamma.matrix[i][0].enforce_equal(&R_gamma.matrix[i][0])?;
        }

        for i in 0..DATA_SET.Data_size {
            if i >= K {
                let check_CT = data[i].clone() + matrix_R.matrix[i / K][i % K].clone();
                check_CT.enforce_equal(&CT[i])?;
            } else {
                let check_CT = data[i].clone() + matrix_R.matrix[0][i].clone();
                check_CT.enforce_equal(&CT[i])?;
            }
        }

        // check h_k
        data_key.push(sk_seller.clone());
        let check_h_k = MiMCGadget::<C::BaseField>::evaluate(&rc, &data_key).unwrap();
        h_k.enforce_equal(&check_h_k)?;

        println!("Total Constraints num = {:?}", cs.num_constraints());

        Ok(())
    }
}

#[allow(non_snake_case)]
impl<C, GG> MockingCircuit<C, GG> for Registerdatav3Circuit<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    type F = C::BaseField;
    type HashParam = mimc7::Parameters<Self::F>;
    type H = mimc7::MiMC<Self::F>;
    type Output = Registerdatav3Circuit<C, GG>;

    fn generate_circuit<R: ark_std::rand::Rng>(
        round_constants: Self::HashParam,
        rng: &mut R,
    ) -> Result<Self::Output, Error> {
        use crate::gadget::hashes::CRHScheme;

        let rc: mimc7::Parameters<<<C as CurveGroup>::Affine as AffineRepr>::BaseField> =
            round_constants;

        // make data
        let data_size = DATA_SET.Data_size;
        let mut data = Vec::new();
        for _ in 0..data_size {
            data.push(C::BaseField::rand(rng));
        }

        let mut CT = Vec::new();

        let M = DATA_SET.M;
        let N = DATA_SET.N;
        let mut matrix_A = Vec::new();
        for _ in 0..N {
            let mut matrix_A_i = Vec::new();
            for _ in 0..M {
                matrix_A_i.push(C::BaseField::rand(rng));
            }
            matrix_A.push(matrix_A_i);
        }
        let matrix_A = Matrix::new(matrix_A);

        let K = DATA_SET.K;
        let mut basefield_key = Vec::new();
        for _ in 0..DATA_SET.Key_len {
            basefield_key.push(C::BaseField::rand(rng));
        }

        let mut key_bit = Vec::new();
        for i in 0..basefield_key.len() {
            key_bit.append(&mut basefield_key[i].clone().into_bigint().to_bits_le());
        }

        let mut matrix_K = Vec::new();
        for i in 0..M {
            let mut matrix_K_i = Vec::new();
            for j in 0..K {
                matrix_K_i.push(C::BaseField::from(key_bit[i * K + j]));
            }
            matrix_K.push(matrix_K_i);
        }
        let matrix_K = Matrix::new(matrix_K);
        let matrix_R = matrix_A.clone().mul(matrix_K.clone());

        // make h_k
        let sk_seller = Self::F::rand(rng);
        // let h_k = Self::H::evaluate(&rc.clone(), basefield_key.clone()).unwrap();
        let mut basefield_key_tmp = basefield_key.clone();
        basefield_key_tmp.push(sk_seller);
        let h_k = Self::H::evaluate(&rc.clone(), basefield_key_tmp).unwrap();

        // encrypt ct
        for i in 0..data_size {
            if i >= K {
                let CT_i = data[i] + matrix_R.matrix[i / K][i % K];
                CT.push(CT_i);
            } else {
                let CT_i = data[i] + matrix_R.matrix[0][i];
                CT.push(CT_i);
            }
        }

        println!("check = {:?}", CT[CT.len() - 1]);
        println!("CT length = {:?}", CT.len());

        let mut gamma_matrix = Vec::new();
        for _ in 0..K {
            gamma_matrix.push(vec![C::BaseField::rand(rng)]);
        }
        let gamma = Matrix::new(gamma_matrix);

        Ok(Registerdatav3Circuit {
            //constant
            rc: rc.clone(),
            // statement
            H_k: Some(h_k),
            matrix_A: Some(matrix_A),

            //witness
            data: Some(data),
            CT: Some(CT),
            data_key: Some(basefield_key),
            matrix_R: Some(matrix_R),
            gamma: Some(gamma),
            sk_seller: Some(sk_seller),

            _curve_var: std::marker::PhantomData,
        })
    }
}

// let mut matrix_R: Vec<Vec<FpVar<<<C as CurveGroup>::Affine as AffineRepr>::BaseField>>> =
//     Vec::new();
// for i in 0..self.matrix_R.unwrap().len() {
//     matrix_R.push(Vec::new_input(ark_relations::ns!(cs, "matrix_R"), || {
//         Some(self.matrix_R.unwrap()[i]).ok_or(SynthesisError::AssignmentMissing)
//     })?);
// }
