use ark_crypto_primitives::Error;
use ark_ff::Field;
use ark_r1cs_std::prelude::AllocVar;

use super::SymmetricEncryption;

pub trait SymmetricEncryptionGadget<Enc: SymmetricEncryption, F: Field> {
    type ParametersVar;

    type RandomnessVar: AllocVar<Enc::Randomness, F> + Clone;
    type SymmetricKeyVar: AllocVar<Enc::SymmetricKey, F> + Clone;
    type CiphertextVar: AllocVar<Enc::Ciphertext, F> + Clone;
    type PlaintextVar: AllocVar<Enc::Plaintext, F> + Clone;

    fn encrypt(
        params: Self::ParametersVar,
        r: Self::RandomnessVar,
        k: Self::SymmetricKeyVar,
        m: Self::PlaintextVar,
    ) -> Result<Self::CiphertextVar, Error>;

    fn decrypt(
        params: Self::ParametersVar,
        k: Self::SymmetricKeyVar,
        ct: Self::CiphertextVar,
    ) -> Result<Self::PlaintextVar, Error>;
}
