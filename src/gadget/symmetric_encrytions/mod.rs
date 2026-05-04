use ark_crypto_primitives::Error;

pub mod symmetric;

pub mod constraints;

pub trait SymmetricEncryption {
    type Parameters;

    type Randomness;
    type SymmetricKey;
    type Ciphertext;
    type Plaintext;

    fn keygen(params: Self::Parameters) -> Result<Self::SymmetricKey, Error>;

    fn encrypt(
        params: Self::Parameters,
        r: Self::Randomness,
        k: Self::SymmetricKey,
        m: Self::Plaintext,
    ) -> Result<Self::Ciphertext, Error>;

    fn decrypt(
        params: Self::Parameters,
        k: Self::SymmetricKey,
        ct: Self::Ciphertext,
    ) -> Result<Self::Plaintext, Error>;
}
