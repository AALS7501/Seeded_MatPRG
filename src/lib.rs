pub type Error = Box<dyn ark_std::error::Error>;

pub mod gadget;
pub mod original_MatPRG;
pub mod seeded_MatPRG;

#[cfg(feature = "registerdata")]
#[path = "original_MatPRG/registerdatav1/mod.rs"]
pub mod registerdatav1;
#[cfg(feature = "registerdatav2")]
#[path = "original_MatPRG/registerdatav2/mod.rs"]
pub mod registerdatav2;
#[cfg(feature = "registerdatav3")]
#[path = "original_MatPRG/registerdatav3/mod.rs"]
pub mod registerdatav3;

#[cfg(feature = "MatPRG")]
#[path = "original_MatPRG/MatPRG/mod.rs"]
pub mod MatPRG;
#[cfg(feature = "MatPRGEnc")]
#[path = "original_MatPRG/MatPRGEnc/mod.rs"]
pub mod MatPRGEnc;

#[cfg(feature = "mimc")]
#[path = "original_MatPRG/mimc/mod.rs"]
pub mod mimc;

// circuits
#[cfg(feature = "accepttrade")]
#[path = "original_MatPRG/accepttrade/mod.rs"]
pub mod accepttrade;
#[cfg(feature = "gentrade")]
#[path = "original_MatPRG/gentrade/mod.rs"]
pub mod gentrade;
#[cfg(feature = "accepttrade_v2")]
#[path = "seeded_MatPRG/accepttrade_v2/mod.rs"]
pub mod accepttrade_v2;
#[cfg(feature = "gentrade_v2")]
#[path = "seeded_MatPRG/gentrade_v2/mod.rs"]
pub mod gentrade_v2;

// SNARK
#[cfg(feature = "CP-SNARK")]
pub mod cp_snark;

#[cfg(feature = "register_MatPRG")]
#[path = "original_MatPRG/register_MatPRG/mod.rs"]
pub mod register_MatPRG;

#[cfg(feature = "register_seeded_matprg")]
#[path = "seeded_MatPRG/register_seeded_matprg/mod.rs"]
pub mod register_seeded_matprg;

#[cfg(feature = "register_MiMC_CTR")]
#[path = "original_MatPRG/register_MiMC_CTR/mod.rs"]
pub mod register_MiMC_CTR;

#[cfg(feature = "register_Poseidon_CTR")]
#[path = "original_MatPRG/register_Poseidon_CTR/mod.rs"]
pub mod register_Poseidon_CTR;
