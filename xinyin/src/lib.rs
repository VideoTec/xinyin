mod xinyin;

#[cfg(feature = "generate")]
pub use xinyin::generate::generate_words32;

#[cfg(feature = "import")]
pub use xinyin::import::import_words32;

#[cfg(feature = "sks")]
pub mod sks;
#[cfg(feature = "sks")]
pub use sks::{EncryptedSk, SksStore};
