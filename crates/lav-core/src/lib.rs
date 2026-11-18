//! LockAlperen core: the `.lav` vault format, its cryptography and the vault data model.
//!
//! ```no_run
//! use lav_core::{Entry, KdfParams, Vault};
//!
//! let mut vault = Vault::create("Personal", "correct horse", None, KdfParams::default())?;
//! let mut e = Entry::new(vault.data.root, "GitHub");
//! e.username = "me".into();
//! vault.data.add_entry(e)?;
//! vault.save_file("personal.lav".as_ref())?;
//! # Ok::<(), lav_core::Error>(())
//! ```

#![forbid(unsafe_code)]

pub mod crypto;
pub mod error;
pub mod format;
pub mod generator;
pub mod model;
pub mod secret;
pub mod vault;

/// Raw cryptographic helpers for this crate's own tests only (feature
/// `test-utils`, enabled through the self dev-dependency). Never enabled in
/// normal builds: they bypass the key-commitment check on purpose, to build
/// and inspect crafted files.
#[cfg(feature = "test-utils")]
#[doc(hidden)]
pub mod testing {
    use zeroize::Zeroizing;

    use crate::crypto::{self, DerivedKeys, KEY_LEN, NONCE_LEN};
    use crate::error::Result;

    pub fn payload_key(keys: &DerivedKeys) -> [u8; KEY_LEN] {
        *keys.payload_key()
    }

    pub fn encrypt(
        key: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        crypto::encrypt(key, nonce, aad, plaintext)
    }

    pub fn decrypt(
        key: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        crypto::decrypt_raw(key, nonce, aad, ciphertext)
    }

    pub fn nfc_password(s: &str) -> String {
        crypto::nfc_password(s).as_str().to_owned()
    }
}

pub use crypto::KdfParams;
pub use error::{Error, Result};
pub use generator::{generate as generate_password, PasswordOptions};
pub use generator::{generate_pattern, pattern_entropy_bits, PATTERN_HELP};
pub use model::{
    Attachment, AutoTypeConfig, CustomField, Entry, EntryIcon, EntryVersion, Group, MergeReport,
    Removal, Tombstone, VaultData, HISTORY_LIMIT_MAX,
};
pub use secret::{SecretBytes, SecretString};
pub use vault::Vault;
