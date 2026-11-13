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

pub use crypto::KdfParams;
pub use error::{Error, Result};
pub use generator::{generate as generate_password, PasswordOptions};
pub use model::{Attachment, CustomField, Entry, EntryIcon, EntryVersion, Group, VaultData};
pub use secret::{SecretBytes, SecretString};
pub use vault::Vault;
