use std::borrow::Cow;

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

/// The ONE message shown to the user for every unlock failure caused by the
/// credentials or by the file's content (THREAT_MODEL principle 3). It must not
/// tell a wrong password apart from a damaged or crafted file.
pub const UNLOCK_FAILED_MESSAGE: &str =
    "The vault could not be opened: the password or key file is wrong, or the file is damaged or not supported.";

#[derive(Debug, Error)]
pub enum Error {
    #[error("not a LockAlperen vault file")]
    NotAVault,

    #[error("vault file is truncated or malformed")]
    Malformed,

    #[error("unsupported vault format version {0}")]
    UnsupportedVersion(u16),

    #[error("unsupported vault content schema {0}")]
    UnsupportedSchema(u32),

    #[error("unsupported algorithm id {0}")]
    UnsupportedAlgorithm(u8),

    #[error("unknown header flags {0:#06x}")]
    UnknownFlags(u16),

    #[error("key derivation parameters are out of the allowed range")]
    InvalidKdfParams,

    #[error("this vault requires a key file")]
    KeyFileRequired,

    /// A key file was supplied but the header says the vault does not use one.
    /// Rejected instead of silently mixing it into the key.
    #[error("this vault does not use a key file")]
    UnexpectedKeyFile,

    /// AEAD authentication failed. We cannot (and must not try to) tell a wrong
    /// password apart from a tampered or corrupted file.
    #[error("wrong password / key file, or the vault file is corrupted")]
    DecryptionFailed,

    #[error("encryption failed")]
    EncryptionFailed,

    #[error("key derivation failed")]
    KeyDerivation,

    /// Only produced while OPENING a vault (decoding the decrypted payload).
    #[error("vault content could not be (de)serialized: {0}")]
    Serialization(String),

    /// Encoding the vault for saving failed. Not an unlock failure.
    #[error("the vault could not be encoded for saving")]
    Encode,

    #[error("the master password must be at least {0} characters (or use a key file)")]
    WeakPassword(usize),

    #[error("the key file is empty")]
    EmptyKeyFile,

    #[error("the current password / key file is not correct")]
    WrongCurrentCredentials,

    #[error("file is larger than the allowed {0} bytes")]
    FileTooLarge(u64),

    #[error("invalid password generator options: {0}")]
    InvalidGeneratorOptions(&'static str),

    #[error("item not found")]
    NotFound,

    #[error("the root group cannot be deleted")]
    CannotDeleteRoot,

    #[error("the root group cannot be moved")]
    CannotMoveRoot,

    /// Moving a group into itself or one of its own subgroups would cut that
    /// subtree off the root (a cycle).
    #[error("a group cannot be moved into itself or its subgroups")]
    InvalidMove,

    #[error("the vault file was changed on disk since it was opened")]
    FileChangedOnDisk,

    /// Another instance is saving this vault and did not finish in time.
    #[error("another instance is saving this vault; try again")]
    SaveBusy,

    /// The save lock file was removed or replaced while we held it, so
    /// another writer may be active. The save was aborted before the vault
    /// file was replaced.
    #[error("the save lock was lost; the save was aborted")]
    LockLost,

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl Error {
    /// True for every error that depends on the credentials or on the file's
    /// content. These must all look the same to the user; the variants exist
    /// only for tests and diagnostics.
    ///
    /// Note: `InvalidKdfParams` and `KeyDerivation` can also come from
    /// `Vault::create` / `change_credentials` when the APP passes parameters
    /// outside [`crate::KdfParams::validate`]. That is a caller bug: settings
    /// UIs must validate first, and must not show `user_message()` for it.
    pub fn is_unlock_failure(&self) -> bool {
        matches!(
            self,
            Error::NotAVault
                | Error::Malformed
                | Error::UnsupportedVersion(_)
                | Error::UnsupportedSchema(_)
                | Error::UnsupportedAlgorithm(_)
                | Error::UnknownFlags(_)
                | Error::InvalidKdfParams
                | Error::KeyFileRequired
                | Error::UnexpectedKeyFile
                | Error::DecryptionFailed
                | Error::KeyDerivation
                | Error::Serialization(_)
        )
    }

    /// Text to show the user. Unlock failures all collapse into
    /// [`UNLOCK_FAILED_MESSAGE`]; anything else uses its own message.
    pub fn user_message(&self) -> Cow<'static, str> {
        if self.is_unlock_failure() {
            Cow::Borrowed(UNLOCK_FAILED_MESSAGE)
        } else {
            Cow::Owned(self.to_string())
        }
    }
}
