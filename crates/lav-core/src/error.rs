use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

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

    /// AEAD authentication failed. We cannot (and must not try to) tell a wrong
    /// password apart from a tampered or corrupted file.
    #[error("wrong password / key file, or the vault file is corrupted")]
    DecryptionFailed,

    #[error("encryption failed")]
    EncryptionFailed,

    #[error("key derivation failed")]
    KeyDerivation,

    #[error("vault content could not be (de)serialized: {0}")]
    Serialization(String),

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

    #[error("the vault file was changed on disk since it was opened")]
    FileChangedOnDisk,

    #[error(transparent)]
    Io(#[from] std::io::Error),
}
