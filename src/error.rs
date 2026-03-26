use core::{fmt, error};
use alloc::string::String;
#[cfg(feature = "std")]
use std::time::SystemTimeError;

/// Error type
#[non_exhaustive]
#[derive(Debug)]
pub enum Error {
    /// System time is set to before the Unix epoch
    #[cfg(feature = "std")]
    SystemTime(SystemTimeError),
    /// Empty secret key provided
    EmptySecret,
    /// Invalid secret key format or decoding failed
    DecodeError,
    /// Secret key is too short for secure TOTP generation
    KeyTooShort(usize),
    /// Unknown algorithm name
    AlgorithmError(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "std")]
            Self::SystemTime(e) => write!(
                f,
                "System time error: {e}. The system time is set before the Unix epoch (1970-01-01 00:00:00 UTC)"
            ),
            Self::EmptySecret => write!(f, "Secret key cannot be empty"),
            Self::DecodeError => write!(f, "Invalid secret key format or Base32 decoding failed"),
            Self::KeyTooShort(actual_bits) => write!(
                f,
                "Secret key too short: {actual_bits} bits. Minimum required: 80 bits (10 bytes) for secure TOTP generation"
            ),
            Self::AlgorithmError(s) => write!(
                f,
                "unknown algorithm: '{s}' (expected: SHA1, SHA256, SHA512{})",
                if cfg!(feature = "steam") { ", STEAM" } else { "" }
            ),
        }
    }
}

impl error::Error for Error {
    #[cfg(feature = "std")]
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::SystemTime(e) => Some(e),
            _ => None,
        }
    }
}

#[cfg(feature = "std")]
impl From<SystemTimeError> for Error {
    fn from(e: SystemTimeError) -> Self {
        Self::SystemTime(e)
    }
}
