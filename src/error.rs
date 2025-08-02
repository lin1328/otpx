use core::fmt;
use std::time::SystemTimeError;

/// Error type
#[derive(Debug)]
pub enum Error {
    /// System time is set to before the Unix epoch
    SystemTime(SystemTimeError),
    /// Invalid secret key format or decoding failed
    DecodeError,
    /// Secret key is too short for secure TOTP generation
    KeyTooShort(usize),
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SystemTime(e) => Some(e),
            Self::DecodeError | Self::KeyTooShort(_) => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SystemTime(e) => write!(
                f,
                "System time error: {e}. The system time is set before the Unix epoch (1970-01-01 00:00:00 UTC)"
            ),
            Self::DecodeError => write!(f, "Invalid secret key format or Base32 decoding failed"),
            Self::KeyTooShort(actual_bits) => write!(
                f,
                "Secret key too short: {actual_bits} bits. Minimum required: 80 bits (10 bytes) for secure TOTP generation"
            ),
        }
    }
}

impl From<SystemTimeError> for Error {
    fn from(e: SystemTimeError) -> Self {
        Self::SystemTime(e)
    }
}
