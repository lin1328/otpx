use core::fmt;
#[cfg(feature = "std")]
use std::time::SystemTimeError;

/// Errors type
#[non_exhaustive]
#[derive(Debug)]
pub enum Error {
    /// System time is set to before the Unix epoch
    #[cfg(feature = "std")]
    SystemTime(SystemTimeError),

    /// A required field was empty
    EmptyField(&'static str),
    /// Invalid Base32 character or structure; carries the byte offset of the first error
    DecodeError(usize),

    /// Secret key is too short for secure TOTP generation
    KeyTooShort(usize),

    /// OTP digit count is outside the valid range (`6..=8`)
    InvalidDigits(u8),
    /// Time step is below the minimum (15 seconds)
    InvalidTimeStep(u8),
    /// Unknown algorithm name
    InvalidAlgorithm,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "std")]
            Self::SystemTime(e) => write!(f, "System time error: {e}"),
            Self::EmptyField(field) => write!(f, "'{field}' cannot be empty"),
            Self::DecodeError(pos) => write!(f, "Base32 decode failed at position {pos}"),
            Self::KeyTooShort(bits) => write!(
                f,
                "Secret key too short: {bits} bits (minimum 80 bits / 10 bytes)"
            ),
            Self::InvalidDigits(digits) => {
                write!(f, "invalid OTP digits: {digits} (expected 6..=8)")
            }
            Self::InvalidTimeStep(step) => {
                write!(f, "invalid time step: {step}s (minimum is 15s)")
            }
            Self::InvalidAlgorithm => write!(f, "Invalid or unsupported algorithm"),
        }
    }
}

impl core::error::Error for Error {}

pub type Result<T, E = Error> = core::result::Result<T, E>;
