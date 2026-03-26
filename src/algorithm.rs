use alloc::boxed::Box;
use core::{fmt, str::FromStr};

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use crate::error::Error;

/// HMAC algorithm used for OTP code generation.
///
/// RFC 4226 mandates HMAC-SHA-1; RFC 6238 §1.2 extends support to
/// HMAC-SHA-256 and HMAC-SHA-512. `SHA1` is the default to maximise
/// compatibility with existing authenticator apps.
///
/// The `Steam` variant is a SHA-1-based variant that uses a custom
/// character set instead of decimal digits, and is only available when
/// the `steam` feature is enabled.
///
/// # Parsing
///
/// `Algorithm` implements [`FromStr`](core::str::FromStr) for case-insensitive
/// string parsing and [`Display`](core::fmt::Display) for the canonical
/// uppercase representation. See [`FromStr`] for accepted values.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub enum Algorithm {
    /// HMAC-SHA-1 (RFC 4226 §5). Default algorithm.
    #[default]
    Sha1,
    /// HMAC-SHA-256 (RFC 6238 §1.2).
    Sha256,
    /// HMAC-SHA-512 (RFC 6238 §1.2).
    Sha512,
    /// Steam Guard variant: HMAC-SHA-1 with a custom 26-character encoding.
    #[cfg(feature = "steam")]
    Steam,
}

impl Algorithm {
    /// Returns the uppercase string of the corresponding algorithm.
    ///
    /// # Examples
    ///
    /// ```
    /// use otpx::Algorithm;
    ///
    /// assert_eq!(Algorithm::Sha1.as_str(), "SHA1");
    /// assert_eq!(Algorithm::Sha256.as_str(), "SHA256");
    /// ```
    #[must_use]
    #[inline]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
            #[cfg(feature = "steam")]
            Self::Steam => "STEAM",
        }
    }

    /// Computes HMAC using this algorithm's hash function.
    ///
    /// Returns the raw digest bytes as a heap-allocated slice.
    pub(crate) fn compute_hmac(self, key: &[u8], message: &[u8]) -> Box<[u8]> {
        fn run<H>(mut mac: H, message: &[u8]) -> Box<[u8]>
        where
            H: Mac,
        {
            mac.update(message);
            mac.finalize().into_bytes().to_vec().into_boxed_slice()
        }
        match self {
            Self::Sha1 => run(Hmac::<Sha1>::new_from_slice(key).unwrap(), message),
            #[cfg(feature = "steam")]
            Self::Steam => run(Hmac::<Sha1>::new_from_slice(key).unwrap(), message),
            Self::Sha256 => run(Hmac::<Sha256>::new_from_slice(key).unwrap(), message),
            Self::Sha512 => run(Hmac::<Sha512>::new_from_slice(key).unwrap(), message),
        }
    }
}

impl fmt::Display for Algorithm {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Algorithm {
    type Err = Error;

    /// Parses an algorithm from a string.
    ///
    /// Accepted values (case-insensitive):
    ///
    /// - `"SHA1"` / `"sha1"`
    /// - `"SHA256"` / `"sha256"`
    /// - `"SHA512"` / `"sha512"`
    /// - `"STEAM"` / `"steam"` (when the `steam` feature is enabled)
    ///
    /// # Examples
    ///
    /// ```
    /// use core::str::FromStr;
    /// use otpx::Algorithm;
    ///
    /// assert_eq!(Algorithm::from_str("SHA1").unwrap(), Algorithm::Sha1);
    /// assert_eq!(Algorithm::from_str("sha256").unwrap(), Algorithm::Sha256);
    /// assert_eq!("sha512".parse::<Algorithm>().unwrap(), Algorithm::Sha512);
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        macro_rules! match_ignore_ascii_case {
            ($s:expr, $pat:literal => $variant:expr) => {
                if $s.eq_ignore_ascii_case($pat) {
                    return Ok($variant);
                }
            };
        }

        match_ignore_ascii_case!(s, "SHA1" => Self::Sha1);
        match_ignore_ascii_case!(s, "SHA256" => Self::Sha256);
        match_ignore_ascii_case!(s, "SHA512" => Self::Sha512);
        #[cfg(feature = "steam")]
        match_ignore_ascii_case!(s, "STEAM" => Self::Steam);

        Err(Error::AlgorithmError(s.into()))
    }
}

impl From<Algorithm> for &'static str {
    /// Delegates to [`Algorithm::as_str`].
    #[inline]
    fn from(algo: Algorithm) -> Self {
        algo.as_str()
    }
}
