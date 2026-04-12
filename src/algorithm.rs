use core::{fmt, str::FromStr};

use crate::Error;

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
#[cfg_attr(feature = "serde", serde(rename_all = "UPPERCASE"))]
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
}

impl fmt::Display for Algorithm {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Case-insensitive comparison, ignoring `-` and `_` in the input.
fn eq_normalized(input: &str, expected: &str) -> bool {
    let input_iter = input
        .bytes()
        .filter(|&b| !matches!(b, b'-' | b'_'))
        .map(|b| b.to_ascii_lowercase());

    let expected_iter = expected.bytes();

    input_iter.eq(expected_iter)
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
        macro_rules! matches_algo {
            ($expected:literal => $variant:expr) => {
                if eq_normalized(s, $expected) {
                    return Ok($variant);
                }
            };
        }

        matches_algo!("sha1"   => Self::Sha1);
        matches_algo!("sha256" => Self::Sha256);
        matches_algo!("sha512" => Self::Sha512);
        #[cfg(feature = "steam")]
        matches_algo!("steam"  => Self::Steam);

        Err(Error::InvalidAlgorithm)
    }
}

impl From<Algorithm> for &'static str {
    /// Delegates to [`Algorithm::as_str`].
    #[inline]
    fn from(algo: Algorithm) -> Self {
        algo.as_str()
    }
}
