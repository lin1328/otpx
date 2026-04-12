use alloc::string::String;
#[cfg(feature = "std")]
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use crate::{Algorithm, Error, Result};

/// Computes HMAC using the specified algorithm's hash function.
///
/// Writes the digest into `buf` and returns the subslice containing the result.
///
/// # Parameters
///
/// * `algorithm` - The HMAC algorithm to use.
/// * `key` - The secret key.
/// * `message` - The message to authenticate.
/// * `buf` - Output buffer (must be at least 20/32/64 bytes for SHA-1/256/512).
///
/// # Panics
///
/// Panics if `buf` is smaller than the digest length (20, 32, or 64 bytes).
#[inline]
pub(crate) fn compute_hmac<'a>(
    algorithm: Algorithm,
    key: &[u8],
    message: &[u8],
    buf: &'a mut [u8],
) -> &'a [u8] {
    macro_rules! hmac {
        ($H:ty) => {{
            let mut mac = Hmac::<$H>::new_from_slice(key).expect("HMAC accepts keys of any size");
            mac.update(message);
            let result = mac.finalize().into_bytes();
            let len = result.len();
            buf[..len].copy_from_slice(&result);
            &buf[..len]
        }};
    }

    match algorithm {
        Algorithm::Sha1 => hmac!(Sha1),
        #[cfg(feature = "steam")]
        Algorithm::Steam => hmac!(Sha1),
        Algorithm::Sha256 => hmac!(Sha256),
        Algorithm::Sha512 => hmac!(Sha512),
    }
}

/// RFC 4226 §5.3 dynamic truncation.
///
/// Uses the low 4 bits of the last HMAC byte as an offset, reads 4 bytes
/// at that offset, then masks the most significant bit to produce a
/// 31-bit unsigned integer.
///
/// # Panics
///
/// Panics if `hmac` is empty or if `offset + 4 > hmac.len()`.
/// Callers must pass a valid HMAC output (≥ 20 bytes for SHA-1,
/// ≥ 32 for SHA-256, ≥ 64 for SHA-512); the offset derived from
/// the last byte is at most 15, so any output of at least 20 bytes
/// satisfies the bound.
#[must_use]
#[inline]
pub(crate) fn truncate_rfc4226(hmac: &[u8]) -> u32 {
    let offset = (*hmac.last().unwrap() & 0xf) as usize;
    let bytes: [u8; 4] = hmac[offset..offset + 4].try_into().unwrap();
    u32::from_be_bytes(bytes) & 0x7fff_ffff
}

/// Formats a truncated 31-bit value as a zero-padded decimal OTP string.
///
/// # Parameters
///
/// * `value` - 31-bit integer from [`truncate_rfc4226`].
/// * `digits` - Output length. Must be in `6..=8`; see panics below.
///
/// # Panics
///
/// Panics if `digits > 8`: index out of bounds on the internal `[u8; 8]` buffer.
/// Values of `digits < 6` produce silently truncated output that does not
/// conform to RFC 4226; the caller is responsible for passing a valid value.
#[must_use]
#[inline]
pub(crate) fn format_otp(value: u32, digits: u8) -> String {
    let mut buf = [0u8; 8];
    let mut v = value;
    let n = digits as usize;
    for i in (0..n).rev() {
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    // SAFETY: buf[..n] contains only ASCII digits (b'0'..=b'9')
    String::from(unsafe { core::str::from_utf8_unchecked(&buf[..n]) })
}

/// Encodes a truncated 31-bit value as a 5-character Steam Guard code.
///
/// Repeatedly takes `value % 26` as an index into [`STEAM_CHARSET`] to
/// produce each character, then divides by 26, for 5 iterations.
///
/// # Parameters
///
/// * `value` - 31-bit integer from [`truncate_rfc4226`].
#[cfg(feature = "steam")]
#[must_use]
#[inline]
pub(crate) fn steam_encode(value: u32) -> String {
    use crate::{STEAM_CHARSET, STEAM_RADIX};

    let mut buf = [0u8; 5];
    let mut v = value;
    for b in &mut buf {
        *b = STEAM_CHARSET[(v % STEAM_RADIX) as usize];
        v /= STEAM_RADIX;
    }
    // SAFETY: STEAM_CHARSET contains only ASCII characters
    String::from(unsafe { core::str::from_utf8_unchecked(&buf) })
}

/// Validates that the shared secret meets the minimum length for compatibility.
///
/// Requires at least **80 bits (10 bytes)**. RFC 4226 §4 R6 recommends 128 bits (16 bytes),
/// but 10 bytes is the practical minimum for broad TOTP/HOTP interoperability.
///
/// # Errors
///
/// - [`Error::EmptyField`] if `len == 0`.
/// - [`Error::KeyTooShort`] if `0 < len < 10`; carries the actual bit count.
#[inline]
pub(crate) fn check_secret_len(len: usize) -> Result<()> {
    if len == 0 {
        return Err(Error::EmptyField("secret"));
    }
    if len < 10 {
        return Err(Error::KeyTooShort(len * 8));
    }
    Ok(())
}

/// Validates that the time step meets the RFC 6238 §4 minimum.
///
/// Values below 15 seconds are rejected as they provide insufficient
/// security margin for time-based OTP.
///
/// # Errors
///
/// Returns [`Error::InvalidTimeStep`] if `period < 15`.
#[inline]
pub(crate) fn check_period(period: u8) -> Result<()> {
    if period < crate::MIN_TIME_STEP {
        return Err(Error::InvalidTimeStep(period));
    }
    Ok(())
}

/// Validates that the OTP digit count conforms to RFC 4226 §4 R4.
///
/// RFC 4226 §4 R4 requires at least 6 digits. This implementation caps the
/// maximum at 8 to stay within the 31-bit truncation value range.
///
/// # Errors
///
/// Returns [`Error::InvalidDigits`] if `digits` is not in `6..=8`.
#[inline]
pub(crate) fn check_digits(digits: u8) -> Result<()> {
    if !(6..=8).contains(&digits) {
        return Err(Error::InvalidDigits(digits));
    }
    Ok(())
}

/// Get the current system time as Unix timestamp (seconds)
#[cfg(feature = "std")]
#[inline]
pub(crate) fn system_time() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(Error::SystemTime)
}
