use alloc::string::String;
#[cfg(feature = "std")]
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error;

/// RFC 4226 §5.3 dynamic truncation.
///
/// Uses the low 4 bits of the last HMAC byte as an offset, reads 4 bytes
/// at that offset, then masks the most significant bit to produce a
/// 31-bit unsigned integer.
#[must_use]
#[inline]
pub(crate) fn truncate_rfc4226(hmac: &[u8]) -> u32 {
    let offset: usize = (hmac[hmac.len() - 1] & 0xf).into();
    let bytes = &hmac[offset..offset + 4];
    u32::from_be_bytes([bytes[0] & 0x7f, bytes[1], bytes[2], bytes[3]])
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
/// `digits >= 10` additionally causes `10u32.pow(digits)` to overflow `u32`.
/// Values of `digits < 6` produce silently truncated output that does not
/// conform to RFC 4226; the caller is responsible for passing a valid value.
#[must_use]
#[inline]
pub(crate) fn format_otp(value: u32, digits: u8) -> String {
    let mut code = value % 10u32.pow(digits.into());
    let real = digits as usize;
    let mut otp = String::with_capacity(real);
    let mut chars = [0u8; 8];
    for char_digit in chars.iter_mut().take(real) {
        *char_digit = (code % 10) as u8;
        code /= 10;
    }
    for i in (0..real).rev() {
        otp.push((chars[i] + b'0') as char);
    }
    otp
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
pub(crate) fn steam_encode(mut value: u32) -> String {
    use crate::STEAM_CHARSET;

    let mut code = String::with_capacity(5);
    for _ in 0..5 {
        // index ∈ [0, 25], always in bounds
        let index = (value % 26) as usize;
        code.push(STEAM_CHARSET[index] as char);
        value /= 26;
    }
    code
}

/// Get the current system time as Unix timestamp (seconds)
#[cfg(feature = "std")]
#[inline]
pub(crate) fn system_time() -> Result<u64, error::Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(error::Error::SystemTime)
}
