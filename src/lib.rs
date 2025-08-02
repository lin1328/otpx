//! RFC 4226 & RFC 6238 compatible OTP (One-Time Password) implementation
//!
//! - **TOTP Support**: Implements RFC 6238 Time-based One-Time Password
//! - **Multiple Hash Algorithms**: Supports SHA1, SHA256, SHA512
//! - **Flexible Digits**: Support 5-8 digit verification codes
//! - **Byte Support**: ⚠️ User must ensure input correctness
//!
//! # Examples
//!
//! ```ignore
//! // Use cases: Single verification, simple and easy to use
//! use otpx::{Totp, Algorithm};
//!
//! // Base32 string (for most scenarios)
//! let totp = Totp::new("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP").unwrap();
//! println!("{}", totp.generate().unwrap());
//! println!("{}s", totp.ttl().unwrap());
//!
//! // Custom config
//! let custom_totp = Totp::new("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")
//!     .unwrap()
//!     .with_algorithm(Algorithm::Sha256)
//!     .with_digits(8)
//!     .with_time_step(60);
//! ```
//!
//! ## Steam Guard Support
//!
//! First enable the `steam` feature in `Cargo.toml`:
//!
//! ```ignore
//! use otpx::{Totp, Algorithm};
//!
//! // Steam Guard
//! let steam_totp = Totp::new("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")
//!     .unwrap()
//!     .with_algorithm(Algorithm::Steam);
//!
//! let code = steam_totp.generate_at(57856320);
//! println!("Steam : {}", code);
//! assert_eq!(code, "R6Q5N");
//! ```
//!

mod error;
pub use error::Error;

use core::fmt;
use data_encoding::BASE32_NOPAD_NOCASE;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use std::time::{SystemTime, UNIX_EPOCH};

/// Steam Guard specific character set
#[cfg(feature = "steam")]
const STEAM_CHARSET: &[u8; 26] = b"23456789BCDFGHJKMNPQRTVWXY";
const MIN_TIME_STEP: u64 = 15;
const DEFAULT_DIGITS: u8 = 6;
const DEFAULT_STEP: u64 = 30;

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

/// Hash algorithms supported by OTP
///
/// According to RFC 4226 and RFC 6238 standards, OTP can use different hash algorithms
///
/// RFC 4226 requires HMAC-SHA-1, RFC 6238 extends support for HMAC-SHA-256 and HMAC-SHA-512
///
/// Use SHA1 by default to ensure maximum compatibility
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Algorithm {
    /// HMAC-SHA-1 is the default algorithm for most OTP implementations
    #[default]
    Sha1,
    /// HMAC-SHA-256. Supported in theory according to [Datatracker](https://datatracker.ietf.org/doc/html/rfc6238#section-1.2)
    Sha256,
    /// HMAC-SHA-512
    Sha512,
    /// Steam Guard. HMAC-SHA1 variant (using SHA1 + custom character set)
    #[cfg(feature = "steam")]
    Steam,
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sha1 => write!(f, "SHA1"),
            Self::Sha256 => write!(f, "SHA256"),
            Self::Sha512 => write!(f, "SHA512"),
            #[cfg(feature = "steam")]
            Self::Steam => write!(f, "STEAM"),
        }
    }
}

impl From<&str> for Algorithm {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "sha256" => Self::Sha256,
            "sha512" => Self::Sha512,
            #[cfg(feature = "steam")]
            "steam" => Self::Steam,
            _ => Self::Sha1,
        }
    }
}

/// Shared secret container
///
/// Securely store keys with support for automatic memory zeroing (when `zeroize` feature is enabled)
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
pub struct SecretKey(Box<[u8]>);

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretKey")
            .field("len", &self.0.len())
            .finish_non_exhaustive()
    }
}

impl SecretKey {
    /// Decodes a Base32 encoded shared secret
    ///
    /// Use RFC 4648 standard Base32 encoding (case-insensitive, no padding)
    /// Decoded key length should be at least 80 bits (10 bytes)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The input contains invalid Base32 characters
    /// - The decoded key length is less than 80 bits (10 bytes)
    pub fn from_base32<S: AsRef<str>>(secret: S) -> Result<Self, Error> {
        let input = secret.as_ref();

        let decoded = BASE32_NOPAD_NOCASE
            .decode(input.as_bytes())
            .map_err(|_| Error::DecodeError)?;

        let decoded_len = decoded.len();

        if decoded_len < 10 {
            return Err(Error::KeyTooShort(decoded_len * 8));
        }

        #[cfg(debug_assertions)]
        if decoded_len < 16 {
            eprintln!(
                "Warning: Key length is {} bits, below the RFC 4226 recommended 128 bits. Consider using a longer key for improved security",
                decoded_len * 8
            );
        }

        Ok(Self(decoded.into_boxed_slice()))
    }

    /// Byte array key
    ///
    /// Suitable for decoded raw key data or external system integration
    /// No length validation is performed; the caller must ensure key security
    pub fn from_bytes<S: AsRef<[u8]>>(secret: S) -> Self {
        let secret_bytes = secret.as_ref();
        Self(secret_bytes.to_vec().into_boxed_slice())
    }

    /// Reference to the shared secret byte array
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the number of elements in the slice (In bytes)
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if the length of 0
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// RFC 6238: Time-Based One-Time Password implementation
/// TOTP = HOTP(K, T) where T = (Current Unix time - T0) / X
#[derive(Debug)]
pub struct Totp {
    /// Decoded shared secret
    secret: SecretKey,
    // RFC 6238: X represents the time step in seconds (default value X = 30 seconds)
    time_step: u64,
    // RFC 6238: T0 is the Unix time to start counting time steps (default value is 0) Usually can be omitted
    // t0: u64,
    /// The number of digits composing the auth code. [Datatracker](https://datatracker.ietf.org/doc/html/rfc4226#section-5.3)
    digits: u8,
    /// Hash algorithm
    algorithm: Algorithm,
    // Allows ±1 skew time window Clients usually don't need skew
    // skew: u8,
}

impl Default for Totp {
    fn default() -> Self {
        Self {
            secret: SecretKey::from_bytes(vec![]),
            time_step: DEFAULT_STEP,
            digits: DEFAULT_DIGITS,
            algorithm: Algorithm::default(),
        }
    }
}

impl Totp {
    /// Create TOTP instance with default config
    ///
    /// Default config: SHA1 algorithm, 6 digits, 30-second time step
    ///
    /// # Parameter
    ///
    /// * `secret` - Base32 encoded shared secret
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The input contains invalid Base32 characters
    /// - The decoded key length is less than 80 bits (10 bytes)
    pub fn new<S: AsRef<str>>(secret: S) -> Result<Self, Error> {
        let decoded_secret = SecretKey::from_base32(secret)?;

        Ok(Self {
            secret: decoded_secret,
            ..Default::default()
        })
    }

    /// Create TOTP instance directly from bytes
    ///
    /// # Parameter
    ///
    /// * `secret` - Decoded secret key byte array
    ///
    /// # Use cases
    ///
    /// - Keys imported from a verified external source
    /// - Allow keys in formats other than Base32 for compatibility
    ///
    /// # Examples
    ///
    /// ```
    /// use otpx::{Totp, Algorithm};
    ///
    /// // pre-verified 16-byte key
    /// let secret_bytes = b"Hello!\xde\xad\xbe\xefHello!\xde\xad\xbe\xef";
    /// let totp = Totp::new_from_bytes(secret_bytes);
    ///
    /// let code = totp.generate().unwrap();
    /// ```
    ///
    #[must_use]
    pub fn new_from_bytes<S: AsRef<[u8]>>(secret: S) -> Self {
        Self {
            secret: SecretKey::from_bytes(secret),
            ..Default::default()
        }
    }

    /// Configure hash algorithm
    #[must_use]
    pub const fn with_algorithm(mut self, algo: Algorithm) -> Self {
        self.algorithm = algo;
        self
    }

    /// Configure the number of verification code digits
    ///
    /// 1. **Storage stage**: Limits input digits to the 5-8 range
    /// 2. **Formatting stage**: `format_code()` further limits digits to the 6-8 range
    ///
    /// Therefore, when set to 5 digits, the final generated verification code will be 6 digits.
    ///
    /// **Special case**:
    /// - Steam algorithm ignores this setting and always generates 5-digit codes
    #[must_use]
    pub fn with_digits(mut self, digits: u8) -> Self {
        self.digits = digits.clamp(5, 8);
        self
    }

    /// Configure time step
    ///
    /// Time step is usually 30 seconds, values less than 15 will be automatically raised to 15
    #[must_use]
    pub const fn with_time_step(mut self, time_step: u64) -> Self {
        self.time_step = if time_step < MIN_TIME_STEP {
            MIN_TIME_STEP
        } else {
            time_step
        };
        self
    }

    /// Generate current verification code
    ///
    /// # Errors
    ///
    /// Returns an error when system time retrieval fails
    pub fn generate(&self) -> Result<String, Error> {
        let counter = self.current_counter()?;
        Ok(self.generate_at(counter))
    }

    /// Generate verification code using specified counter value
    ///
    /// # Parameters
    ///
    /// * `counter` - TOTP counter value, obtained through `time_counter_now` or custom
    #[must_use]
    pub fn generate_at(&self, counter: u64) -> String {
        let truncated = self.compute_hmac(counter);

        match self.algorithm {
            #[cfg(feature = "steam")]
            Algorithm::Steam => steam_encode(truncated),
            _ => format_code(truncated, self.digits),
        }
    }

    /// Get the remaining valid time (TTL) for the current verification code
    ///
    /// ```ignore
    /// let totp = Totp::new("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP").unwrap();
    /// let remaining = totp.ttl().unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error when system time retrieval fails.
    pub fn ttl(&self) -> Result<u64, Error> {
        let now = system_time()?;
        Ok(self.time_step - (now % self.time_step))
    }

    /// Generic `update -> finalize` -> `dynamic_truncation` workflow
    /// Uses `finalize()` to consume the MAC instance, suitable for one-time calculations
    #[inline]
    fn compute_with_mac<M>(mut mac: M, message: &[u8]) -> u32
    where
        M: Mac,
    {
        mac.update(message);
        let hmac = mac.finalize().into_bytes();
        let hmac_result = hmac.as_slice();

        let offset = (hmac_result[hmac_result.len() - 1] & 0xf).into();
        let bytes = &hmac[offset..offset + 4];
        u32::from_be_bytes([bytes[0] & 0x7f, bytes[1], bytes[2], bytes[3]])
    }

    /// RFC 6238: TOTP = HOTP(K, T) where T = (Current Unix time - T0) / X
    /// RFC 4226: HOTP(K,C) = Truncate(HMAC-SHA-1(K,C))
    fn compute_hmac(&self, counter: u64) -> u32 {
        // Standard implementation: Create a new MAC instance from the key each time
        // Concise, stateless, thread-safe, slightly higher overhead (almost negligible)
        match self.algorithm {
            Algorithm::Sha1 => Self::compute_with_mac(
                HmacSha1::new_from_slice(self.secret.as_bytes()).unwrap(),
                &counter.to_be_bytes(),
            ),
            #[cfg(feature = "steam")]
            Algorithm::Steam => Self::compute_with_mac(
                HmacSha1::new_from_slice(self.secret.as_bytes()).unwrap(),
                &counter.to_be_bytes(),
            ),

            Algorithm::Sha256 => Self::compute_with_mac(
                HmacSha256::new_from_slice(self.secret.as_bytes()).unwrap(),
                &counter.to_be_bytes(),
            ),

            Algorithm::Sha512 => Self::compute_with_mac(
                HmacSha512::new_from_slice(self.secret.as_bytes()).unwrap(),
                &counter.to_be_bytes(),
            ),
        }
    }

    /// Get the current time counter T value
    #[inline]
    fn current_counter(&self) -> Result<u64, Error> {
        let now = system_time()?;
        Ok(self.calc_counter(now))
    }

    /// RFC 6238: T = (Current Unix time - T0) / X
    ///
    /// Calculate the counter value corresponding to the timestamp
    #[must_use]
    #[inline]
    const fn calc_counter(&self, timestamp: u64) -> u64 {
        timestamp / self.time_step
    }
}

/// RFC 4226: Dynamic truncation
///
/// Extract 4-byte dynamic binary code from HMAC result
///
/// masking the most significant bit
///
/// Take the last 31 bits to ensure a positive integer result
///
/// In normal usage, HMAC output length is guaranteed by the algorithm (SHA1/SHA256/SHA512 are all ≥ 20 bytes)
///
#[must_use]
#[inline]
pub fn truncation_rfc4226(hmac: &[u8]) -> u32 {
    let offset = (hmac[hmac.len() - 1] & 0x0f) as usize;

    debug_assert!(
        offset + 4 <= hmac.len(),
        "Cannot safely extract 4-byte data from HMAC result: need positions {} to {}, but total length is only {}",
        offset,
        offset + 3,
        hmac.len()
    );

    let p = u32::from_be_bytes([
        hmac[offset],
        hmac[offset + 1],
        hmac[offset + 2],
        hmac[offset + 3],
    ]);

    p & 0x7FFF_FFFF
}

/// Standard formatting
///
/// Format a 32-bit integer into a decimal verification code with specified digits
///
/// **Digit limit**: Automatically limit digits to the 6-8 range
/// This is to comply with RFC 4226 standard, ensuring the verification code has sufficient security strength
///
/// # Parameters
///
/// * `value` - 32-bit integer obtained from HMAC truncation
/// * `digits` - Expected verification code digits, actual value used is processed by `digits.clamp(6, 8)`
#[must_use]
#[inline]
pub fn format_code(value: u32, digits: u8) -> String {
    let set_digits = digits.clamp(6, 8);

    // RFC 4226: Take modulo 10^Digit to generate decimal code
    let mut code = value % 10u32.pow(set_digits.into());

    let real = set_digits as usize;
    let mut result = String::with_capacity(real);

    let mut chars = [0u8; 8];
    for char_digit in chars.iter_mut().take(real) {
        *char_digit = (code % 10) as u8;
        code /= 10;
    }

    for i in (0..real).rev() {
        result.push((chars[i] + b'0') as char);
    }

    result
}

/// Steam Guard specific encoding
///
/// Format/convert a 32-bit integer to Steam Guard's special 26-character set 5-character format
///
/// # Parameters
///
/// * `value` - 32-bit integer obtained from HMAC truncation
#[cfg(feature = "steam")]
#[must_use]
#[inline]
pub fn steam_encode(mut value: u32) -> String {
    // let mut chars = [0u8; 5];
    // for i in 0..5 {
    //     let index = (value % 26) as usize;
    //     chars[i] = STEAM_CHARSET[index];
    //     value /= 26;
    // }
    // unsafe { String::from_utf8_unchecked(chars.to_vec()) }
    // Alternative implementation: Use safer methods to avoid unsafe operations

    let mut result = String::with_capacity(5);

    for _ in 0..5 {
        let index = (value % 26) as usize;
        result.push(STEAM_CHARSET[index] as char);
        value /= 26;
    }

    result
}

/// Get the current system time as Unix timestamp
///
/// # Errors
///
/// Returns an error when system time is earlier than Unix epoch (1970-01-01 00:00:00 UTC).
#[inline]
fn system_time() -> Result<u64, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(Error::SystemTime)
}

/// Get the counter value for the current system time
///
/// # Parameters
///
/// * `step` - Time step in seconds, minimum value is 15 seconds
///
/// # Errors
///
/// Returns an error when system time retrieval fails.
pub fn time_counter_now(step: u8) -> Result<u64, Error> {
    let effective_step = step.max(15);

    let now = system_time()?;
    Ok(now / u64::from(effective_step))
}
