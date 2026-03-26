use alloc::{boxed::Box, string::String};
use core::{fmt, ops};

use crate::Algorithm;
use crate::error::Error;
#[cfg(feature = "steam")]
use crate::util::steam_encode;
#[cfg(feature = "std")]
use crate::util::system_time;
use crate::util::{format_otp, truncate_rfc4226};
use crate::{DEFAULT_DIGITS, DEFAULT_STEP, MIN_TIME_STEP};

/// Internal wrapper that holds the raw bytes of a TOTP secret key.
///
/// When the `zeroize` feature is enabled, the bytes are stored inside
/// [`zeroize::Zeroizing`], which zeroes the memory on drop to prevent
/// secret material from lingering in the heap.
/// Without the feature, a plain [`Box<[u8]>`] is used.
///
/// The `Debug` implementation intentionally redacts the contents to
/// avoid leaking key material into logs or error messages.
#[cfg(not(feature = "zeroize"))]
struct ByteSecret(Box<[u8]>);
#[cfg(feature = "zeroize")]
struct ByteSecret(zeroize::Zeroizing<Box<[u8]>>);

impl fmt::Debug for ByteSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ByteSecret").finish_non_exhaustive()
    }
}

impl ops::Deref for ByteSecret {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Box<[u8]>> for ByteSecret {
    /// Converts a boxed byte slice into a `ByteSecret`.
    fn from(bytes: Box<[u8]>) -> Self {
        #[cfg(not(feature = "zeroize"))]
        {
            Self(bytes)
        }
        #[cfg(feature = "zeroize")]
        {
            Self(bytes.into())
        }
    }
}

/// RFC 6238: Time-Based One-Time Password (TOTP) implementation.
///
/// TOTP extends HOTP by deriving the counter from the current time:
/// `T = floor((Unix time − T0) / X)`, where T0 is the Unix epoch and
/// X is the time step (default 30 s).
///
/// # Construction
///
/// Pass the decoded secret key bytes directly to [`Totp::new`].
/// Base32 decoding is the caller's responsibility; use [`SecretKey::from_base32`]
/// for the common case:
///
/// ```
/// use otpx::{Totp, SecretKey};
///
/// let key = SecretKey::from_base32("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP").unwrap();
/// let totp = Totp::new(key.as_bytes());
/// ```
///
/// # Configuration
///
/// Builder methods allow customising the algorithm, digit count, and time step:
///
/// ```
/// use otpx::{Totp, Algorithm};
///
/// let totp = Totp::new(b"12345678901234567890")
///     .with_algorithm(Algorithm::Sha256)
///     .with_digits(8)
///     .with_time_step(60);
/// ```
///
/// # Code generation
///
/// Two generation methods are provided:
///
/// - [`generate`](Self::generate) — reads the system clock internally.
///   Requires the `std` feature (enabled by default).
/// - [`generate_at`](Self::generate_at) — accepts a pre-computed time counter
///   `T = floor(Unix time / time_step)`. Always available, including `no_std`.
///
/// # Key requirements
///
/// [`Totp::new`] accepts any byte slice without length validation.
///
/// RFC 4226 §4 requires at least 80 bits (10 bytes); 128 bits (16 bytes)
/// or more is recommended.
#[derive(Debug)]
pub struct Totp {
    /// Shared secret key (RFC 4226 §4 / RFC 6238 §4).
    secret: ByteSecret,
    /// Number of OTP digits (6–8). Default: 6.
    digits: u8,
    /// HMAC algorithm used for code generation. Default: SHA-1.
    algorithm: Algorithm,
    /// Time step in seconds. Minimum: 15. Default: 30.
    time_step: u8,
    // Allowable time window offset
    // skew: u8,
}

impl Totp {
    /// Creates a `Totp` instance from decoded secret key bytes.
    ///
    /// The default configuration uses SHA-1, 6 digits, and a 30-second time step,
    /// which is compatible with most authenticator apps (RFC 6238).
    ///
    /// No key length validation is performed.
    ///
    /// To change the defaults, chain the builder methods
    /// [`with_algorithm`](Self::with_algorithm), [`with_digits`](Self::with_digits),
    /// and [`with_time_step`](Self::with_time_step).
    ///
    /// # Parameters
    ///
    /// * `secret` - Decoded secret key bytes. Base32 decoding or any other
    ///   key derivation is the caller's responsibility.
    #[must_use]
    pub fn new<S: AsRef<[u8]>>(secret: S) -> Self {
        let bytes = secret.as_ref().to_vec().into_boxed_slice();
        let secret = ByteSecret::from(bytes);
        Self {
            secret,
            ..Default::default()
        }
    }

    /// Sets the HMAC algorithm used for code generation.
    #[must_use]
    pub const fn with_algorithm(mut self, algo: Algorithm) -> Self {
        self.algorithm = algo;
        self
    }

    /// Sets the number of OTP digits (clamped to 6–8).
    ///
    /// The Steam algorithm ignores this setting and always produces 5-character codes.
    #[must_use]
    pub fn with_digits(mut self, digits: u8) -> Self {
        self.digits = digits.clamp(6, 8);
        self
    }

    /// Sets the time step in seconds (minimum 15, default 30).
    ///
    /// Values below 15 are silently raised to 15.
    #[must_use]
    pub const fn with_time_step(mut self, time_step: u8) -> Self {
        self.time_step = Self::clamp_min_u8(time_step, MIN_TIME_STEP);
        self
    }

    /// Generates the OTP code for the current system time.
    ///
    /// This is a convenience wrapper around [`generate_at`](Self::generate_at)
    /// that reads the system clock and computes `T` internally.
    /// Only available with the `std` feature (enabled by default).
    ///
    /// # Errors
    ///
    /// Returns an error when system time retrieval fails.
    #[cfg(feature = "std")]
    pub fn generate(&self) -> Result<String, Error> {
        let counter = self.current_counter()?;
        Ok(self.generate_at(counter))
    }

    /// Generates the OTP code for the given counter value.
    ///
    /// This is the core generation primitive and the only generation method
    /// available in `no_std` environments.
    ///
    /// [`generate`](Self::generate) is a convenience wrapper around this method.
    /// Call `generate_at` directly when the counter is derived externally,
    /// e.g. from a custom time source or an HOTP sequence number.
    ///
    /// # Parameters
    ///
    /// * `counter` - The pre-computed time counter `T = floor(Unix time / time_step)`.
    ///   `generate_at` uses this value directly without further division.
    ///   For HOTP-style use: an incrementing sequence number.
    #[must_use]
    pub fn generate_at(&self, counter: u64) -> String {
        let truncated = {
            let bytes = self
                .algorithm
                .compute_hmac(self.secret.as_ref(), &counter.to_be_bytes());
            truncate_rfc4226(&bytes)
        };

        match self.algorithm {
            #[cfg(feature = "steam")]
            Algorithm::Steam => steam_encode(truncated),
            _ => format_otp(truncated, self.digits),
        }
    }

    /// Returns the remaining validity period of the current code in seconds.
    ///
    /// ```
    /// use otpx::Totp;
    ///
    /// let totp = Totp::new(b"12345678901234567890");
    /// let remaining = totp.ttl().unwrap();
    /// assert!(remaining <= 30);
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error when system time retrieval fails.
    #[cfg(feature = "std")]
    pub fn ttl(&self) -> Result<u64, Error> {
        let now = system_time()?;
        let step = u64::from(self.time_step);
        Ok(step - (now % step))
    }

    /// Returns the current TOTP counter `T = floor(Unix time / time_step)`.
    #[cfg(feature = "std")]
    #[inline]
    fn current_counter(&self) -> Result<u64, Error> {
        let now = system_time()?;
        Ok(self.calc_counter(now))
    }

    /// Computes `T = floor(timestamp / time_step)` per RFC 6238 §4.
    #[cfg(feature = "std")]
    #[must_use]
    #[inline]
    const fn calc_counter(&self, timestamp: u64) -> u64 {
        timestamp / self.time_step as u64
    }

    /// Returns `value` if it is at least `min`, otherwise returns `min`.
    const fn clamp_min_u8(value: u8, min: u8) -> u8 {
        if value < min { min } else { value }
    }
}

impl Default for Totp {
    fn default() -> Self {
        Self {
            secret: ByteSecret::from(Box::<[u8]>::default()),
            digits: DEFAULT_DIGITS,
            algorithm: Algorithm::default(),
            time_step: DEFAULT_STEP,
        }
    }
}
