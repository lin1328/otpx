use alloc::string::String;

#[cfg(feature = "steam")]
use crate::util::steam_encode;
#[cfg(feature = "std")]
use crate::util::system_time;
use crate::util::{compute_hmac, format_otp, truncate_rfc4226};
use crate::{Algorithm, Result, SecretKey};
use crate::{DEFAULT_DIGITS, DEFAULT_STEP, MAX_DIGEST_LEN};

mod builder;
use builder::TotpBuilder;
pub use builder::{NoSecret, WithSecret};

/// RFC 6238: Time-Based One-Time Password (TOTP) implementation.
///
/// TOTP extends HOTP by deriving the counter from the current time:
/// `T = floor((Unix time − T0) / X)`, where T0 is the Unix epoch and
/// X is the time step (default 30 s).
///
/// # Construction
///
/// Pass a [`SecretKey`] to [`Totp::new`]. Use [`SecretKey::from_base32`]
/// to decode Base32-encoded secrets:
///
/// ```
/// use otpx::{Totp, SecretKey};
///
/// let key = SecretKey::from_base32("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP").unwrap();
/// let totp = Totp::new(key);
/// ```
///
/// # Configuration
///
/// For custom parameters, use [`Totp::builder()`] (see [`TotpBuilder`] for details).
///
/// # Code generation
///
/// Two generation methods are provided:
///
/// - [`generate`](Self::generate) — reads the system clock internally.
///   Requires the `std` feature (enabled by default).
/// - [`generate_at`](Self::generate_at) — accepts a Unix timestamp; computes `T` internally.
/// - [`generate_counter`](Self::generate_counter) — accepts a pre-computed counter directly.
///   Always available, including `no_std`. Also serves as a low-level HOTP primitive.
///
/// # Key requirements
///
/// [`Totp::new`] validates key length: the secret must be at least 80 bits (10 bytes)
/// per RFC 4226 §4; 128 bits (16 bytes) or more is recommended.
#[derive(Debug)]
pub struct Totp {
    /// Shared secret key (RFC 4226 §4 / RFC 6238 §4).
    secret: SecretKey,
    /// Number of OTP digits (6–8). Default: 6.
    digits: u8,
    /// HMAC algorithm used for code generation. Default: SHA-1.
    algorithm: Algorithm,
    /// Time step in seconds. Minimum: 15. Default: 30.
    period: u8,
}

impl Totp {
    /// Creates a `Totp` instance from a secret key.
    ///
    /// The default configuration uses SHA-1, 6 digits, and a 30-second time step,
    /// which is compatible with most authenticator apps (RFC 6238).
    ///
    /// To change the defaults, use [`Totp::builder()`] for validated construction.
    ///
    /// # Parameters
    ///
    /// * `secret` - The secret key. Use [`SecretKey::from_base32`] to decode
    ///   Base32-encoded secrets, or [`SecretKey::from_slice`] for raw bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use otpx::{Totp, SecretKey};
    ///
    /// let key = SecretKey::from_base32("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP").unwrap();
    /// let totp = Totp::new(key);
    /// ```
    #[must_use]
    pub fn new(secret: SecretKey) -> Self {
        Self {
            secret,
            ..Default::default()
        }
    }

    /// Creates a [`TotpBuilder`] with default configuration.
    ///
    /// Use the builder to configure the secret, algorithm, digit count,
    /// time step, issuer, and account before calling [`TotpBuilder::build`].
    pub fn builder() -> TotpBuilder<NoSecret> {
        TotpBuilder::default()
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
    pub fn generate(&self) -> Result<String> {
        let now = system_time()?;
        Ok(self.generate_counter(now / u64::from(self.period)))
    }

    /// Generates the OTP code for the given Unix timestamp (seconds since epoch).
    ///
    /// Computes `T = floor(timestamp / time_step)` internally.
    /// Use this when you have a Unix timestamp and want to avoid manual counter arithmetic.
    ///
    /// # Parameters
    ///
    /// * `timestamp` - Unix timestamp in seconds.
    #[must_use]
    pub fn generate_at(&self, timestamp: u64) -> String {
        self.generate_counter(timestamp / u64::from(self.period))
    }

    /// Generates the OTP code for the given counter value.
    ///
    /// Use this method directly when:
    /// - The counter is derived from a custom time source
    /// - Implementing HOTP with an incrementing sequence number
    /// - You need full control over the counter value
    ///
    /// # Parameters
    ///
    /// * `counter` - For TOTP: `T = floor(Unix time / time_step)`.
    ///   For HOTP: an incrementing sequence number.
    #[must_use]
    pub fn generate_counter(&self, counter: u64) -> String {
        let truncated = {
            let mut buf = [0u8; MAX_DIGEST_LEN];
            let bytes = compute_hmac(
                self.algorithm,
                self.secret.as_ref(),
                &counter.to_be_bytes(),
                &mut buf,
            );
            truncate_rfc4226(bytes)
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
    pub fn ttl(&self) -> Result<u64> {
        let now = system_time()?;
        let step = u64::from(self.period);
        Ok(step - (now % step))
    }

    /// Returns the number of OTP digits.
    #[must_use]
    pub fn __digits(&self) -> u8 {
        self.digits
    }

    /// Returns the HMAC algorithm used for code generation.
    #[must_use]
    pub fn __algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Returns the time step in seconds.
    #[must_use]
    pub fn __period(&self) -> u8 {
        self.period
    }
}

impl Default for Totp {
    fn default() -> Self {
        Self {
            secret: SecretKey::default(),
            digits: DEFAULT_DIGITS,
            algorithm: Algorithm::default(),
            period: DEFAULT_STEP,
        }
    }
}
