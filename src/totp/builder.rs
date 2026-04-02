use core::marker::PhantomData;

use super::{Algorithm, DEFAULT_DIGITS, DEFAULT_STEP, Result, SecretKey, Totp};
use crate::util::{check_digits, check_period, check_secret_len};

/// Marker type for [`TotpBuilder`]: secret has not been set.
pub struct NoSecret;
/// Marker type for [`TotpBuilder`]: secret has been set, ready to build.
pub struct WithSecret;

/// Builder for constructing [`Totp`] instances with custom configuration.
///
/// `TotpBuilder` uses the typestate pattern to ensure that a secret is provided
/// before calling [`build`](TotpBuilder::build). The generic parameter `S` tracks
/// the builder state:
/// - [`NoSecret`] — secret not yet provided
/// - [`WithSecret`] — secret has been set, ready to build
///
/// # Usage
///
/// Obtain a builder via [`Totp::builder()`], configure optional parameters,
/// set the secret with [`secret`](TotpBuilder::secret), then call
/// [`build`](TotpBuilder::build).
///
/// ```
/// use otpx::Totp;
///
/// let totp = Totp::builder()
///     .with_digits(8)
///     .with_period(60)
///     .secret(b"12345678901234567890")
///     .build()
///     .unwrap();
/// ```
#[must_use = "builder does nothing until `.build()` is called"]
pub struct TotpBuilder<S = NoSecret> {
    secret: Option<SecretKey>,
    digits: u8,
    period: u8,
    algorithm: Algorithm,
    _state: PhantomData<S>,
}

impl Default for TotpBuilder<NoSecret> {
    fn default() -> Self {
        Self {
            secret: None,
            digits: DEFAULT_DIGITS,
            period: DEFAULT_STEP,
            algorithm: Algorithm::default(),
            _state: PhantomData,
        }
    }
}

impl<S> TotpBuilder<S> {
    /// Sets the number of OTP digits. Must be in `6..=8` (RFC 4226 §4 R4).
    ///
    /// Default: `6`.
    ///
    /// Validated at [`build`](TotpBuilder::build) time; invalid values return
    /// [`Error::InvalidDigits`](crate::Error::InvalidDigits).
    pub fn with_digits(mut self, digits: u8) -> Self {
        self.digits = digits;
        self
    }

    /// Sets the time step in seconds (RFC 6238 §4).
    ///
    /// Default: `30`.
    ///
    /// Must be at least `15`; smaller values return
    /// [`Error::InvalidTimeStep`](crate::Error::InvalidTimeStep) at
    /// [`build`](TotpBuilder::build) time.
    pub fn with_period(mut self, period: u8) -> Self {
        self.period = period;
        self
    }

    /// Sets the HMAC algorithm used for code generation.
    ///
    /// Default: [`Algorithm::Sha1`].
    pub fn with_algorithm(mut self, algorithm: Algorithm) -> Self {
        self.algorithm = algorithm;
        self
    }
}

impl TotpBuilder<NoSecret> {
    /// Sets the secret key from a byte slice, transitioning the builder to the ready state.
    ///
    /// This is the only required field; all other settings have defaults.
    /// Key length is validated at [`build`](TotpBuilder::build) time.
    ///
    /// Prefer [`secret_key`](Self::secret_key) when you already have a [`SecretKey`]
    /// to avoid copying the key bytes.
    pub fn secret(self, secret: impl AsRef<[u8]>) -> TotpBuilder<WithSecret> {
        self.secret_key(SecretKey::from_slice(secret.as_ref()))
    }

    /// Sets the secret key from an existing [`SecretKey`], transitioning the builder
    /// to the ready state.
    ///
    /// Unlike [`secret`](Self::secret), this method moves the key directly without
    /// copying the underlying bytes.
    pub fn secret_key(self, key: SecretKey) -> TotpBuilder<WithSecret> {
        TotpBuilder {
            secret: Some(key),
            digits: self.digits,
            period: self.period,
            algorithm: self.algorithm,
            _state: PhantomData,
        }
    }
}

impl TotpBuilder<WithSecret> {
    /// Validates configuration and constructs a [`Totp`] instance.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidDigits`](crate::Error::InvalidDigits) — digits not in `6..=8`
    /// - [`Error::InvalidTimeStep`](crate::Error::InvalidTimeStep) — period below 15 s
    /// - [`Error::EmptyField`](crate::Error::EmptyField) — secret is empty
    /// - [`Error::KeyTooShort`](crate::Error::KeyTooShort) — secret shorter than 128 bits (16 bytes)
    ///
    /// # Panics
    ///
    /// Does not panic in practice: the `WithSecret` typestate guarantees the secret
    /// field is `Some` before `build` can be called.
    pub fn build(self) -> Result<Totp> {
        let secret = self.secret.expect("typestate guarantees Some");
        check_secret_len(secret.len())?;
        check_digits(self.digits)?;
        check_period(self.period)?;

        Ok(Totp {
            secret,
            digits: self.digits,
            period: self.period,
            algorithm: self.algorithm,
        })
    }
}
