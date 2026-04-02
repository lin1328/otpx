use alloc::{boxed::Box, vec::Vec};
use core::fmt;

use data_encoding::BASE32_NOPAD_NOCASE;
#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Error, Result, util};

/// A container for the decoded HOTP/TOTP shared secret key.
///
/// `SecretKey` holds the raw key bytes as a fixed-length `Box<[u8]>`.
/// The length is immutable after construction, which avoids heap reallocations
/// and ensures that zeroization (see below) covers the entire allocation.
///
/// # Construction
///
/// Prefer [`SecretKey::from_base32`] for keys that arrive as Base32-encoded
/// strings (the most common case in TOTP/HOTP URIs). Use [`SecretKey::from_slice`]
/// when you already have the decoded bytes, e.g. from an HSM or test fixture.
///
/// # Key length
///
/// [`SecretKey::from_base32`] requires a minimum of **128 bits (16 bytes)** per
/// RFC 4226 §4 R6 recommendation.
///
/// [`SecretKey::from_slice`] skips length validation — the caller is
/// responsible for ensuring the key meets the desired security level.
///
/// # Memory safety
///
/// When the `zeroize` feature is enabled, `SecretKey` derives
/// [`ZeroizeOnDrop`](zeroize::ZeroizeOnDrop): the backing memory is
/// overwritten with zeros when the value is dropped, preventing secret
/// material from lingering in the heap.
/// The [`Debug`] implementation only exposes the key length, never the
/// key bytes, to prevent accidental leakage through logs or error messages.
#[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
#[derive(Default)]
pub struct SecretKey(Box<[u8]>);

impl SecretKey {
    /// Decodes a Base32-encoded shared secret (RFC 4648, case-insensitive, no padding).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The input is empty
    /// - The input contains invalid Base32 characters
    /// - The decoded key is shorter than 128 bits (16 bytes) per RFC 4226 §4 R6
    ///
    /// # Examples
    ///
    /// ```
    /// use otpx::SecretKey;
    ///
    /// let key = SecretKey::from_base32("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP").unwrap();
    /// assert_eq!(key.as_bytes().len(), 20);
    /// ```
    pub fn from_base32<S: AsRef<str>>(encoded: S) -> Result<Self> {
        let input = encoded.as_ref();

        if input.is_empty() {
            return Err(Error::EmptyField("secret"));
        }

        #[cfg_attr(not(feature = "zeroize"), allow(unused_mut))]
        let mut decoded = BASE32_NOPAD_NOCASE
            .decode(input.as_bytes())
            .map_err(|e| Error::DecodeError(e.position))?;

        // Cannot use `?` here: when the `zeroize` feature is enabled we must
        // explicitly zero `decoded` before returning, which `?` would skip.
        #[allow(clippy::question_mark)]
        if let Err(e) = util::check_secret_len(decoded.len()) {
            #[cfg(feature = "zeroize")]
            decoded.zeroize();
            return Err(e);
        }

        Ok(Self(decoded.into_boxed_slice()))
    }

    /// Constructs a `SecretKey` by copying a byte slice, skipping length validation.
    ///
    /// Use this when the bytes are already decoded, e.g. from an HSM or test fixture.
    /// The caller is responsible for ensuring the key meets the desired security level.
    ///
    /// # Examples
    ///
    /// ```
    /// use otpx::SecretKey;
    ///
    /// let key = SecretKey::from_slice(b"\x48\x65\x6c\x6c\x6f\x21\x52\x75\x73\x74\x48\x65\x6c\x6c\x6f\x21\x52\x75\x73\x74");
    /// assert_eq!(key.as_bytes().len(), 20);
    /// ```
    #[must_use]
    pub fn from_slice(slice: impl AsRef<[u8]>) -> Self {
        Self(slice.as_ref().into())
    }

    /// Returns a reference to the raw key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Encodes the raw key bytes as an uppercase Base32 string (no padding).
    ///
    /// This is the inverse of [`SecretKey::from_base32`].
    ///
    /// # Examples
    ///
    /// ```
    /// use otpx::SecretKey;
    ///
    /// let key = SecretKey::from_base32("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP").unwrap();
    /// assert_eq!(key.to_base32(), "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP");
    /// ```
    #[must_use]
    pub fn to_base32(&self) -> alloc::string::String {
        BASE32_NOPAD_NOCASE.encode(&self.0)
    }

    /// Returns the number of bytes in the secret key.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if the secret key contains no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    // /// Generates a random secret key of [`DEFAULT_SECRET_LEN`] bytes (160 bits).
    // ///
    // /// - `std`: uses [`rand::rngs::ThreadRng`] (thread-local, no syscall per call)
    // /// - `no_std`: uses [`rand::rngs::SysRng`] (`getrandom` syscall)
    // #[must_use]
    // pub fn new() -> Self {
    //     let mut bytes = [0u8; DEFAULT_SECRET_LEN];
    //     #[cfg(feature = "std")]
    //     {
    //         use rand::rand_core::Rng as _;
    //         rand::rng().fill_bytes(&mut bytes);
    //     }
    //     #[cfg(not(feature = "std"))]
    //     {
    //         use rand::rand_core::TryRng as _;
    //         rand::rngs::SysRng
    //             .try_fill_bytes(&mut bytes)
    //             .expect("OS RNG failed");
    //     }
    //     Self(Box::from(bytes))
    // }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretKey")
            .field("len", &self.0.len())
            .finish_non_exhaustive()
    }
}

impl TryFrom<Box<[u8]>> for SecretKey {
    type Error = Error;

    fn try_from(bytes: Box<[u8]>) -> Result<Self> {
        util::check_secret_len(bytes.len())?;
        Ok(Self(bytes))
    }
}

impl TryFrom<Vec<u8>> for SecretKey {
    type Error = Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self> {
        util::check_secret_len(bytes.len())?;
        Ok(Self(bytes.into_boxed_slice()))
    }
}

impl TryFrom<&[u8]> for SecretKey {
    type Error = Error;

    fn try_from(slice: &[u8]) -> Result<Self> {
        util::check_secret_len(slice.len())?;
        Ok(Self(slice.into()))
    }
}

impl AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
