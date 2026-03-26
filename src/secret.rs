use alloc::boxed::Box;
use core::fmt;

use data_encoding::BASE32_NOPAD_NOCASE;
#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error;

/// A container for the decoded HOTP/TOTP shared secret key.
///
/// `SecretKey` holds the raw key bytes as a fixed-length `Box<[u8]>`.
/// The length is immutable after construction, which avoids heap reallocations
/// and ensures that zeroization (see below) covers the entire allocation.
///
/// # Construction
///
/// Prefer [`SecretKey::from_base32`] for keys that arrive as Base32-encoded
/// strings (the most common case in TOTP/HOTP URIs). Use [`SecretKey::from_bytes`]
/// when you already have the decoded bytes, e.g. from an HSM or test fixture.
///
/// # Key length
///
/// [`SecretKey::from_base32`] enforces a minimum of **80 bits (10 bytes)**
/// as required by RFC 4226 §4. RFC 4226 recommends at least 128 bits (16 bytes);
/// in debug builds with the `std` feature a warning is printed for keys shorter
/// than that threshold.
///
/// [`SecretKey::from_bytes`] skips length validation — the caller is
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
    /// - The decoded key is shorter than 80 bits (10 bytes)
    ///
    /// # Examples
    ///
    /// ```
    /// use otpx::SecretKey;
    ///
    /// let key = SecretKey::from_base32("JBSWY3DPL5JHK43U").unwrap();
    /// assert_eq!(key.as_bytes().len(), 10);
    /// ```
    pub fn from_base32<S: AsRef<str>>(encoded: S) -> Result<Self, error::Error> {
        let input = encoded.as_ref();

        if input.is_empty() {
            return Err(error::Error::EmptySecret);
        }

        #[cfg_attr(not(feature = "zeroize"), allow(unused_mut))]
        let mut decoded = BASE32_NOPAD_NOCASE
            .decode(input.as_bytes())
            .map_err(|_| error::Error::DecodeError)?;

        if !Self::validate(decoded.len()) {
            let bits = decoded.len() * 8;
            #[cfg(feature = "zeroize")]
            decoded.zeroize();
            return Err(error::Error::KeyTooShort(bits));
        }

        Ok(Self(decoded.into_boxed_slice()))
    }

    /// Constructs a `SecretKey` directly from raw bytes, skipping length validation.
    ///
    /// Use this when the bytes are already decoded, e.g. from an HSM or test fixture.
    /// The caller is responsible for ensuring the key meets the desired security level.
    ///
    /// # Examples
    ///
    /// ```
    /// use otpx::SecretKey;
    ///
    /// let key = SecretKey::from_bytes(b"48656c6c6f2152757374");
    /// assert_eq!(key.as_bytes().len(), 20);
    /// ```
    pub fn from_bytes<S: AsRef<[u8]>>(bytes: S) -> Self {
        Self(bytes.as_ref().into())
    }

    /// Returns a reference to the raw key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns `true` if `len` meets the minimum key length (80 bits / 10 bytes, RFC 4226 §4).
    fn validate(len: usize) -> bool {
        if len < 10 {
            return false;
        }
        #[cfg(all(debug_assertions, feature = "std"))]
        if len < 16 {
            std::eprintln!(
                "Warning: Key length is {} bits, below the RFC 4226 recommended 128 bits. Consider using a longer key for improved security",
                len * 8
            );
        }
        true
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretKey")
            .field("len", &self.0.len())
            .finish_non_exhaustive()
    }
}
