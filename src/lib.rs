#![no_std]
//! RFC 4226 (HOTP) and RFC 6238 (TOTP) one-time password implementation.
//!
//! `otpx` provides [`Totp`] and `Hotp` types with support for multiple
//! HMAC algorithms, configurable digit counts, and optional Steam Guard
//! encoding. The crate supports `no_std` with `alloc`.
//!
//! ## Feature highlights
//!
//! - TOTP (RFC 6238) and HOTP (RFC 4226)
//! - Multiple hash algorithms: SHA-1 (default), SHA-256, SHA-512
//! - Configurable digit count: 6–8 for TOTP/HOTP; 5 characters for Steam Guard
//!
//! ## Quick start
//!
//! [`Totp::new`] accepts pre-decoded `&[u8]`; use [`SecretKey::from_base32`] to decode
//! a Base32 secret first.
//!
//! ```
//! use otpx::{Totp, SecretKey};
//!
//! let key = SecretKey::from_base32("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP").unwrap();
//! let totp = Totp::new(key.as_bytes());
//! // 57_856_320 is a pre-computed time counter T = floor(Unix time / 30)
//! let code = totp.generate_counter(57_856_320);
//! assert_eq!(code, "311152");
//! ```
//!
//! ## `no_std` support
//!
//! This crate is `#![no_std]` but requires `alloc`. Disable the default
//! `std` feature to use it in `no_std` environments:
//!
//! ```toml
//! [dependencies]
//! otpx = { version = "...", default-features = false }
//! ```
//!
//! Without `std`, [`Totp::generate`] and [`Totp::ttl`] are unavailable.
//! Use [`Totp::generate_at`] instead, supplying the time counter
//! `T = (Current Unix time - T0) / X` computed by the caller.
//!
//! ## Cargo features
//!
//! | Feature   | Default | Description |
//! |-----------|---------|-------------|
//! | `std`     | yes     | Enables [`Totp::generate`] and [`Totp::ttl`] via system clock |
//! | `steam`   | no      | Enables [`Algorithm::Steam`] and Steam Guard 5-character encoding |
//! | `zeroize` | no      | Zeroes secret key bytes on drop to reduce heap exposure |
//! | `serde`   | no      | Derives `Serialize`/`Deserialize` for [`Algorithm`] |
//!
//! ## API overview
//!
//! - [`Totp`] — time-based OTP with builder API and full usage examples
//! - [`Algorithm`] — supported hash algorithms and string parsing
//! - [`SecretKey`] — Base32 decoding, key validation, and optional zeroize-on-drop

#[cfg(feature = "std")]
extern crate std;

extern crate alloc;

mod algorithm;
mod error;
mod secret;
mod totp;
mod util;

/// Minimum time step for TOTP in seconds.
pub(crate) const MIN_TIME_STEP: u8 = 15;
/// Maximum HMAC digest length across all variants.
pub(crate) const MAX_DIGEST_LEN: usize = 64;

/// Default number of digits for OTP codes.
pub const DEFAULT_DIGITS: u8 = 6;
// /// Default secret key length in bytes for random generation (RFC 4226 §4 R6: 160 bits).
// pub const DEFAULT_SECRET_LEN: usize = 20;
/// Default time step for TOTP in seconds.
pub const DEFAULT_STEP: u8 = 30;

/// Steam Guard character set (26 alphanumeric characters).
#[cfg(feature = "steam")]
pub const STEAM_CHARSET: &[u8; 26] = b"23456789BCDFGHJKMNPQRTVWXY";
/// Number of characters in [`STEAM_CHARSET`], used as the encoding radix.
#[cfg(feature = "steam")]
pub(crate) const STEAM_RADIX: u32 = 26;
#[cfg(feature = "steam")]
const _: () = assert!(STEAM_CHARSET.len() == STEAM_RADIX as usize);

pub use algorithm::Algorithm;
pub use error::{Error, Result};
pub use secret::SecretKey;
pub use totp::Totp;
#[doc(hidden)]
pub use totp::{NoSecret, WithSecret};
