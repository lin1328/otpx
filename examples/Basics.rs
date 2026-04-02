use data_encoding::BASE32_NOPAD;

use otpx::{SecretKey, Totp};

/// Generates cryptographically secure random bytes for secret keys.
///
/// Length is clamped to 16–128 bytes (128–1024 bits).
fn random_secret_bytes(len: usize) -> Vec<u8> {
    let len = len.clamp(16, 128);
    let mut out = vec![0u8; len];
    getrandom::fill(&mut out).expect("OS RNG unavailable");
    out
}

/// Returns the current Unix timestamp in seconds.
#[cfg(feature = "std")]
fn unix_time() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn main() {
    let raw = random_secret_bytes(20);
    let encoded = BASE32_NOPAD.encode(&raw);

    let key = SecretKey::from_base32(encoded).unwrap();
    #[cfg(feature = "std")]
    let now = unix_time();

    let totp = Totp::new(key);
    let code = totp.generate_at(now);
    println!("TOTP: {code}");
    #[cfg(feature = "std")]
    println!("TTL: {}s", totp.ttl().unwrap());
}
