use otpx::{Algorithm, SecretKey, Totp};

#[cfg(not(feature = "steam"))]
fn main() {
    let raw = random_secret_bytes(20);
    let key = SecretKey::try_from(raw).unwrap();
    let now = unix_time();

    let totp = Totp::builder()
        .with_algorithm(Algorithm::Sha256)
        .with_digits(8)
        .with_period(60)
        .secret(&key)
        .build()
        .unwrap();

    println!(
        "Custom TOTP (SHA256, 8 digits, 60s): {}",
        totp.generate_at(now)
    );
    #[cfg(feature = "std")]
    println!("TTL: {}s", totp.ttl().unwrap());
}

#[cfg(feature = "steam")]
fn main() {
    let raw = random_secret_bytes(20).into_boxed_slice();
    let key = SecretKey::try_from(raw).unwrap();

    let steam = Totp::builder()
        .secret_key(key)
        .with_algorithm(Algorithm::Steam)
        .build()
        .unwrap();

    println!("Steam Guard: {}", steam.generate_counter(5));
}

fn random_secret_bytes(len: usize) -> Vec<u8> {
    let len = len.clamp(16, 128);
    let mut out = vec![0u8; len];
    getrandom::fill(&mut out).expect("OS RNG unavailable");
    out
}

#[cfg(not(feature = "steam"))]
fn unix_time() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
