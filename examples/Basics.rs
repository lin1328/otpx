use otpx::Totp;

use data_encoding::BASE32_NOPAD;
use rand::{RngExt, rng};

fn random_secret_bytes(byte_length: usize) -> Vec<u8> {
    let effective_length = byte_length.clamp(10, 128);
    let mut secret = vec![0u8; effective_length];
    rng().fill(&mut secret[..]);
    secret
}

fn get_time_counter() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 30
}

fn main() {
    let demo_bytes = random_secret_bytes(16);
    let demo_secret = BASE32_NOPAD.encode(demo_bytes.as_ref());

    // Both paths produce the same key bytes
    let decoded = data_encoding::BASE32_NOPAD
        .decode(demo_secret.as_bytes())
        .unwrap();
    let base32 = Totp::new(&decoded);
    let bytes = Totp::new(&demo_bytes);

    let counter = get_time_counter();
    let base32_code = base32.generate_at(counter);
    let bytes_code = bytes.generate_at(counter);

    if base32_code == bytes_code {
        println!("success  : {base32_code}");
    } else {
        println!("fail：This branch will not be executed");
        println!("Base32: {base32_code}\nBytes:  {bytes_code}");
    }

    #[cfg(feature = "steam")]
    {
        let steam_totp = Totp::new(&decoded).with_algorithm(otpx::Algorithm::Steam);
        println!("Steam    : {}", steam_totp.generate().unwrap());
    }

    let hotp = otpx::Totp::new(demo_secret.clone());
    println!("hotp dome: {}", hotp.generate_at(57_856_320));

    let custom_totp = Totp::new(&decoded)
        .with_algorithm("Sha1".parse().unwrap())
        .with_digits(6)
        .with_time_step(30);
    println!("SHA1 6 30: {}", custom_totp.generate().unwrap());
    println!("remaining: {}s", custom_totp.ttl().unwrap());
}
