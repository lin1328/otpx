use otpx::{Totp, time_counter_now};

use data_encoding::BASE32_NOPAD;
use rand::{Rng, rng};

fn random_secret_bytes(byte_length: usize) -> Vec<u8> {
    let effective_length = byte_length.clamp(10, 128);
    let mut secret = vec![0u8; effective_length];
    rng().fill(&mut secret[..]);
    secret
}

fn main() {
    let demo_bytes = random_secret_bytes(16);
    let demo_secret = BASE32_NOPAD.encode(demo_bytes.as_ref());

    let base32 = Totp::new(&demo_secret).unwrap();
    let bytes = Totp::new_from_bytes(demo_bytes);

    let c = time_counter_now(30).unwrap();
    let x = base32.generate_hotp(c);
    let y = bytes.generate_hotp(c);

    if x == y {
        println!("success  : {x}");
    } else {
        println!("fail：This branch will not be executed");
        println!("Base32: {x}\nBytes:  {y}");
    }

    #[cfg(feature = "steam")]
    {
        let steam_totp = Totp::new(&demo_secret)
            .unwrap()
            .with_algorithm(otpx::Algorithm::Steam);
        println!("Steam    : {}", steam_totp.generate().unwrap());
    }

    let hotp = Totp::new(demo_secret.clone()).unwrap();
    println!("hotp dome: {}", hotp.generate_hotp(57_856_320));

    let custom_totp = Totp::new(demo_secret)
        .unwrap()
        .with_algorithm("Sha1".into())
        .with_digits(6)
        .with_time_step(30);
    println!("SHA1 6 30: {}", custom_totp.generate().unwrap());
    println!("remaining: {}s", custom_totp.ttl().unwrap());
}
