# OTPX - One-Time Password Generator

[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> A TOTP (RFC 6238) library in Rust, supporting multiple hash algorithms and Steam Guard compatibility. The core `generate_counter(counter)` method also serves as a low-level HOTP primitive for counter-based OTP generation.

## ✨ Features

- **🔐 RFC Standard Compliant**: Follows RFC 6238 (TOTP) and RFC 4226 (HOTP)
- **🛡️ Multiple Hash Algorithms**: Supports SHA1, SHA256, SHA512
- **🎯 Flexible Configuration**: Supports 6–8 digit codes for standard OTP, 5-character codes for Steam Guard, with custom time steps
- **🎮 Steam Compatible**: Supports Steam Guard format codes
- **📱 Cross-Platform**: Supports all Rust target platforms

### Installation

Add the following to your `Cargo.toml`:

```toml
[dependencies]
otpx = { git = "https://github.com/lin1328/otpx" }
```

### Basic Usage

See the [Basics example](examples/Basics.rs) for complete usage demonstrations including:

- Creating TOTP instances from Base32 strings and byte
- Generating codes at specific time counters
- Steam Guard algorithm support
- Custom algorithm and time step configurations

Run the basic example:

```bash
cargo run --example Basics
```

## 🔒 Security Best Practices

### 1. Key Management

- **Minimum Length**: Use at least 16 Base32 characters (80 bits / 10 bytes) for keys
- **Recommended Length**: 26+ Base32 characters (128 bits / 16 bytes), following RFC 4226 §4 R6
- **Secure Storage**: Keys should be stored in secure locations, avoid hardcoding
- **Access Control**: Restrict access permissions to keys

### 2. Algorithm Selection

- **Default**: SHA1 (best compatibility)
- **Recommended**: SHA256 (higher security)
- **High Security**: SHA512 (highest security)

### 3. Time Synchronization

Ensure system time accuracy, recommend using NTP service:

```bash
# Linux/macOS
sudo ntpdate -s time.nist.gov
```

### Running Examples

```bash
cargo run --example Basics
```

## 🔧 Troubleshooting

### Common Issues

**Q: Code doesn't match?**
A: Check if system time is synchronized and ensure the key is correct.

**Q: Key length error?**
A: Ensure Base32 key is at least 16 characters (80 bits). For production use, 26+ characters (128 bits) is recommended.

**Q: Steam code format incorrect?**
A: Use `Algorithm::Steam` and ensure the key is correct.

## 🤝 Contributing

Contributions are welcome!

## 📚 Related Standards

- [RFC 6238 - TOTP: Time-Based One-Time Password Algorithm](https://tools.ietf.org/html/rfc6238)
- [RFC 4226 - HOTP: An HMAC-Based One-Time Password Algorithm](https://tools.ietf.org/html/rfc4226)
