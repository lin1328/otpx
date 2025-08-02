# OTPX - One-Time Password Generator

[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> A Time-based One-Time Password (TOTP) Rust implementation library that follows RFC 6238, supporting multiple hash algorithms and Steam Guard compatibility.

## ✨ Features

- **🔐 RFC Standard Compliant**: Follows RFC 6238 (TOTP) and RFC 4226 (HOTP)
- **🛡️ Multiple Hash Algorithms**: Supports SHA1, SHA256, SHA512
- **🎯 Flexible Configuration**: Supports 5-8 digit codes with custom time steps
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

- **Minimum Length**: Use at least 16 Base32 characters (80 bits) for keys
- **Recommended Length**: 26+ characters (128 bits), following RFC 4226 recommendations
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
A: Ensure Base32 key is at least 16 characters.

**Q: Steam code format incorrect?**
A: Use `Algorithm::Steam` and ensure the key is correct.

## 🤝 Contributing

Contributions are welcome!

## 📚 Related Standards

- [RFC 6238 - TOTP: Time-Based One-Time Password Algorithm](https://tools.ietf.org/html/rfc6238)
- [RFC 4226 - HOTP: An HMAC-Based One-Time Password Algorithm](https://tools.ietf.org/html/rfc4226)
