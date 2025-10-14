# AES CLI

A simple command-line interface for encrypting and decrypting data using AES-256-CBC encryption.

## Features

- AES-256-CBC encryption/decryption
- Read data from stdin
- Provide key via command-line argument or file
- Support for hex and base64 output formats
- Automatic IV generation for encryption
- PKCS7 padding

## Installation

```bash
cargo build --release
```

The binary will be available at `target/release/icub3d-aes` (or `icub3d-aes.exe` on Windows).

## Usage

### Encrypt

Encrypt data using a key provided as a string:

```bash
echo "Hello, World!" | cargo run -- encrypt --key "this_is_a_32_byte_secret_key!!"
```

Encrypt using a key from a file:

```bash
echo "Hello, World!" | cargo run -- encrypt --key-file key.bin
```

Use base64 output format:

```bash
echo "Hello, World!" | cargo run -- encrypt --key "this_is_a_32_byte_secret_key!!" --output-format base64
```

### Decrypt

Decrypt data using a key provided as a string:

```bash
echo "5a3d2c1b4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e" | cargo run -- decrypt --key "this_is_a_32_byte_secret_key!!"
```

Decrypt using a key from a file:

```bash
echo "5a3d2c1b4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e" | cargo run -- decrypt --key-file key.bin
```

Use base64 input format:

```bash
echo "WjPSwbTl9qe4yZ0OHyo7TF1uf4qbDB0uP0pbbH2Onw==" | cargo run -- decrypt --key "this_is_a_32_byte_secret_key!!" --input-format base64
```

### Working with Files

Encrypt a file:

```bash
cat plaintext.txt | cargo run -- encrypt --key "this_is_a_32_byte_secret_key!!" > encrypted.hex
```

Decrypt a file:

```bash
cat encrypted.hex | cargo run -- decrypt --key "this_is_a_32_byte_secret_key!!" > decrypted.txt
```

### Generating a Key

To generate a random 32-byte key, you can use:

**Linux/macOS:**
```bash
dd if=/dev/urandom of=key.bin bs=32 count=1
```

**Windows (PowerShell):**
```powershell
$key = New-Object byte[] 32
[Security.Cryptography.RNGCryptoServiceProvider]::new().GetBytes($key)
[IO.File]::WriteAllBytes("key.bin", $key)
```

## Key Requirements

- The key must be exactly 32 bytes for AES-256
- When providing the key as a string, it should be a 32-character ASCII string
- When using a key file, the file should contain exactly 32 bytes

## Security Notes

- The IV (Initialization Vector) is randomly generated for each encryption operation
- The IV is prepended to the ciphertext output
- PKCS7 padding is used for block alignment
- Never reuse keys for sensitive data
- Store keys securely and never commit them to version control

## Help

For more information and command options:

```bash
cargo run -- --help
cargo run -- encrypt --help
cargo run -- decrypt --help
```
