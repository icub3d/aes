use aes::Aes256;
use anyhow::{Context, Result};
use block_padding::Pkcs7;
use cbc::{Decryptor, Encryptor};
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use clap::{Parser, Subcommand};
use rand::Rng;
use std::fs;
use std::io::{self, Read};

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

#[derive(Parser)]
#[command(name = "aes")]
#[command(about = "AES encryption/decryption CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt data using AES-256-CBC
    Encrypt {
        /// Key as a string (must be 32 bytes for AES-256)
        #[arg(short, long, conflicts_with = "key_file")]
        key: Option<String>,

        /// Path to file containing the key
        #[arg(short = 'f', long)]
        key_file: Option<String>,

        /// Output format (hex or base64)
        #[arg(short, long, default_value = "hex")]
        output_format: OutputFormat,
    },
    /// Decrypt data using AES-256-CBC
    Decrypt {
        /// Key as a string (must be 32 bytes for AES-256)
        #[arg(short, long, conflicts_with = "key_file")]
        key: Option<String>,

        /// Path to file containing the key
        #[arg(short = 'f', long)]
        key_file: Option<String>,

        /// Input format (hex or base64)
        #[arg(short, long, default_value = "hex")]
        input_format: OutputFormat,
    },
}

#[derive(Clone, clap::ValueEnum)]
enum OutputFormat {
    Hex,
    Base64,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt {
            key,
            key_file,
            output_format,
        } => {
            let key = load_key(key, key_file)?;
            let plaintext = read_stdin()?;
            let ciphertext = encrypt(&plaintext, &key)?;

            let output = match output_format {
                OutputFormat::Hex => hex::encode(&ciphertext),
                OutputFormat::Base64 => base64_encode(&ciphertext),
            };

            println!("{}", output);
        }
        Commands::Decrypt {
            key,
            key_file,
            input_format,
        } => {
            let key = load_key(key, key_file)?;
            let input = read_stdin_string()?;

            let ciphertext = match input_format {
                OutputFormat::Hex => {
                    hex::decode(input.trim()).context("Failed to decode hex input")?
                }
                OutputFormat::Base64 => {
                    base64_decode(input.trim()).context("Failed to decode base64 input")?
                }
            };

            let plaintext = decrypt(&ciphertext, &key)?;
            let output =
                String::from_utf8(plaintext).context("Decrypted data is not valid UTF-8")?;

            print!("{}", output);
        }
    }

    Ok(())
}

fn load_key(key_str: Option<String>, key_file: Option<String>) -> Result<Vec<u8>> {
    if let Some(k) = key_str {
        let bytes = k.as_bytes().to_vec();
        if bytes.len() != 32 {
            anyhow::bail!(
                "Key must be exactly 32 bytes for AES-256, got {} bytes",
                bytes.len()
            );
        }
        Ok(bytes)
    } else if let Some(path) = key_file {
        let bytes =
            fs::read(&path).with_context(|| format!("Failed to read key file: {}", path))?;
        if bytes.len() != 32 {
            anyhow::bail!(
                "Key must be exactly 32 bytes for AES-256, got {} bytes",
                bytes.len()
            );
        }
        Ok(bytes)
    } else {
        anyhow::bail!("Either --key or --key-file must be provided");
    }
}

fn read_stdin() -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    io::stdin()
        .read_to_end(&mut buffer)
        .context("Failed to read from stdin")?;
    Ok(buffer)
}

fn read_stdin_string() -> Result<String> {
    let mut buffer = String::new();
    io::stdin()
        .read_to_string(&mut buffer)
        .context("Failed to read from stdin")?;
    Ok(buffer)
}

fn encrypt(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    // Generate a random IV
    let mut iv = [0u8; 16];
    rand::thread_rng().fill(&mut iv);

    // Create cipher
    let cipher = Aes256CbcEnc::new(key.into(), &iv.into());

    // Pad and encrypt
    let mut buffer = plaintext.to_vec();
    let pos = buffer.len();
    let block_size = 16;
    let padding_len = block_size - (pos % block_size);
    buffer.resize(pos + padding_len, 0);

    // Apply PKCS7 padding
    for i in 0..padding_len {
        buffer[pos + i] = padding_len as u8;
    }

    let ciphertext = cipher
        .encrypt_padded_mut::<Pkcs7>(&mut buffer, pos)
        .map_err(|_| anyhow::anyhow!("Encryption failed"))?;

    // Prepend IV to ciphertext
    let mut result = iv.to_vec();
    result.extend_from_slice(ciphertext);

    Ok(result)
}

fn decrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 16 {
        anyhow::bail!("Invalid ciphertext: too short to contain IV");
    }

    // Extract IV and ciphertext
    let (iv, ciphertext) = data.split_at(16);

    // Create cipher
    let cipher = Aes256CbcDec::new(key.into(), iv.into());

    // Decrypt
    let mut buffer = ciphertext.to_vec();
    let plaintext = cipher
        .decrypt_padded_mut::<Pkcs7>(&mut buffer)
        .map_err(|_| anyhow::anyhow!("Decryption failed (wrong key or corrupted data)"))?;

    Ok(plaintext.to_vec())
}

fn base64_encode(data: &[u8]) -> String {
    use std::io::Write;
    let mut buf = Vec::new();
    {
        let mut encoder =
            base64::write::EncoderWriter::new(&mut buf, &base64::engine::general_purpose::STANDARD);
        encoder.write_all(data).unwrap();
    }
    String::from_utf8(buf).unwrap()
}

fn base64_decode(data: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(data)
        .context("Failed to decode base64")
}
