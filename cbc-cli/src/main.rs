/// CBC CLI — command-line tool for encoding, decoding, validating, inspecting, and
/// transforming CBC artifacts.

use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;
use std::process;

#[derive(Parser)]
#[command(name = "cbc", version = "0.1.0", about = "CBC (Context-Bound Container) v0.1 CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encode a file into a CBC artifact
    Encode {
        /// Input file
        #[arg(short, long)]
        input: PathBuf,
        /// Output CBC artifact file
        #[arg(short, long)]
        output: PathBuf,
        /// Hash suite (blake3 or sha256)
        #[arg(long, default_value = "blake3")]
        hash: String,
        /// Block payload size in bytes (must be power of 2, 512..=16MiB)
        #[arg(long, default_value = "4096")]
        block_size: u32,
        /// Comma-separated constraint families (A, A+B, A+B+C)
        #[arg(long, default_value = "A")]
        families: String,
    },

    /// Decode a CBC artifact and extract the payload
    Decode {
        /// Input CBC artifact file
        #[arg(short, long)]
        input: PathBuf,
        /// Output file for extracted payload
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Validate a CBC artifact (exit 0 if valid, 1 if invalid)
    Validate {
        /// Input CBC artifact file
        #[arg(short, long)]
        input: PathBuf,
    },

    /// Inspect a CBC artifact and display metadata
    Inspect {
        /// Input CBC artifact file
        #[arg(short, long)]
        input: PathBuf,
    },

    /// Perform a transform operation
    Transform {
        /// Transform type (truncate, rechunk, recompress, concat, subrange)
        #[arg(short = 't', long = "type")]
        transform_type: String,
        /// Input CBC artifact file(s), comma-separated for concat
        #[arg(short, long)]
        input: String,
        /// Output CBC artifact file
        #[arg(short, long)]
        output: PathBuf,
        /// Signing key file (Ed25519)
        #[arg(short, long)]
        key: PathBuf,
        /// Keep blocks (for truncate)
        #[arg(long)]
        keep: Option<u32>,
        /// New block size (for rechunk)
        #[arg(long)]
        new_block_size: Option<u32>,
        /// Start block for subrange (inclusive)
        #[arg(long)]
        start: Option<u32>,
        /// End block for subrange (inclusive)
        #[arg(long)]
        end: Option<u32>,
    },

    /// Generate a signing key pair
    Keygen {
        /// Output key file path
        #[arg(short, long)]
        output: PathBuf,
        /// Algorithm (ed25519 or ecdsa)
        #[arg(long, default_value = "ed25519")]
        alg: String,
    },
}

fn parse_families(s: &str) -> u8 {
    let mut mode: u8 = 0;
    for part in s.split('+') {
        match part.trim().to_uppercase().as_str() {
            "A" => mode |= cbc_core::bootstrap::FAMILY_A_BIT,
            "B" => mode |= cbc_core::bootstrap::FAMILY_B_BIT,
            "C" => mode |= cbc_core::bootstrap::FAMILY_C_BIT,
            _ => {
                eprintln!("Unknown family: {part}. Valid: A, B, C");
                process::exit(1);
            }
        }
    }
    if mode & cbc_core::bootstrap::FAMILY_A_BIT == 0 {
        mode |= cbc_core::bootstrap::FAMILY_A_BIT; // Always include A
    }
    mode
}

fn parse_hash(s: &str) -> cbc_core::HashSuite {
    match s.to_lowercase().as_str() {
        "blake3" => cbc_core::HashSuite::Blake3,
        "sha256" => cbc_core::HashSuite::Sha256,
        _ => {
            eprintln!("Unknown hash suite: {s}. Valid: blake3, sha256");
            process::exit(1);
        }
    }
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encode {
            input,
            output,
            hash,
            block_size,
            families,
        } => cmd_encode(input, output, hash, block_size, families),

        Commands::Decode { input, output } => cmd_decode(input, output),

        Commands::Validate { input } => cmd_validate(input),

        Commands::Inspect { input } => cmd_inspect(input),

        Commands::Transform {
            transform_type,
            input,
            output,
            key,
            keep,
            new_block_size,
            start,
            end,
        } => cmd_transform(transform_type, input, output, key, keep, new_block_size, start, end),

        Commands::Keygen { output, alg } => cmd_keygen(output, alg),
    }
}

fn cmd_encode(input: PathBuf, output: PathBuf, hash: String, block_size: u32, families: String) {
    let payload = fs::read(&input).unwrap_or_else(|e| {
        eprintln!("Error reading {}: {e}", input.display());
        process::exit(1);
    });

    let config = cbc_core::EncoderConfig {
        hash_suite: parse_hash(&hash),
        commitment_mode: parse_families(&families),
        block_payload_size: block_size,
        flags: 0,
    };

    let artifact = cbc_core::encoder::encode_random_nonce(&config, &payload, &[]);

    fs::write(&output, &artifact).unwrap_or_else(|e| {
        eprintln!("Error writing {}: {e}", output.display());
        process::exit(1);
    });

    let block_count = (payload.len() + block_size as usize - 1) / block_size as usize;
    println!("✓ Encoded {} bytes → {} ({} blocks, {} bytes)",
        payload.len(), output.display(), block_count.max(1), artifact.len());
}

fn cmd_decode(input: PathBuf, output: PathBuf) {
    let data = fs::read(&input).unwrap_or_else(|e| {
        eprintln!("Error reading {}: {e}", input.display());
        process::exit(1);
    });

    let decoded = cbc_core::decoder::decode(&data).unwrap_or_else(|e| {
        eprintln!("✗ Validation failed: {e}");
        process::exit(1);
    });

    fs::write(&output, &decoded.payload).unwrap_or_else(|e| {
        eprintln!("Error writing {}: {e}", output.display());
        process::exit(1);
    });

    println!("✓ Decoded {} blocks → {} bytes → {}",
        decoded.block_count, decoded.payload.len(), output.display());
}

fn cmd_validate(input: PathBuf) {
    let data = fs::read(&input).unwrap_or_else(|e| {
        eprintln!("Error reading {}: {e}", input.display());
        process::exit(1);
    });

    match cbc_core::decoder::validate(&data) {
        Ok(()) => {
            println!("✓ Valid CBC artifact");
            process::exit(0);
        }
        Err(e) => {
            eprintln!("✗ Invalid: {e}");
            process::exit(1);
        }
    }
}

fn cmd_inspect(input: PathBuf) {
    let data = fs::read(&input).unwrap_or_else(|e| {
        eprintln!("Error reading {}: {e}", input.display());
        process::exit(1);
    });

    // Parse bootstrap (always safe even if artifact is invalid)
    if data.len() < 64 {
        eprintln!("File too small for CBC bootstrap segment ({} bytes)", data.len());
        process::exit(1);
    }

    let mut bootstrap_bytes = [0u8; 64];
    bootstrap_bytes.copy_from_slice(&data[..64]);

    match cbc_core::BootstrapSegment::decode(&bootstrap_bytes) {
        Ok(bs) => {
            println!("=== CBC Artifact Inspection ===");
            println!("File size:         {} bytes", data.len());
            println!("Hash suite:        {:?}", bs.hash_suite);
            println!("Commitment mode:   0x{:02x} (A:{} B:{} C:{})",
                bs.commitment_mode,
                if bs.family_a() { "✓" } else { "✗" },
                if bs.family_b() { "✓" } else { "✗" },
                if bs.family_c() { "✓" } else { "✗" },
            );
            println!("Block payload:     {} bytes", bs.block_payload_size);
            println!("Block count:       {}", bs.block_count);
            println!("Nonce:             {}", hex::encode(bs.bootstrap_nonce));
            println!("Flags:             0x{:08x} (compressed:{} encrypted:{})",
                bs.flags,
                if bs.flags & 0x01 != 0 { "yes" } else { "no" },
                if bs.flags & 0x02 != 0 { "yes" } else { "no" },
            );

            // Try full validation
            match cbc_core::decoder::decode(&data) {
                Ok(decoded) => {
                    println!("Chain root:        {}", hex::encode(decoded.chain_root));
                    if let Some(mr) = decoded.merkle_root {
                        println!("Merkle root:       {}", hex::encode(mr));
                    }
                    println!("Payload size:      {} bytes", decoded.payload.len());
                    println!("Receipts:          {}", decoded.receipt_slots.len());
                    for (i, r) in decoded.receipt_slots.iter().enumerate() {
                        match cbc_transform::Receipt::decode(r) {
                            Ok(receipt) => {
                                println!("  Receipt #{i}:");
                                println!("    Source root:   {}", hex::encode(receipt.source_root));
                                println!("    Derived root:  {}", hex::encode(receipt.derived_root));
                                println!("    Transform:     {:?}", receipt.transform_type);
                                println!("    Timestamp:     {}", receipt.timestamp);
                                println!("    Sig algorithm: {:?}", receipt.sig_alg);
                            }
                            Err(_) => {
                                println!("  Receipt #{i}: (decode error, {} bytes)", r.len());
                            }
                        }
                    }
                    println!("\nValidation:        ✓ PASS");
                }
                Err(e) => {
                    println!("\nValidation:        ✗ FAIL ({e})");
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to parse bootstrap segment: {e}");
            process::exit(1);
        }
    }
}

fn cmd_transform(
    transform_type: String,
    input: String,
    output: PathBuf,
    key_path: PathBuf,
    keep: Option<u32>,
    new_block_size: Option<u32>,
    start: Option<u32>,
    end: Option<u32>,
) {
    let key_bytes = fs::read(&key_path).unwrap_or_else(|e| {
        eprintln!("Error reading key {}: {e}", key_path.display());
        process::exit(1);
    });
    let signing_key = load_signing_key(&key_bytes);

    match transform_type.as_str() {
        "truncate" => {
            let keep_blocks = keep.unwrap_or_else(|| {
                eprintln!("--keep required for truncate");
                process::exit(1);
            });
            let data = fs::read(input.trim()).unwrap_or_else(|e| {
                eprintln!("Error reading input: {e}");
                process::exit(1);
            });
            let (artifact, _receipt) =
                cbc_transform::truncate(&data, keep_blocks, &signing_key)
                    .unwrap_or_else(|e| {
                        eprintln!("Transform failed: {e}");
                        process::exit(1);
                    });
            fs::write(&output, &artifact).unwrap();
            println!("✓ Truncated → {} ({} bytes)", output.display(), artifact.len());
        }
        "rechunk" => {
            let new_bs = new_block_size.unwrap_or_else(|| {
                eprintln!("--new-block-size required for rechunk");
                process::exit(1);
            });
            let data = fs::read(input.trim()).unwrap_or_else(|e| {
                eprintln!("Error reading input: {e}");
                process::exit(1);
            });
            let (artifact, _receipt) =
                cbc_transform::rechunk(&data, new_bs, &signing_key)
                    .unwrap_or_else(|e| {
                        eprintln!("Transform failed: {e}");
                        process::exit(1);
                    });
            fs::write(&output, &artifact).unwrap();
            println!("✓ Rechunked → {} ({} bytes)", output.display(), artifact.len());
        }
        "recompress" => {
            let data = fs::read(input.trim()).unwrap_or_else(|e| {
                eprintln!("Error reading input: {e}");
                process::exit(1);
            });
            let (artifact, _receipt) =
                cbc_transform::recompress(&data, &signing_key)
                    .unwrap_or_else(|e| {
                        eprintln!("Transform failed: {e}");
                        process::exit(1);
                    });
            fs::write(&output, &artifact).unwrap();
            println!("✓ Recompressed → {} ({} bytes)", output.display(), artifact.len());
        }
        "concat" => {
            let input_files: Vec<&str> = input.split(',').map(|s| s.trim()).collect();
            let data: Vec<Vec<u8>> = input_files
                .iter()
                .map(|f| {
                    fs::read(f).unwrap_or_else(|e| {
                        eprintln!("Error reading {f}: {e}");
                        process::exit(1);
                    })
                })
                .collect();
            let refs: Vec<&[u8]> = data.iter().map(|d| d.as_slice()).collect();
            let (artifact, _receipts) =
                cbc_transform::concatenate(&refs, &signing_key)
                    .unwrap_or_else(|e| {
                        eprintln!("Transform failed: {e}");
                        process::exit(1);
                    });
            fs::write(&output, &artifact).unwrap();
            println!("✓ Concatenated {} sources → {} ({} bytes)",
                input_files.len(), output.display(), artifact.len());
        }
        "subrange" => {
            let s = start.unwrap_or_else(|| {
                eprintln!("--start required for subrange");
                process::exit(1);
            });
            let e = end.unwrap_or_else(|| {
                eprintln!("--end required for subrange");
                process::exit(1);
            });
            let data = fs::read(input.trim()).unwrap_or_else(|e| {
                eprintln!("Error reading input: {e}");
                process::exit(1);
            });
            let (artifact, _receipt) =
                cbc_transform::subrange_extract(&data, s, e, &signing_key)
                    .unwrap_or_else(|e| {
                        eprintln!("Transform failed: {e}");
                        process::exit(1);
                    });
            fs::write(&output, &artifact).unwrap();
            println!("✓ Extracted blocks [{s}..{e}] → {} ({} bytes)",
                output.display(), artifact.len());
        }
        other => {
            eprintln!("Unknown transform: {other}. Valid: truncate, rechunk, recompress, concat, subrange");
            process::exit(1);
        }
    }
}

fn cmd_keygen(output: PathBuf, alg: String) {
    match alg.as_str() {
        "ed25519" => {
            use rand::rngs::OsRng;
            let key = ed25519_dalek::SigningKey::generate(&mut OsRng);
            let key_bytes = key.to_bytes();
            fs::write(&output, key_bytes).unwrap_or_else(|e| {
                eprintln!("Error writing key: {e}");
                process::exit(1);
            });
            // Write public key alongside
            let pub_path = output.with_extension("pub");
            let pub_bytes = key.verifying_key().to_bytes();
            fs::write(&pub_path, pub_bytes).unwrap_or_else(|e| {
                eprintln!("Error writing public key: {e}");
                process::exit(1);
            });
            println!("✓ Generated Ed25519 key pair");
            println!("  Private: {}", output.display());
            println!("  Public:  {}", pub_path.display());
        }
        "ecdsa" => {
            use rand::rngs::OsRng;
            let key = p256::ecdsa::SigningKey::random(&mut OsRng);
            let key_bytes = key.to_bytes();
            fs::write(&output, key_bytes).unwrap_or_else(|e| {
                eprintln!("Error writing key: {e}");
                process::exit(1);
            });
            let pub_path = output.with_extension("pub");
            let pub_bytes = key.verifying_key().to_encoded_point(false);
            fs::write(&pub_path, pub_bytes.as_bytes()).unwrap_or_else(|e| {
                eprintln!("Error writing public key: {e}");
                process::exit(1);
            });
            println!("✓ Generated ECDSA P-256 key pair");
            println!("  Private: {}", output.display());
            println!("  Public:  {}", pub_path.display());
        }
        other => {
            eprintln!("Unknown algorithm: {other}. Valid: ed25519, ecdsa");
            process::exit(1);
        }
    }
}

fn load_signing_key(key_bytes: &[u8]) -> cbc_transform::SigningKey {
    // Try Ed25519 first (32 bytes)
    if key_bytes.len() == 32 {
        let bytes: [u8; 32] = key_bytes.try_into().unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&bytes);
        return cbc_transform::SigningKey::Ed25519(key);
    }
    // Try ECDSA P-256 (typically 32 bytes for the scalar)
    if key_bytes.len() == 32 {
        // Ambiguous - default to Ed25519
        let bytes: [u8; 32] = key_bytes.try_into().unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&bytes);
        return cbc_transform::SigningKey::Ed25519(key);
    }
    // ECDSA P-256 scalar might be stored as GenericArray
    match p256::ecdsa::SigningKey::from_bytes(key_bytes.into()) {
        Ok(key) => cbc_transform::SigningKey::EcdsaP256(key),
        Err(_) => {
            eprintln!("Could not parse key file. Expected 32-byte Ed25519 or ECDSA P-256 key.");
            process::exit(1);
        }
    }
}
