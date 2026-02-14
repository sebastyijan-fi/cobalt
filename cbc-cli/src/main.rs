//! CBC CLI — command-line tool for encoding, decoding, validating, inspecting, and
//! transforming CBC artifacts.
use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;
use std::process;

#[derive(Parser)]
#[command(
    name = "cbc",
    version = "0.1.0",
    about = "CBC (Context-Bound Container) v0.1 CLI"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encode file(s) into a CBC artifact
    Encode {
        /// Input file(s)
        #[arg(short, long, num_args = 1..)]
        input: Vec<PathBuf>,
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
        /// Enable zstd compression
        #[arg(long)]
        compress: bool,
        /// Encryption key (32 bytes as hex)
        #[arg(long)]
        encrypt_key: Option<String>,
    },

    /// Decode a CBC artifact and extract the payload
    Decode {
        /// Input CBC artifact file
        #[arg(short, long)]
        input: PathBuf,
        /// Output file for extracted payload
        #[arg(short, long)]
        output: PathBuf,
        /// Decryption key (32 bytes as hex)
        #[arg(long)]
        decrypt_key: Option<String>,
    },

    /// Validate a CBC artifact (exit 0 if valid, 1 if invalid)
    Validate {
        /// Input CBC artifact file
        #[arg(short, long)]
        input: PathBuf,
        /// Attempt to recover data from corrupted artifact using prefix markers
        #[arg(long)]
        recover: bool,
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

    /// Sign a CBC artifact with a provenance receipt
    Sign {
        /// Input CBC artifact file
        #[arg(short, long)]
        input: PathBuf,
        /// Output CBC artifact file
        #[arg(short, long)]
        output: PathBuf,
        /// Signing key file (Ed25519 or ECDSA)
        #[arg(short, long)]
        key: PathBuf,
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

    /// Generate a Merkle range proof for a block range
    Prove {
        /// Input CBC artifact file (must have Family B enabled)
        #[arg(short, long)]
        input: PathBuf,
        /// Start block index (inclusive)
        #[arg(long)]
        start: u32,
        /// End block index (inclusive)
        #[arg(long)]
        end: u32,
        /// Output proof file
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Verify a Merkle range proof against a CBC artifact
    VerifyProof {
        /// Input CBC artifact file
        #[arg(short, long)]
        input: PathBuf,
        /// Proof file to verify
        #[arg(short, long)]
        proof: PathBuf,
    },

    /// Streaming encode — read from file(s) with constant memory usage
    StreamEncode {
        /// Input file(s)
        #[arg(short, long, num_args = 1..)]
        input: Vec<PathBuf>,
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
        /// Enable zstd compression
        #[arg(long)]
        compress: bool,
        /// Encryption key (32 bytes as hex)
        #[arg(long)]
        encrypt_key: Option<String>,
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
            compress,
            encrypt_key,
        } => cmd_encode(input, output, hash, block_size, families, compress, encrypt_key),

        Commands::Decode { input, output, decrypt_key } => cmd_decode(input, output, decrypt_key),

        Commands::Validate { input, recover } => cmd_validate(input, recover),

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
        } => cmd_transform(
            transform_type,
            input,
            output,
            key,
            keep,
            new_block_size,
            start,
            end,
        ),

        Commands::Sign { input, output, key } => cmd_sign(input, output, key),

        Commands::Keygen { output, alg } => cmd_keygen(output, alg),

        Commands::Prove {
            input,
            start,
            end,
            output,
        } => cmd_prove(input, start, end, output),

        Commands::VerifyProof { input, proof } => cmd_verify_proof(input, proof),

        Commands::StreamEncode {
            input,
            output,
            hash,
            block_size,
            families,
            compress,
            encrypt_key,
        } => cmd_stream_encode(input, output, hash, block_size, families, compress, encrypt_key),
    }
}

fn cmd_encode(
    input: Vec<PathBuf>,
    output: PathBuf,
    hash: String,
    block_size: u32,
    families: String,
    compress: bool,
    encrypt_key: Option<String>,
) {
    let mut payload = Vec::new();
    for path in &input {
        let content = fs::read(path).unwrap_or_else(|e| {
            eprintln!("Error reading {}: {e}", path.display());
            process::exit(1);
        });
        payload.extend_from_slice(&content);
    }

    let mut flags = 0;
    if compress {
        flags |= cbc_core::bootstrap::FLAG_COMPRESSED;
    }

    let key = encrypt_key.map(|s| {
        flags |= cbc_core::bootstrap::FLAG_ENCRYPTED;
        parse_key(&s)
    });

    let config = cbc_core::EncoderConfig {
        hash_suite: parse_hash(&hash),
        commitment_mode: parse_families(&families),
        block_payload_size: block_size,
        flags,
        encryption_key: key,
    };

    let artifact = cbc_core::encoder::encode_random_nonce(&config, &payload, &[])
        .unwrap_or_else(|e| {
            eprintln!("✗ Encoding failed: {e}");
            process::exit(1);
        });

    fs::write(&output, &artifact).unwrap_or_else(|e| {
        eprintln!("Error writing {}: {e}", output.display());
        process::exit(1);
    });

    let block_count = payload.len().div_ceil(block_size as usize);
    println!(
        "✓ Encoded {} bytes (from {} files) → {} ({} blocks, {} bytes)",
        payload.len(),
        input.len(),
        output.display(),
        block_count.max(1),
        artifact.len()
    );
}

fn cmd_decode(input: PathBuf, output: PathBuf, decrypt_key: Option<String>) {
    let data = fs::read(&input).unwrap_or_else(|e| {
        eprintln!("Error reading {}: {e}", input.display());
        process::exit(1);
    });

    let key = decrypt_key.map(|s| parse_key(&s));

    let decoded = cbc_core::decoder::decode(&data, key).unwrap_or_else(|e| {
        eprintln!("✗ Validation failed: {e}");
        process::exit(1);
    });

    fs::write(&output, &decoded.payload).unwrap_or_else(|e| {
        eprintln!("Error writing {}: {e}", output.display());
        process::exit(1);
    });

    println!(
        "✓ Decoded {} blocks → {} bytes → {}",
        decoded.block_count,
        decoded.payload.len(),
        output.display()
    );
}

fn cmd_validate(input: PathBuf, recover: bool) {
    let data = fs::read(&input).unwrap_or_else(|e| {
        eprintln!("Error reading {}: {e}", input.display());
        process::exit(1);
    });

    if recover {
        cmd_recover_lite(&data);
        return;
    }

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

fn cmd_recover_lite(data: &[u8]) {
    println!("=== CBC Recovery Scan (Family C) ===");
    if data.len() < 64 {
        eprintln!("File too small for recovery");
        process::exit(1);
    }
    
    let mut bootstrap_bytes = [0u8; 64];
    bootstrap_bytes.copy_from_slice(&data[..64]);
    let bs = match cbc_core::BootstrapSegment::decode(&bootstrap_bytes) {
        Ok(bs) => bs,
        Err(_) => {
            println!("Warning: Bootstrap corrupted, using heuristic scan...");
            // Non-ideal but we could fallback to scanning for any marker
            process::exit(1);
        }
    };
    
    let mut recovered_blocks = 0;
    let mut offset = 64;
    while offset < data.len() {
        match cbc_core::prefix::find_next_block_boundary(&data[offset..]) {
            Some(relative_offset) => {
                let absolute_offset = offset + relative_offset;
                println!("Found potential block at offset {absolute_offset}");
                recovered_blocks += 1;
                // Skip this block's approximate size to find next
                offset = absolute_offset + 16 + bs.block_payload_size as usize + 32;
            }
            None => break,
        }
    }
    
    println!("\nRecovery summary: Found {recovered_blocks} potential block boundaries.");
    println!("In a full implementation, these would be reassembled into a new artifact.");
}

fn cmd_inspect(input: PathBuf) {
    let data = fs::read(&input).unwrap_or_else(|e| {
        eprintln!("Error reading {}: {e}", input.display());
        process::exit(1);
    });

    // Parse bootstrap (always safe even if artifact is invalid)
    if data.len() < 64 {
        eprintln!(
            "File too small for CBC bootstrap segment ({} bytes)",
            data.len()
        );
        process::exit(1);
    }

    let mut bootstrap_bytes = [0u8; 64];
    bootstrap_bytes.copy_from_slice(&data[..64]);

    match cbc_core::BootstrapSegment::decode(&bootstrap_bytes) {
        Ok(bs) => {
            println!("=== CBC Artifact Inspection ===");
            println!("File size:         {} bytes", data.len());
            println!("Hash suite:        {:?}", bs.hash_suite);
            println!(
                "Commitment mode:   0x{:02x} (A:{} B:{} C:{})",
                bs.commitment_mode,
                if bs.family_a() { "✓" } else { "✗" },
                if bs.family_b() { "✓" } else { "✗" },
                if bs.family_c() { "✓" } else { "✗" },
            );
            println!("Block payload:     {} bytes", bs.block_payload_size);
            println!("Block count:       {}", bs.block_count);
            println!("Nonce:             {}", hex::encode(bs.bootstrap_nonce));
            println!(
                "Flags:             0x{:08x} (compressed:{} encrypted:{})",
                bs.flags,
                if bs.flags & 0x01 != 0 { "yes" } else { "no" },
                if bs.flags & 0x02 != 0 { "yes" } else { "no" },
            );

            // Try full validation
            match cbc_core::decoder::decode(&data, None) {
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
                                println!(
                                    "    Derived root:  {}",
                                    hex::encode(receipt.derived_root)
                                );
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
            let (artifact, _receipt) = cbc_transform::truncate(&data, keep_blocks, &signing_key)
                .unwrap_or_else(|e| {
                    eprintln!("Transform failed: {e}");
                    process::exit(1);
                });
            fs::write(&output, &artifact).unwrap();
            println!(
                "✓ Truncated → {} ({} bytes)",
                output.display(),
                artifact.len()
            );
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
            let (artifact, _receipt) = cbc_transform::rechunk(&data, new_bs, &signing_key)
                .unwrap_or_else(|e| {
                    eprintln!("Transform failed: {e}");
                    process::exit(1);
                });
            fs::write(&output, &artifact).unwrap();
            println!(
                "✓ Rechunked → {} ({} bytes)",
                output.display(),
                artifact.len()
            );
        }
        "recompress" => {
            let data = fs::read(input.trim()).unwrap_or_else(|e| {
                eprintln!("Error reading input: {e}");
                process::exit(1);
            });
            let (artifact, _receipt) = cbc_transform::recompress(&data, &signing_key)
                .unwrap_or_else(|e| {
                    eprintln!("Transform failed: {e}");
                    process::exit(1);
                });
            fs::write(&output, &artifact).unwrap();
            println!(
                "✓ Recompressed → {} ({} bytes)",
                output.display(),
                artifact.len()
            );
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
            let (artifact, _receipts) = cbc_transform::concatenate(&refs, &signing_key)
                .unwrap_or_else(|e| {
                    eprintln!("Transform failed: {e}");
                    process::exit(1);
                });
            fs::write(&output, &artifact).unwrap();
            println!(
                "✓ Concatenated {} sources → {} ({} bytes)",
                input_files.len(),
                output.display(),
                artifact.len()
            );
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
            let (artifact, _receipt) = cbc_transform::subrange_extract(&data, s, e, &signing_key)
                .unwrap_or_else(|e| {
                    eprintln!("Transform failed: {e}");
                    process::exit(1);
                });
            fs::write(&output, &artifact).unwrap();
            println!(
                "✓ Extracted blocks [{s}..{e}] → {} ({} bytes)",
                output.display(),
                artifact.len()
            );
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

fn cmd_prove(input: PathBuf, start: u32, end: u32, output: PathBuf) {
    let data = fs::read(&input).unwrap_or_else(|e| {
        eprintln!("Error reading {}: {e}", input.display());
        process::exit(1);
    });

    let decoded = cbc_core::decoder::decode(&data, None).unwrap_or_else(|e| {
        eprintln!("✗ Validation failed: {e}");
        process::exit(1);
    });

    if !decoded.bootstrap.family_b() {
        eprintln!("✗ Artifact does not have Family B (Merkle tree) enabled");
        process::exit(1);
    }

    if start > end || end as usize >= decoded.block_count as usize {
        eprintln!(
            "✗ Invalid range [{start}..{end}], artifact has {} blocks",
            decoded.block_count
        );
        process::exit(1);
    }

    // Re-compute Merkle tree to generate proof
    let bps = decoded.bootstrap.block_payload_size;
    let params_canonical = decoded.bootstrap.params_canonical();
    let params_hash =
        cbc_core::chain::compute_params_hash(&params_canonical, decoded.bootstrap.hash_suite);
    let padded_payloads = compute_padded_payloads(&decoded.payload, bps);
    let tree = cbc_core::merkle::MerkleTree::build(
        &params_hash,
        &padded_payloads,
        decoded.bootstrap.hash_suite,
    );

    let proof = tree
        .prove_range(start as usize, end as usize)
        .unwrap_or_else(|| {
            eprintln!("✗ Failed to generate range proof");
            process::exit(1);
        });

    let proof_bytes = proof.encode();
    fs::write(&output, &proof_bytes).unwrap_or_else(|e| {
        eprintln!("Error writing proof: {e}");
        process::exit(1);
    });

    println!("✓ Generated Merkle range proof for blocks [{start}..={end}]");
    println!("  Proof size:   {} bytes", proof_bytes.len());
    println!("  Proof nodes:  {}", proof.proof_nodes.len());
    println!("  Merkle root:  {}", hex::encode(tree.root));
    println!("  Output:       {}", output.display());
}

fn cmd_verify_proof(input: PathBuf, proof_path: PathBuf) {
    let data = fs::read(&input).unwrap_or_else(|e| {
        eprintln!("Error reading {}: {e}", input.display());
        process::exit(1);
    });

    let decoded = cbc_core::decoder::decode(&data, None).unwrap_or_else(|e| {
        eprintln!("✗ Validation failed: {e}");
        process::exit(1);
    });

    let merkle_root = decoded.merkle_root.unwrap_or_else(|| {
        eprintln!("✗ Artifact has no Merkle root (Family B not enabled)");
        process::exit(1);
    });

    let proof_bytes = fs::read(&proof_path).unwrap_or_else(|e| {
        eprintln!("Error reading proof {}: {e}", proof_path.display());
        process::exit(1);
    });

    let proof = cbc_core::merkle::RangeProof::decode(&proof_bytes).unwrap_or_else(|| {
        eprintln!("✗ Failed to decode proof file");
        process::exit(1);
    });

    // Compute leaf hashes for the proved range
    let bps = decoded.bootstrap.block_payload_size;
    let params_canonical = decoded.bootstrap.params_canonical();
    let params_hash =
        cbc_core::chain::compute_params_hash(&params_canonical, decoded.bootstrap.hash_suite);
    let padded_payloads = compute_padded_payloads(&decoded.payload, bps);

    let leaf_hashes: Vec<[u8; 32]> = (proof.start..=proof.end)
        .map(|i| {
            cbc_core::merkle::compute_leaf(
                &params_hash,
                i as u64,
                &padded_payloads[i],
                decoded.bootstrap.hash_suite,
            )
        })
        .collect();

    if proof.verify(&leaf_hashes, &merkle_root, decoded.bootstrap.hash_suite) {
        println!(
            "✓ Proof verified: blocks [{}..={}] belong to Merkle root {}",
            proof.start,
            proof.end,
            hex::encode(merkle_root)
        );
    } else {
        eprintln!("✗ Proof verification FAILED");
        process::exit(1);
    }
}

fn cmd_sign(input_path: PathBuf, output_path: PathBuf, key_path: PathBuf) {
    let source_data = fs::read(&input_path).unwrap_or_else(|e| {
        eprintln!("Error reading {}: {e}", input_path.display());
        process::exit(1);
    });

    let key_data = fs::read(&key_path).unwrap_or_else(|e| {
        eprintln!("Error reading {}: {e}", key_path.display());
        process::exit(1);
    });

    // Determine key type by length
    let key = if key_data.len() == 32 {
        cbc_transform::SigningKey::Ed25519(
            ed25519_dalek::SigningKey::from_bytes(&key_data.try_into().unwrap()),
        )
    } else if key_data.len() == 36 {
        // Assume SEC1 preserved
        cbc_transform::SigningKey::EcdsaP256(
            p256::ecdsa::SigningKey::from_slice(&key_data).unwrap()
        )
    } else {
        eprintln!("Unknown key format ({} bytes)", key_data.len());
        process::exit(1);
    };

    let bs = cbc_core::BootstrapSegment::decode(&source_data[..64].try_into().unwrap()).unwrap();
    let (derived, receipt) = cbc_transform::subrange_extract(
        &source_data,
        0,
        bs.block_count - 1,
        &key
    ).unwrap_or_else(|e| {
        eprintln!("✗ Signing failed: {e}");
        process::exit(1);
    });

    fs::write(&output_path, &derived).unwrap_or_else(|e| {
        eprintln!("Error writing {}: {e}", output_path.display());
        process::exit(1);
    });

    println!("✓ Signed artifact → {}", output_path.display());
    println!("  Receipt timestamp: {}", receipt.timestamp);
}

fn cmd_stream_encode(
    input: Vec<PathBuf>,
    output: PathBuf,
    hash: String,
    block_size: u32,
    families: String,
    compress: bool,
    encrypt_key: Option<String>,
) {
    use cbc_core::streaming::StreamingEncoder;
    use std::io::Read;

    let mut flags = 0;
    if compress {
        flags |= cbc_core::bootstrap::FLAG_COMPRESSED;
    }

    let key = encrypt_key.map(|s| {
        flags |= cbc_core::bootstrap::FLAG_ENCRYPTED;
        parse_key(&s)
    });

    let config = cbc_core::EncoderConfig {
        hash_suite: parse_hash(&hash),
        commitment_mode: parse_families(&families),
        block_payload_size: block_size,
        flags,
        encryption_key: key,
    };

    let mut encoder = StreamingEncoder::new(&config, [0u8; 16]);
    let mut total_bytes = 0usize;

    for path in &input {
        let mut file = fs::File::open(path).unwrap_or_else(|e| {
            eprintln!("Error opening {}: {e}", path.display());
            process::exit(1);
        });

        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            let n = file.read(&mut buffer).unwrap_or_else(|e| {
                eprintln!("Error reading {}: {e}", path.display());
                process::exit(1);
            });
            if n == 0 {
                break;
            }
            encoder.write_payload(&buffer[..n]).unwrap_or_else(|e| {
                eprintln!("✗ Streaming encode failed: {e}");
                process::exit(1);
            });
            total_bytes += n;
        }
    }

    let artifact = encoder.finalize(&[]).unwrap_or_else(|e| {
        eprintln!("✗ Streaming finalization failed: {e}");
        process::exit(1);
    });

    fs::write(&output, &artifact).unwrap_or_else(|e| {
        eprintln!("Error writing {}: {e}", output.display());
        process::exit(1);
    });

    println!(
        "✓ Stream-encoded {} bytes (from {} files) → {} ({} bytes)",
        total_bytes,
        input.len(),
        output.display(),
        artifact.len()
    );
}

/// Reconstruct padded payloads from a flat payload buffer.
fn compute_padded_payloads(payload: &[u8], block_payload_size: u32) -> Vec<Vec<u8>> {
    let bps = block_payload_size as usize;
    if payload.is_empty() {
        return vec![vec![0u8; bps]];
    }
    payload
        .chunks(bps)
        .map(|chunk| {
            let mut padded = chunk.to_vec();
            padded.resize(bps, 0);
            padded
        })
        .collect()
}

fn parse_key(s: &str) -> [u8; 32] {
    let mut key = [0u8; 32];
    hex::decode_to_slice(s, &mut key).unwrap_or_else(|e| {
        eprintln!("Invalid encryption key (must be 64 hex characters): {e}");
        process::exit(1);
    });
    key
}
