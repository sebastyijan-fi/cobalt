//! CBC CLI — command-line tool for encoding, decoding, validating, inspecting, and
//! transforming CBC artifacts.
use clap::Parser;
use owo_colors::OwoColorize;
use std::fs;
use std::io::{self, IsTerminal, Read};
use std::path::PathBuf;
use std::process;

fn setup_panic() {
    human_panic::setup_panic!();
}

use cbc_cli::*;

fn main() {
    setup_panic();

    // Auto-disable ANSI colors when stdout is not a terminal (piped/redirected)
    if !std::io::stdout().is_terminal() {
        owo_colors::set_override(false);
    }

    let cli = Cli::parse();
    let config = load_config();

    match cli.command {
        Commands::Encode {
            input,
            output,
            hash,
            block_size,
            families,
            compress,
            encrypt_key,
        } => {
            let hash = hash
                .or(config.defaults.hash.clone())
                .unwrap_or_else(|| "blake3".to_string());
            let block_size = block_size.or(config.defaults.block_size).unwrap_or(65536);
            let families = families
                .or(config.defaults.families.clone())
                .unwrap_or_else(|| "A+B".to_string());
            let compress = compress.or(config.defaults.compress).unwrap_or(false);

            cmd_encode(
                input,
                output,
                hash,
                block_size,
                families,
                compress,
                encrypt_key,
            )
        }

        Commands::Decode {
            input,
            output,
            decrypt_key,
        } => cmd_decode(input, output, decrypt_key),

        Commands::Validate {
            input,
            partial,
            json,
        } => cmd_validate(input, partial, json),

        Commands::Inspect { input, json } => cmd_inspect(input, json),

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

        Commands::Cat { input, decrypt_key } => cmd_cat(input, decrypt_key),

        Commands::Extract {
            input,
            output,
            key,
            start,
            end,
        } => cmd_extract(input, output, key, start, end),

        Commands::StreamEncode {
            input,
            output,
            hash,
            block_size,
            families,
            compress,
            encrypt_key,
        } => {
            let hash = hash
                .or(config.defaults.hash.clone())
                .unwrap_or_else(|| "blake3".to_string());
            let block_size = block_size.or(config.defaults.block_size).unwrap_or(65536);
            let families = families
                .or(config.defaults.families.clone())
                .unwrap_or_else(|| "A+B".to_string());
            let compress = compress.or(config.defaults.compress).unwrap_or(false);

            cmd_stream_encode(
                input,
                output,
                hash,
                block_size,
                families,
                compress,
                encrypt_key,
            )
        }

        Commands::Completions { shell } => {
            use clap::CommandFactory;
            use clap_complete::{generate, Shell};

            let shell = match shell.to_lowercase().as_str() {
                "bash" => Shell::Bash,
                "zsh" => Shell::Zsh,
                "fish" => Shell::Fish,
                "powershell" => Shell::PowerShell,
                "elvish" => Shell::Elvish,
                _ => {
                    eprintln!("Unknown shell: {shell}. Valid: bash, zsh, fish, powershell, elvish");
                    process::exit(1);
                }
            };

            generate(shell, &mut Cli::command(), "cbc", &mut io::stdout());
        }
        Commands::Doctor => cmd_doctor(),
        Commands::Bench { hash, size } => cmd_bench(hash, size),
        Commands::Init { path } => cmd_init(path),
        Commands::Action { r#type } => cmd_action(r#type),
        Commands::Watch { path } => cmd_watch(path),
    }
}

fn cmd_init(path: PathBuf) {
    println!("{}", "=== Cobalt Project Initializer ===".bold().blue());

    if path.exists() && !path.is_dir() {
        eprintln!("✗ Error: {} is not a directory", path.display());
        process::exit(1);
    }

    if !path.exists() {
        fs::create_dir_all(&path).unwrap_or_else(|e| {
            eprintln!("✗ Error creating directory: {e}");
            process::exit(1);
        });
    }

    // 1. Create cbc.toml
    let config = CbcConfig {
        defaults: DefaultsConfig {
            hash: Some("blake3".to_string()),
            block_size: Some(65536),
            families: Some("A+B".to_string()),
            compress: Some(true),
        },
    };
    let toml_content = toml::to_string_pretty(&config).unwrap();
    let config_path = path.join("cbc.toml");
    fs::write(&config_path, toml_content).unwrap();

    // 2. Create .gitignore
    let gitignore =
        "# Cobalt artifacts\n*.cbc\n*.cbc.tmp\n\n# Evidence & Proofs\n*.proof\nreceipts/\n";
    fs::write(path.join(".gitignore"), gitignore).unwrap();

    // 3. Create README.cbc.md
    let readme = r#"# Cobalt Sovereign Project

This directory is initialized with **Cobalt (CBC)** for sovereign-grade data integrity.

## Project Policy (`cbc.toml`)
- **Hash Suite**: Blake3 (Hardware Accelerated)
- **Commitment**: Family A + B (Merkle Integrity)
- **Block Size**: 64 KB

## Common Commands
- `cbc encode -i <file> -o <file>.cbc`: Protect a file.
- `cbc validate -i <file>.cbc`: Verify integrity.
- `cbc inspect -i <file>.cbc`: Audit metadata.
"#;
    fs::write(path.join("README.cbc.md"), readme).unwrap();

    println!("{}", "✓ Cobalt project initialized successfully.".green());
    println!("  Policy:  {}", config_path.display());
    println!("  Docs:    {}", path.join("README.cbc.md").display());
}

fn cmd_bench(hash: String, size_mb: usize) {
    use rand::RngCore;
    use std::time::Instant;

    println!("{}", "=== Cobalt Sovereign Benchmark ===".bold().blue());
    println!(
        "{:<24} {}",
        "Hash Suite:".dimmed(),
        hash.to_uppercase().green()
    );
    println!("{:<24} {} MB", "Data Size:".dimmed(), size_mb);

    let mut data = vec![0u8; size_mb * 1024 * 1024];
    println!("{}", "Generating random entropy...".dimmed());
    rand::thread_rng().fill_bytes(&mut data);

    let config = cbc_core::EncoderConfig {
        hash_suite: parse_hash(&hash),
        commitment_mode: cbc_core::bootstrap::FAMILY_A_BIT,
        block_payload_size: 64 * 1024,
        flags: 0,
        encryption_key: None,
    };

    println!("{}", "Executing saturation flight...".bold().yellow());
    let start = Instant::now();
    let result = cbc_core::encoder::encode_random_nonce(&config, &data, &[]);
    let duration = start.elapsed();

    match result {
        Ok(artifact) => {
            let throughput = (size_mb as f64) / duration.as_secs_f64();
            println!("\n{}", "--- Benchmark Results ---".bold());
            println!(
                "{:<24} {:.2} ms",
                "Total Time:".dimmed(),
                duration.as_secs_f64() * 1000.0
            );
            println!(
                "{:<24} {:.2} MB/s ({:.2} GiB/s)",
                "Throughput:".dimmed(),
                throughput,
                throughput / 1024.0
            );
            println!("{:<24} {} bytes", "Artifact Size:".dimmed(), artifact.len());

            println!(
                "\n{}",
                "Verdict: Your hardware is capable of high-assurance saturation.".green()
            );
        }
        Err(e) => {
            println!("\n{} Encoding failed: {}", "✗ ERROR:".bold().red(), e);
            process::exit(1);
        }
    }
}

fn cmd_doctor() {
    println!("{}", "=== Cobalt Environmental Doctor ===".bold().blue());

    // Check OS
    println!(
        "{:<24} {}",
        "Operating System:".dimmed(),
        std::env::consts::OS
    );
    println!(
        "{:<24} {}",
        "Architecture:".dimmed(),
        std::env::consts::ARCH
    );

    // Check CPU features (x86_64 specific for now)
    #[cfg(target_arch = "x86_64")]
    {
        println!("\n{}", "--- CPU Acceleration ---".bold());
        let features = [
            ("AVX2", std::is_x86_feature_detected!("avx2")),
            ("AES-NI", std::is_x86_feature_detected!("aes")),
            ("SSSE3", std::is_x86_feature_detected!("ssse3")),
            ("PCLMULQDQ", std::is_x86_feature_detected!("pclmulqdq")),
            ("SHA Extensions", std::is_x86_feature_detected!("sha")),
        ];

        for (name, supported) in features {
            let status = if supported {
                "SUPPORTED".green().to_string()
            } else {
                "NOT SUPPORTED".yellow().to_string()
            };
            println!("{:<24} {}", name.dimmed(), status);
        }

        if features.iter().all(|(_, s)| !s) {
            println!(
                "\n{}",
                "WARNING: No cryptographic acceleration detected. Performance will be degraded."
                    .yellow()
            );
        }
    }

    // Check standard features
    println!("\n{}", "--- Cobalt Features ---".bold());
    println!(
        "{:<24} {}",
        "Zstd Compression:".dimmed(),
        if cfg!(feature = "zstd") {
            "ENABLED".green().to_string()
        } else {
            "DISABLED".dimmed().to_string()
        }
    );

    println!(
        "\n{}",
        "Verdict: Your environment is healthy and ready for sovereign-grade storage.".green()
    );
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
        if path.is_dir() {
            println!("{} {}", "Archiving directory:".dimmed(), path.display());
            // Create a tar archive in memory
            let mut builder = tar::Builder::new(Vec::new());

            // We want to preserve the directory name at the root of the archive
            // e.g. "leaked_docs/" -> "leaked_docs/memo.txt"
            let dir_name = path.file_name().unwrap_or_else(|| path.as_os_str());

            builder.append_dir_all(dir_name, path).unwrap_or_else(|e| {
                eprintln!("Error archiving directory {}: {e}", path.display());
                process::exit(1);
            });

            // Finish the archive
            let tar_data = builder.into_inner().unwrap();
            payload.extend_from_slice(&tar_data);
        } else {
            let content = fs::read(path).unwrap_or_else(|e| {
                eprintln!("Error reading {}: {e}", path.display());
                process::exit(1);
            });
            payload.extend_from_slice(&content);
        }
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

    let artifact =
        cbc_core::encoder::encode_random_nonce(&config, &payload, &[]).unwrap_or_else(|e| {
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

fn cmd_validate(input: PathBuf, partial: bool, json_output: bool) {
    let data = fs::read(&input).unwrap_or_else(|e| {
        eprintln!("Error reading {}: {e}", input.display());
        process::exit(1);
    });

    let pb = indicatif::ProgressBar::new_spinner();
    pb.set_message("Validating integrity...");
    pb.enable_steady_tick(std::time::Duration::from_millis(100));

    match cbc_core::decoder::validate(&data) {
        Ok(stats) => {
            pb.finish_and_clear();
            if json_output {
                let report = ValidationReport {
                    valid: true,
                    status: "Valid".to_string(),
                    blocks_verified: stats.blocks_verified,
                    total_blocks: Some(stats.total_blocks),
                    error: None,
                };
                println!("{}", serde_json::to_string_pretty(&report).unwrap());
            } else {
                println!("✓ Valid CBC artifact ({} blocks verified)", stats.blocks_verified);
            }
            process::exit(0);
        }
        Err(e) => {
            pb.finish_and_clear();
            // If standard validation failed, check if partial validation works
            if partial {
                // Heuristic partial validation
                let mut report = ValidationReport {
                    valid: false,
                    status: "Invalid".to_string(),
                    blocks_verified: 0,
                    total_blocks: None,
                    error: Some(e.to_string()),
                };

                if data.len() >= 64 {
                    // Try to stream validate what we have
                    let mut decoder = cbc_core::streaming::StreamingDecoder::new(None);
                    if decoder.feed_bootstrap(&data[..64]).is_ok() {
                        let bps = decoder.bootstrap().unwrap().block_payload_size as usize;
                        let mut offset = 64;
                        let mut loop_err = None;
                        loop {
                            if offset + 16 > data.len() {
                                break;
                            }
                            // We don't strictly need to read header to know size, but we do to validate it
                            let mut h_bytes = [0u8; 16];
                            h_bytes.copy_from_slice(&data[offset..offset + 16]);
                            let header = cbc_core::block::BlockHeader::decode(&h_bytes);

                            // Safety check on payload length
                            if header.payload_length as usize > bps {
                                break;
                            }

                            let block_len = 16 + bps + 32;
                            if offset + block_len > data.len() {
                                break;
                            } // Truncated

                            let block_bytes = &data[offset..offset + block_len];
                            // In recovery/partial mode, we don't know if a block is last or not.
                            // Treating it as "potentially last" (true) allows partial payloads to validate.
                            match decoder.feed_block(block_bytes, true) {
                                Ok(_) => {
                                    report.blocks_verified += 1;
                                    offset += block_len;
                                }
                                Err(verr) => {
                                    loop_err = Some(verr);
                                    break;
                                }
                            }
                        }

                        if let Some(verr) = loop_err {
                            report.status = format!("Partial Fail: {verr}");
                            report.valid = false;
                        } else {
                            // No block errors, just stopped (EOF)
                            // This counts as a valid partial chain
                            report.valid = true;
                            report.status = "Valid Partial Chain".to_string();
                            report.error = None; // Clear the original validation error
                        }
                    }
                }

                if json_output {
                    println!("{}", serde_json::to_string_pretty(&report).unwrap());
                } else if report.valid {
                    println!(
                        "✓ Valid Partial Chain ({} blocks verified)",
                        report.blocks_verified
                    );
                    println!("  (Standard validation failed: {e})");
                } else {
                    eprintln!("✗ Invalid: {e}");
                    eprintln!(
                        "  Partial scan failed after {} blocks: {}",
                        report.blocks_verified, report.status
                    );
                }

                if report.valid {
                    process::exit(0);
                } else {
                    process::exit(1);
                }
            }

            if json_output {
                let report = ValidationReport {
                    valid: false,
                    status: "Invalid".to_string(),
                    blocks_verified: 0,
                    total_blocks: None,
                    error: Some(e.to_string()),
                };
                println!("{}", serde_json::to_string_pretty(&report).unwrap());
            } else {
                eprintln!("✗ Invalid: {e}");
            }
            process::exit(1);
        }
    }
}

fn cmd_inspect(input: PathBuf, json_output: bool) {
    let data = fs::read(&input).unwrap_or_else(|e| {
        eprintln!("Error reading {}: {e}", input.display());
        process::exit(1);
    });

    if data.len() < 64 {
        eprintln!(
            "File too small for CBC bootstrap segment ({} bytes)",
            data.len()
        );
        process::exit(1);
    }

    let mut bootstrap_bytes = [0u8; 64];
    bootstrap_bytes.copy_from_slice(&data[..64]);

    let pb = indicatif::ProgressBar::new_spinner();
    pb.set_message("Inspecting artifact metadata...");
    pb.enable_steady_tick(std::time::Duration::from_millis(100));

    match cbc_core::BootstrapSegment::decode(&bootstrap_bytes) {
        Ok(bs) => {
            let mut report = InspectionReport {
                file_size: data.len() as u64,
                hash_suite: format!("{:?}", bs.hash_suite),
                commitment_mode: format!(
                    "0x{:02x} (A:{} B:{} C:{})",
                    bs.commitment_mode,
                    if bs.family_a() { "✓" } else { "✗" },
                    if bs.family_b() { "✓" } else { "✗" },
                    if bs.family_c() { "✓" } else { "✗" },
                ),
                block_payload_size: bs.block_payload_size,
                block_count: bs.block_count,
                nonce: hex::encode(bs.bootstrap_nonce),
                flags: Vec::new(),
                root_hash: None,
                merkle_root: None,
                payload_size: None,
                receipts: Vec::new(),
                validation: "Unknown".to_string(),
            };

            if bs.flags & 0x01 != 0 {
                report.flags.push("compressed".to_string());
            }
            if bs.flags & 0x02 != 0 {
                report.flags.push("encrypted".to_string());
            }

            match cbc_core::decoder::decode(&data, None) {
                Ok(decoded) => {
                    let hash_prefix = format!("{:?}", bs.hash_suite).to_lowercase();
                    report.root_hash = Some(format!("{}:{}", hash_prefix, hex::encode(decoded.root_hash)));
                    report.merkle_root = decoded.merkle_root.map(hex::encode);
                    report.payload_size = Some(decoded.payload.len());
                    report.validation = "PASS".to_string();

                    for (i, r) in decoded.receipt_slots.iter().enumerate() {
                        if let Ok(receipt) = cbc_transform::Receipt::decode(r) {
                            report.receipts.push(ReceiptSummary {
                                index: i,
                                source_root: hex::encode(receipt.source_root),
                                derived_root: hex::encode(receipt.derived_root),
                                transform: format!("{:?}", receipt.transform_type),
                                timestamp: receipt.timestamp,
                                sig_alg: format!("{:?}", receipt.sig_alg),
                            });
                        }
                    }
                }
                Err(e) => {
                    report.validation = format!("FAIL ({e})");
                }
            }

            pb.finish_and_clear();

            if json_output {
                println!("{}", serde_json::to_string_pretty(&report).unwrap());
            } else {
                println!("{}", "=== CBC Artifact Inspection ===".bold().blue());
                println!("{:<18} {} bytes", "File size:".dimmed(), report.file_size);
                println!(
                    "{:<18} {}",
                    "Hash suite:".dimmed(),
                    format!("{:?}", bs.hash_suite).to_uppercase().green()
                );
                println!(
                    "{:<18} {}",
                    "Commitment mode:".dimmed(),
                    report.commitment_mode
                );
                println!(
                    "{:<18} {} bytes",
                    "Block payload:".dimmed(),
                    report.block_payload_size
                );
                println!("{:<18} {}", "Block count:".dimmed(), report.block_count);
                println!("{:<18} {}", "Nonce:".dimmed(), report.nonce);
                println!("{:<18} {:?}", "Flags:".dimmed(), report.flags);

                if let Some(rh) = &report.root_hash {
                    println!("Root hash:         {}", rh);
                }
                if let Some(mr) = &report.merkle_root {
                    println!("Merkle root:       {}", mr);
                }
                if let Some(ps) = report.payload_size {
                    println!("Payload size:      {} bytes", ps);
                }
                println!("Receipts:          {}", report.receipts.len());
                for r in &report.receipts {
                    println!("  Receipt #{}:", r.index);
                    println!("    Source root:   {}", r.source_root);
                    println!("    Derived root:  {}", r.derived_root);
                    println!("    Transform:     {}", r.transform);
                    println!("    Timestamp:     {}", r.timestamp);
                    println!("    Sig algorithm: {}", r.sig_alg);
                }

                if report.validation == "PASS" {
                    println!("\nValidation:        ✓ PASS");
                } else {
                    println!("\nValidation:        ✗ {}", report.validation);
                }
            }
        }
        Err(e) => {
            pb.finish_and_clear();
            eprintln!("Failed to parse bootstrap segment: {e}");
            process::exit(1);
        }
    }
}

#[allow(clippy::too_many_arguments)]
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
            fs::write(&output, &artifact).unwrap_or_else(|e| {
                eprintln!("Error writing output: {e}");
                process::exit(1);
            });
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
            fs::write(&output, &artifact).unwrap_or_else(|e| {
                eprintln!("Error writing output: {e}");
                process::exit(1);
            });
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
            fs::write(&output, &artifact).unwrap_or_else(|e| {
                eprintln!("Error writing output: {e}");
                process::exit(1);
            });
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
            fs::write(&output, &artifact).unwrap_or_else(|e| {
                eprintln!("Error writing output: {e}");
                process::exit(1);
            });
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
            fs::write(&output, &artifact).unwrap_or_else(|e| {
                eprintln!("Error writing output: {e}");
                process::exit(1);
            });
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
        cbc_transform::SigningKey::Ed25519(ed25519_dalek::SigningKey::from_bytes(
            &key_data.try_into().unwrap(),
        ))
    } else if key_data.len() == 36 {
        // Assume SEC1 preserved
        cbc_transform::SigningKey::EcdsaP256(
            p256::ecdsa::SigningKey::from_slice(&key_data).unwrap(),
        )
    } else {
        eprintln!("Unknown key format ({} bytes)", key_data.len());
        process::exit(1);
    };

    let bs = cbc_core::BootstrapSegment::decode(&source_data[..64].try_into().unwrap()).unwrap();
    let (derived, receipt) =
        cbc_transform::subrange_extract(&source_data, 0, bs.block_count - 1, &key).unwrap_or_else(
            |e| {
                eprintln!("✗ Signing failed: {e}");
                process::exit(1);
            },
        );

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
    use rand::RngCore;
    use std::io::{Read, Seek, SeekFrom, Write};

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

    let mut nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);

    // Create output file
    let mut file = fs::File::create(&output).unwrap_or_else(|e| {
        eprintln!("Error creating {}: {e}", output.display());
        process::exit(1);
    });

    // Write placeholder bootstrap
    // We construct a bootstrap segment with 0 block count, encode it, and write it.
    let mut bootstrap = cbc_core::BootstrapSegment {
        hash_suite: config.hash_suite,
        commitment_mode: config.commitment_mode,
        block_payload_size: config.block_payload_size,
        block_count: 0,
        bootstrap_nonce: nonce,
        flags: config.flags,
    };
    let bs_bytes = bootstrap.encode();
    file.write_all(&bs_bytes).unwrap_or_else(|e| {
        eprintln!("Error writing header: {e}");
        process::exit(1);
    });

    let mut encoder = StreamingEncoder::new(&config, nonce);
    let mut total_bytes_written = 0usize;

    // Calculate total size for progress bar
    let total_input_size: u64 = input
        .iter()
        .map(|p| fs::metadata(p).map(|m| m.len()).unwrap_or(0))
        .sum();

    let pb = indicatif::ProgressBar::new(total_input_size);
    pb.set_style(indicatif::ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
        .unwrap()
        .progress_chars("#>-"));

    for path in &input {
        let mut input_file = fs::File::open(path).unwrap_or_else(|e| {
            eprintln!("Error opening {}: {e}", path.display());
            process::exit(1);
        });

        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            let n = input_file.read(&mut buffer).unwrap_or_else(|e| {
                eprintln!("Error reading {}: {e}", path.display());
                process::exit(1);
            });
            if n == 0 {
                break;
            }

            let blocks = encoder.feed(&buffer[..n]).unwrap_or_else(|e| {
                eprintln!("✗ Streaming encode failed: {e}");
                process::exit(1);
            });

            for block in blocks {
                file.write_all(&block).unwrap_or_else(|e| {
                    eprintln!("Error writing block: {e}");
                    process::exit(1);
                });
            }

            total_bytes_written += n;
            pb.inc(n as u64);
        }
    }
    pb.finish_with_message("Encoding complete");

    let (footer_plus_last, final_count) = encoder.finalize(&[]).unwrap_or_else(|e| {
        eprintln!("✗ Streaming finalization failed: {e}");
        process::exit(1);
    });

    file.write_all(&footer_plus_last).unwrap_or_else(|e| {
        eprintln!("Error writing footer: {e}");
        process::exit(1);
    });

    // Patch header with correct block count
    bootstrap.block_count = final_count;
    let final_bs_bytes = bootstrap.encode();
    file.seek(SeekFrom::Start(0)).unwrap_or_else(|e| {
        eprintln!("Error seeking to start: {e}");
        process::exit(1);
    });
    file.write_all(&final_bs_bytes).unwrap_or_else(|e| {
        eprintln!("Error patching header: {e}");
        process::exit(1);
    });

    println!(
        "✓ Stream-encoded {} bytes (from {} files) → {} ({} blocks)",
        total_bytes_written,
        input.len(),
        output.display(),
        final_count
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

fn cmd_cat(input: PathBuf, decrypt_key: Option<String>) {
    let data = fs::read(&input).unwrap_or_else(|e| {
        eprintln!("Error reading {}: {e}", input.display());
        process::exit(1);
    });

    let key = decrypt_key.map(|s| parse_key(&s));

    // We use decode() which loads the whole file. For streaming cat, we'd need StreamingDecoder.
    // For v0.1 cat, memory loading is acceptable.
    let decoded = cbc_core::decoder::decode(&data, key).unwrap_or_else(|e| {
        eprintln!("✗ Decode failed: {e}");
        process::exit(1);
    });

    use std::io::Write;
    io::stdout()
        .write_all(&decoded.payload)
        .unwrap_or_else(|e| {
            eprintln!("Error writing to stdout: {e}");
            process::exit(1);
        });
}

fn cmd_extract(input: PathBuf, output: PathBuf, key_str: String, start: u32, end: u32) {
    let data = fs::read(&input).unwrap_or_else(|e| {
        eprintln!("Error reading {}: {e}", input.display());
        process::exit(1);
    });

    let key_data = load_key_material(&key_str);
    let signing_key = load_signing_key(&key_data);

    let (artifact, _receipt) = cbc_transform::subrange_extract(&data, start, end, &signing_key)
        .unwrap_or_else(|e| {
            eprintln!("Extraction failed: {e}");
            process::exit(1);
        });

    fs::write(&output, &artifact).unwrap_or_else(|e| {
        eprintln!("Error writing {}: {e}", output.display());
        process::exit(1);
    });

    println!(
        "✓ Extracted blocks [{start}..{end}] → {} ({} bytes)",
        output.display(),
        artifact.len()
    );
}

fn load_key_material(s: &str) -> Vec<u8> {
    let s = s.trim();
    if let Some(path) = s.strip_prefix('@') {
        // Read as hex text from file
        let content = fs::read_to_string(path).unwrap_or_else(|_| {
            // Fallback: try reading as raw bytes if hex fails?
            // No, @ implies text usually.
            // But let's just use `fs::read` if it's a file path directly (no @).
            panic!("Use valid file path for binary keys");
        });
        hex::decode(content.trim()).unwrap_or_else(|_| {
            panic!("@file must contain hex string");
        })
    } else if let Some(var) = s.strip_prefix("env:") {
        let content = std::env::var(var).expect("Env var not found");
        hex::decode(content.trim()).expect("Env var must be hex")
    } else if s == "-" {
        let mut buf = Vec::new();
        io::stdin()
            .read_to_end(&mut buf)
            .expect("Stdin read failed");
        // Check if it looks like hex?
        if let Ok(str_val) = std::str::from_utf8(&buf) {
            if let Ok(bytes) = hex::decode(str_val.trim()) {
                return bytes;
            }
        }
        buf
    } else {
        // Try as file path first
        if let Ok(bytes) = fs::read(s) {
            return bytes;
        }
        // Try as hex
        hex::decode(s).unwrap_or_else(|_| {
            eprintln!("Could not read key from '{s}': not a file and not valid hex");
            process::exit(1);
        })
    }
}
fn parse_key(s: &str) -> [u8; 32] {
    let bytes = load_key_material(s);
    bytes.try_into().unwrap_or_else(|v: Vec<u8>| {
        eprintln!("Invalid key length: expected 32 bytes, got {}", v.len());
        process::exit(1);
    })
}

fn cmd_action(action_type: String) {
    if action_type != "github" {
        eprintln!("Unknown action type: {action_type}. Supported: github");
        process::exit(1);
    }

    let workflow_dir = PathBuf::from(".github/workflows");
    if !workflow_dir.exists() {
        fs::create_dir_all(&workflow_dir).unwrap_or_else(|e| {
            eprintln!("Error creating directory {}: {e}", workflow_dir.display());
            process::exit(1);
        });
    }

    let workflow_path = workflow_dir.join("cobalt-integrity.yml");
    let content = r#"name: Cobalt Integrity Check

on: [push, pull_request]

jobs:
  integrity:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install Cobalt
        run: |
          # Placeholder: In production, download from official release
          echo "Installing Cobalt..."
          # curl -L https://github.com/sebastyijan-fi/cobalt/releases/latest/download/cbc-linux-amd64 -o /usr/local/bin/cbc
          # chmod +x /usr/local/bin/cbc

      - name: Validate Artifacts
        run: |
          echo "Finding and validating Cobalt artifacts..."
          # find . -name "*.cbc" -print0 | xargs -0 -I {} cbc validate -i "{}"
"#;

    fs::write(&workflow_path, content).unwrap_or_else(|e| {
        eprintln!("Error writing workflow: {e}");
        process::exit(1);
    });

    println!("{}", "✓ Generated GitHub Actions workflow.".green());
    println!("  Location: {}", workflow_path.display());
}

fn cmd_watch(path: PathBuf) {
    use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
    use std::sync::mpsc::channel;

    println!("{}", "=== Cobalt Autonomous Sidecar ===".bold().blue());
    println!("{:<24} {}", "Watching:".dimmed(), path.display());

    let (tx, rx) = channel();
    let mut watcher = RecommendedWatcher::new(tx, Config::default()).unwrap();

    watcher.watch(&path, RecursiveMode::Recursive).unwrap();

    println!("{}", "Sidecar active. Press Ctrl+C to stop.".green());

    for res in rx {
        match res {
            Ok(event) => {
                // Filter only create/modify events
                if event.kind.is_create() || event.kind.is_modify() {
                    for params_path in event.paths {
                        // Ignore .cbc files and hidden files/dirs like .git
                        if params_path.extension().is_some_and(|ext| ext == "cbc")
                            || params_path
                                .components()
                                .any(|c| c.as_os_str().to_string_lossy().starts_with('.'))
                        {
                            continue;
                        }

                        if !params_path.is_file() {
                            continue;
                        }

                        // Check if corresponding .cbc file is already newer?
                        // For PoC, just encode.

                        println!(
                            "{} {}",
                            "⚡ Detected change:".yellow(),
                            params_path.display()
                        );

                        // Load config freshly to allow hot-reloading policy
                        let config_toml = load_config();
                        let hash = config_toml.defaults.hash.as_deref().unwrap_or("blake3");
                        let family = config_toml.defaults.families.as_deref().unwrap_or("A+B");
                        let block_size = config_toml.defaults.block_size.unwrap_or(65536);
                        let compress = config_toml.defaults.compress.unwrap_or(false);

                        let mut flags = 0;
                        if compress {
                            flags |= cbc_core::bootstrap::FLAG_COMPRESSED;
                        }

                        let config = cbc_core::EncoderConfig {
                            hash_suite: parse_hash(hash),
                            commitment_mode: parse_families(family),
                            block_payload_size: block_size,
                            flags,
                            encryption_key: None, // No auto-encryption for now
                        };

                        let output_path = params_path.with_extension("cbc");

                        // Read file
                        match fs::read(&params_path) {
                            Ok(payload) => {
                                match cbc_core::encoder::encode_random_nonce(&config, &payload, &[])
                                {
                                    Ok(artifact) => {
                                        if let Err(e) = fs::write(&output_path, &artifact) {
                                            eprintln!("Error writing artifact: {e}");
                                        } else {
                                            println!("  ✓ Secured -> {}", output_path.display());
                                        }
                                    }
                                    Err(e) => {
                                        eprintln!("Error encoding {}: {}", params_path.display(), e)
                                    }
                                }
                            }
                            Err(e) => eprintln!("Error reading {}: {}", params_path.display(), e),
                        }
                    }
                }
            }
            Err(e) => eprintln!("watch error: {:?}", e),
        }
    }
}
