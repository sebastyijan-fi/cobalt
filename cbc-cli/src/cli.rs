use clap::{Parser, Subcommand};
use serde::Serialize;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "cbc",
    version = "0.1.0",
    about = "CBC (Context-Bound Container) v0.1 CLI"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Serialize)]
pub struct InspectionReport {
    pub file_size: u64,
    pub hash_suite: String,
    pub commitment_mode: String,
    pub block_payload_size: u32,
    pub block_count: u32,
    pub nonce: String,
    pub flags: Vec<String>,
    pub chain_root: Option<String>,
    pub merkle_root: Option<String>,
    pub payload_size: Option<usize>,
    pub receipts: Vec<ReceiptSummary>,
    pub validation: String,
}

#[derive(Serialize)]
pub struct ReceiptSummary {
    pub index: usize,
    pub source_root: String,
    pub derived_root: String,
    pub transform: String,
    pub timestamp: u64,
    pub sig_alg: String,
}

#[derive(Serialize)]
pub struct ValidationReport {
    pub valid: bool,
    pub status: String,
    pub blocks_verified: u32,
    pub total_blocks: Option<u32>,
    pub error: Option<String>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Encode file(s) into a CBC artifact
    Encode {
        /// Input file(s)
        #[arg(short, long, num_args = 1..)]
        input: Vec<PathBuf>,
        /// Output CBC artifact file
        #[arg(short, long)]
        output: PathBuf,
        /// Hash suite (blake3 or sha256)
        #[arg(long)]
        hash: Option<String>,
        /// Block payload size in bytes (must be power of 2, 512..=16MiB)
        #[arg(long)]
        block_size: Option<u32>,
        /// Comma-separated constraint families (A, A+B, A+B+C)
        #[arg(long)]
        families: Option<String>,
        /// Enable zstd compression
        #[arg(long)]
        compress: Option<bool>,
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
        /// Allow validation of partial chains (missing footer)
        #[arg(long)]
        partial: bool,
        /// Output validation report as JSON
        #[arg(long)]
        json: bool,
    },

    /// Inspect a CBC artifact and display metadata
    Inspect {
        /// Input CBC artifact file
        #[arg(short, long)]
        input: PathBuf,
        /// Output inspection report as JSON
        #[arg(long)]
        json: bool,
    },

    /// Extract a subrange from a CBC artifact (alias for transform --type subrange)
    Extract {
        /// Input CBC artifact file
        #[arg(short, long)]
        input: PathBuf,
        /// Output CBC artifact file
        #[arg(short, long)]
        output: PathBuf,
        /// Signing key (file path, @file, env:VAR, or hex)
        #[arg(short, long)]
        key: String,
        /// Start block index (inclusive)
        #[arg(long)]
        start: u32,
        /// End block index (inclusive)
        #[arg(long)]
        end: u32,
    },

    /// Decode payload to stdout (alias for decode -> stdout)
    Cat {
        /// Input CBC artifact file
        #[arg(short, long)]
        input: PathBuf,
        /// Decryption key (file path, @file, env:VAR, or hex)
        #[arg(long)]
        decrypt_key: Option<String>,
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
        #[arg(long)]
        hash: Option<String>,
        /// Block payload size in bytes (must be power of 2, 512..=16MiB)
        #[arg(long)]
        block_size: Option<u32>,
        /// Comma-separated constraint families (A, A+B, A+B+C)
        #[arg(long)]
        families: Option<String>,
        /// Enable zstd compression
        #[arg(long)]
        compress: Option<bool>,
        /// Encryption key (32 bytes as hex)
        #[arg(long)]
        encrypt_key: Option<String>,
    },

    /// Generate shell completions
    Completions {
        /// Shell to generate completions for (bash, fish, zsh, powershell, elvish)
        #[arg(long, default_value = "bash")]
        shell: String,
    },

    /// Analyze the environment and check for hardware acceleration
    Doctor,

    /// Run a performance benchmark on this hardware
    Bench {
        /// Hash suite to benchmark (blake3 or sha256)
        #[arg(long, default_value = "blake3")]
        hash: String,
        /// Data size in MB to process
        #[arg(long, default_value = "100")]
        size: usize,
    },

    /// Initialize a new Cobalt project
    Init {
        /// Project directory to create
        path: PathBuf,
    },

    /// Generate CI/CD workflow files
    Action {
        /// Type of workflow to generate (github)
        #[arg(long, default_value = "github")]
        r#type: String,
    },

    /// Watch a directory and automatically encode new/modified files
    Watch {
        /// Directory to watch
        #[arg(short, long, default_value = ".")]
        path: PathBuf,
    },
}

#[derive(Serialize, serde::Deserialize, Default)]
pub struct CbcConfig {
    #[serde(default)]
    pub defaults: DefaultsConfig,
}

#[derive(Serialize, serde::Deserialize, Default)]
pub struct DefaultsConfig {
    pub hash: Option<String>,
    pub block_size: Option<u32>,
    pub families: Option<String>,
    pub compress: Option<bool>,
}
