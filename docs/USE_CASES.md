# Sovereign Use Cases: Design Patterns for High-Stakes Integrity

To understand Cobalt is to understand the problems it solves—problems where "trust me" is not enough.

Below are four **Sovereign User Stories**, detailed narratives that demonstrate how Cobalt ensures integrity in adversarial environments.

---

## 1. The Whistleblower (Verifiable Leak)

### 👤 The Persona

**Sarah**, an investigative journalist for a global consortium. She has received a 500GB dump of incriminating PDF documents from an anonymous source inside a corrupt petrochemical giant.

### 🌪️ The Challenge

The corporation claims the documents are "doctored fakes." Sarah needs to prove that the files she publishes are bit-for-bit identical to the ones she received, without revealing her source's identity. She also needs to redact sensitive personal info (PII) from some files *without* breaking the chain of custody.

### 🛡️ The Cobalt Solution

**Step 1: The Source Embeds Truth**
Before sending the drive, the source runs `cbc encode`.

```bash
# Source encodes the dump, generating a Merkle Root
cbc encode -i ./leaked_docs/ -o corruption_scandal.cbc --hash blake3 --families A+B+C
```

The source publishes the **Merkle Root** (a tiny hash string) on a public blockchain or sends it to Sarah via Signal.

**Step 2: Sarah Verifies Receipt**
Sarah receives the drive. She validates it against the Root Hash.

```bash
cbc validate -i corruption_scandal.cbc
# Output: ✓ VALID. Root: 8f4b...
```

She now knows the files are authentic.

**Step 3: Redaction with Integrity**
Sarah needs to redact a specific page in `memo_12.pdf`. She extracts the file, redacts it, and re-encodes it. But to prove it's part of the original set, she uses Cobalt's **Transform** capability (Chain of Custody).

```bash
# Implementation Detail:
# In v0.1, Sarah would extract, redact, and re-encode.
# In future versions involved Receipt chaining.
cbc extract -i corruption_scandal.cbc -o memo_12.pdf --start 45 --end 46
# [Redact manual process]
# Sarah publishes the original hash and the redacted file, letting the public verify the unredacted parts match.
```

### 🔧 Technical Reality

Cobalt's **Family A (Merkle Tree)** ensures that every 64KB block is cryptographically committed. If the corporation claims malicious editing, Sarah can prove that the unredacted blocks mathematically belong to the original Root Hash published by the source.

---

## 2. The Autonomous Drone (Firmware Integrity)

### 👤 The Persona

**Nexus Dynamics**, a defense contractor operating distinct fleets of autonomous survey drones in remote, bandwidth-constrained environments (e.g., Arctic Circle).

### 🌪️ The Challenge

The drones connect via Iridium satellite (2.4 kbps). Sending a full 50MB firmware update is impossible if it fails at 99%. Worse, an adversary might try to inject a malicious block during transmission to hijack the drone.

### 🛡️ The Cobalt Solution

**Step 1: Stream-Encoding the Firmware**
The engineering team encodes the firmware `v2.0.bin`.

```bash
cbc stream-encode -i firmware_v2.0.bin -o fw_update.cbc --block-size 4096 --hash blake3
```

**Step 2: The "Bootstrap" Handshake**
The drone receives just the **Bootstrap Segment** (first 64 bytes) and verifies the signature from HQ. It now knows the Merkle Root of the update.

**Step 3: Trustless Formatting**
The drone requests blocks 0..N.

```rust
// On Drone (no_std):
let mut decoder = StreamingDecoder::new(root_hash);
for packet in satellite_link {
    // Each 4KB block is verified individually against the Merkle Root.
    // Malicious packets are rejected INSTANTLY, not at the end.
    decoder.feed_block(packet)?; 
    flash_memory.write(packet);
}
```

If the connection drops at 50%, the drone resumes from block 500 without restarting.

### 🔧 Technical Reality

Cobalt's **Family B (Block Commits)** puts the hash of every block into the stream. This allows **Streaming Verification**, essential for minimal RAM devices that cannot buffer the whole file.

---

## 3. The Legal Archivist (Chain of Custody)

### 👤 The Persona

**Judge Miller**, overseeing a high-profile digital evidence archive.

### 🌪️ The Challenge

Digital evidence (bodycam footage, surveillance logs) is often moved, copied, and compressed. The defense argues that the video was "compressed lossily" and important frames were altered or removed during the conversion.

### 🛡️ The Cobalt Solution

**Step 1: Ingestion with Provenance**
When the evidence enters the system, it is wrapped in an **Appendix** (Provenance Log).

```bash
cbc encode -i police_cam_01.mp4 -o evidence_001.cbc
```

**Step 2: Audit Logs**
Every time the file is accessed or transformed, a receipt is generated.

```bash
# Future feature: cbc transform --log "Compressed for court display" ...
```

**Step 3: Verification in Court**
The prosecution presents the file. The defense challenges it.

```bash
cbc inspect -i evidence_001.cbc
# Output:
# Merkle Root: 3a1f... (Matches original police report)
# Integrity:   VALID
```

The Judge sees that the **Merkle Root** matches the hash recorded at the crime scene. Integrity is absolute.

---

## 4. The AI Data Pipeline (Model Provenance)

### 👤 The Persona

**DataOps Team** at a regulated fintech company using LLMs for credit scoring.

### 🌪️ The Challenge

The model denies a loan. The regulators ask: "Which exact dataset version was this model trained on? Did it include the biased data we told you to remove?" The team has 50TB of training data versions and lost track.

### 🛡️ The Cobalt Solution

**Step 1: Dataset fingerprinting**
The training pipeline runs `cbc encode` on the dataset *before* training starts.

```bash
cbc encode -i ./clean_dataset_v4/ -o training_set_v4.cbc
```

**Step 2: Model Binding**
The training run ID is cryptographically linked to the `training_set_v4.cbc` Merkle Root.

**Step 3: Regulatory Audit**
The regulator audits the model. They pull the training artifact.

```bash
cbc validate -i training_set_v4.cbc
```

They check if the "biased_data.csv" file exists in the artifact.

```bash
cbc list -i training_set_v4.cbc | grep "biased_data.csv"
# Output: <empty>
```

The team proves mathematically that the biased data was **not** present in the training set used for that specific model version.

### 🔧 Technical Reality

By treating datasets as **Merkle-ized Artifacts**, Cobalt turns "version control" into "cryptographic proof." You don't just *think* you used v4; you can *prove* it.
