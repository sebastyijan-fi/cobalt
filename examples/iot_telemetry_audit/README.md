# Scenario: Enterprise IoT (Telemetry Audit & Immutable Firmware)

## 👤 The Persona

**IoT Fleet Manager** at a global logistics or renewable energy enterprise.

## 🌪️ The Challenge

Remote industrial sensors (e.g., wind turbines, cargo ships) communicate over high-latency, low-bandwidth satellite links (e.g., Iridium at 2.4 kbps). Pushing a 10MB firmware update is risky and expensive. Furthermore, streaming telemetry data back to HQ must be cryptographically protected against man-in-the-middle injection attacks without buffering the entire stream in the device's constrained RAM.

## 🛡️ The Solution

1. **Stream Encoding**: HQ encodes the firmware using a highly granular block size (4KB).
2. **Bootstrap Verification**: The remote IoT device receives the initial 64-byte Bootstrap and verifies the Enterprise KMS signature.
3. **Stream Verification**: The device receives the continuous update stream. Each 4KB block is verified individually against the Merkle Root *before* it is written to the flash partition.
4. **Resilience**: If the TCP connection drops, the device safely resumes appending from the last verified block boundary.

## 🚀 Run the Demo

```bash
./run_demo.sh
```
