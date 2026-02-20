# Scenario: The Autonomous Drone (Firmware Integrity)

## 👤 The Persona

**Nexus Dynamics**, a defense contractor operating drones in the Arctic Circle.

## 🌪️ The Challenge

Drones communicate via Iridium satellite (2.4 kbps). Sending a full 10MB update is risky; if it fails at 99%, the bandwidth cost is wasted. Adversaries may also try to inject malicious packets during the long transmission. The drone has minimal RAM and cannot buffer the whole file before verifying.

## 🛡️ The Solution

1. **Stream Encoding**: HQ encodes the firmware using a small block size (4KB).
2. **Bootstrap**: The drone receives the first 64 bytes (Bootstrap) and verifies the signature.
3. **Stream Verification**: The drone receives the update stream. Each 4KB block is verified individually against the Merkle Root *before* it is written to flash.
4. **Resilience**: If the connection drops, the drone can resume from the last verified block.

## 🚀 Run the Demo

```bash
./run_demo.sh
```
