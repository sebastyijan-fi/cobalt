# Scenario: The Legal Archivist (Chain of Custody)

## 👤 The Persona

**Judge Miller**, overseeing a digital evidence archive.

## 🌪️ The Challenge

Digital evidence (bodycams, surveillance) is often moved, cropped, or transcoded. The defense challenges the integrity of a video file, claiming it was altered during processing. The court needs a mathematical way to prove that the file presented is a legitimate derivative of the original evidence collected at the scene.

## 🛡️ The Solution

1. **Ingestion**: The original evidence is encoded into a Cobalt Container (`.cbc`), generating a **Source Root**.
2. **Transformation**: When the file is cropped or redacted, Cobalt generates a **Transformation Receipt** that cryptographically links the new file to the Source Root.
3. **Verification**: The `inspect` command reveals the full Chain of Custody, proving the file's lineage.

## 🚀 Run the Demo

```bash
./run_demo.sh
```
