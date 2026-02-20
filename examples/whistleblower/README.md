# Scenario: The Whistleblower (Verifiable Leak)

## 👤 The Persona

**Sarah**, an investigative journalist.

## 🌪️ The Challenge

Sarah has received a dump of sensitive documents. She needs to publish them but faces allegations that the documents are "deepfakes" or doctored. She must prove that the published files are bit-for-bit identical to the ones received from the source.

## 🛡️ The Solution

1. **Source**: Encodes the documents into a Cobalt Container (`.cbc`).
2. **Transfer**: The source sends the container and publishes the Merkle Root hash securely (e.g., Signal).
3. **Verification**: Sarah validates the container against the Root Hash.
4. **Publish**: Sarah publishes the `.cbc` file, allowing the public to independently verify the documents.

## 🚀 Run the Demo

```bash
./run_demo.sh
```
