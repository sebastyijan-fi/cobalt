# Scenario: The AI Data Pipeline (Model Provenance)

## 👤 The Persona

**DataOps Team** at a regulated fintech company.

## 🌪️ The Challenge

Regulators demand extracting proof of which specific dataset version was used to train a credit scoring model. The team has 50TB of data and multiple versions (v1, v2, v2-clean). Detecting whether a "poisoned" or biased dataset was accidentally used is critical.

## 🛡️ The Solution

1. **Fingerprinting**: The training pipeline encodes the dataset into a `.cbc` artifact *before* training starts.
2. **Binding**: The Merger Root of the artifact is recorded in the model's metadata.
3. **Audit**: The regulator or internal auditor validates the artifact and checks for the presence of specific files (poisoned data) without needing to download the entire 50TB dataset.

## 🚀 Run the Demo

```bash
./run_demo.sh
```
