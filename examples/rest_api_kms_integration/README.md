# Scenario: Enterprise Microservices (REST API & HashiCorp Vault Integration)

## 👤 The Persona

**Platform Architect** building a distributed microservice ecosystem.

## 🌪️ The Challenge

A constellation of decoupled microservices (Written in Node, Python, and Go) need to encode and validate cryptographic audit trails. However, giving every individual microservice direct access to the HashiCorp Vault transit keys is a massive violation of the Principle of Least Privilege.

## 🛡️ The Solution

1. **Centralized Authority:** The enterprise deploys `cbc-server` as an internal infrastructure primitive (similar to Redis or Kafka). It is the *sole* entity with Vault `transit/sign` ACLs.
2. **REST Delegation:** A Python billing microservice simply POSTs raw JSON data to `cbc-server`'s `/api/v1/encode` endpoint.
3. **KMS Signing:** `cbc-server` generates the Cobalt Block Container, asks Vault to sign the subrange extraction receipts, and returns the strictly immutable `.cbc` base64 back to the Python service.

## 🚀 Run the Demo

Requires Python 3.9+ and the `requests` library.

1. Ensure the `cbc-server` is running in another terminal:

   ```bash
   cd ../../cbc-server
   cargo run --release
   ```

2. Execute the microservice integration demo:

   ```bash
   python3 demo_microservice.py
   ```
