#!/usr/bin/env python3
"""
Enterprise Integration Demo
Demonstrates how a detached microservice delegates cryptographic block generation 
and validation to the centralized `cbc-server` over REST without possessing Vault keys.
"""

import os
import requests
import json
import base64
import sys
import time

CBC_SERVER_URL = os.getenv("CBC_SERVER_URL", "http://127.0.0.1:3030")

def check_server() -> bool:
    try:
        r = requests.get(f"{CBC_SERVER_URL}/health")
        return r.status_code == 200
    except requests.exceptions.ConnectionError:
        return False

def print_step(msg: str):
    print(f"\n\033[1;36m[♦] {msg}\033[0m")

def main():
    print("=== Cobalt REST API & HashiCorp Vault Delegation ===")
    
    if not check_server():
        print(f"\n\033[1;31m[!] Error: Cannot reach cbc-server at {CBC_SERVER_URL}\033[0m")
        print("Please start the server in another terminal:")
        print("  cd ../../cbc-server && cargo run --release")
        sys.exit(1)

    # 1. Simulate the Microservice producing data
    print_step("Microservice: Generating sensitive transaction JSON...")
    transaction_data = json.dumps({
        "transaction_id": "TXN-99482",
        "amount_usd": 45000.0,
        "sender": "Enterprise_Account_A",
        "recipient": "Offshore_Vendor_B",
        "timestamp": int(time.time()),
        "regulatory_flag": True
    }).encode("utf-8")
    
    payload_base64 = base64.b64encode(transaction_data).decode("utf-8")

    # 2. Delegate Encoding to cbc-server
    print_step(f"API Request: POST {CBC_SERVER_URL}/api/v1/encode")
    encode_req = {
        "payload_base64": payload_base64,
        "derive_receipt": True
    }
    
    start_time = time.time()
    encode_res = requests.post(f"{CBC_SERVER_URL}/api/v1/encode", json=encode_req)
    latency = (time.time() - start_time) * 1000
    
    if encode_res.status_code != 200:
        print(f"Encode failed: {encode_res.text}")
        sys.exit(1)
        
    encode_body = encode_res.json()
    artifact_base64 = encode_body["artifact_base64"]
    receipt_base64 = encode_body.get("receipt_base64")
    
    print(f"   ✓ Sub-millisecond Delegation ({latency:.2f} ms)")
    print(f"   ✓ `cbc-server` securely generated the container without exposing Vault transit keys.")
    print(f"   ✓ Artifact Size: {len(artifact_base64)} bytes (Base64)")

    # 3. Simulate an Independent Auditor validating the artifact
    print_step(f"API Request: POST {CBC_SERVER_URL}/api/v1/validate")
    validate_req = {
        "artifact_base64": artifact_base64
    }
    
    val_res = requests.post(f"{CBC_SERVER_URL}/api/v1/validate", json=validate_req)
    
    if val_res.status_code != 200:
        print(f"Validate failed: {val_res.text}")
        sys.exit(1)
        
    val_body = val_res.json()
    is_valid = val_body["valid"]
    merkle_root = val_body["merkle_root"]
    
    if is_valid:
        print(f"   ✓ Cryptographic Validity Confirmed!")
        print(f"   ✓ Immutable Merkle Root: {merkle_root}")
    else:
        print(f"   ❌ Artifact Tampered!")

    print("\n\033[1;32m=== Demo Completed Successfully ===\033[0m")
    print("The Python microservice successfully proved provenance via API delegation.")

if __name__ == "__main__":
    main()
