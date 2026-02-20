import os
import subprocess
import shutil

valid_file = "valid.cbc"
out_dir = "algo_corpus"

if os.path.exists(out_dir):
    shutil.rmtree(out_dir)
os.makedirs(out_dir)

with open(valid_file, "rb") as f:
    base_data = bytearray(f.read())

# Test 1: Invalid HashSuite (0)
bad_hash_0 = base_data[:]
bad_hash_0[6] = 0
with open(f"{out_dir}/bad_hash_0.cbc", "wb") as f:
    f.write(bad_hash_0)

# Test 2: Invalid HashSuite (255)
bad_hash_255 = base_data[:]
bad_hash_255[6] = 255
with open(f"{out_dir}/bad_hash_255.cbc", "wb") as f:
    f.write(bad_hash_255)

# Test 3: No Commitments (Mode 0)
no_commit = base_data[:]
no_commit[7] = 0
with open(f"{out_dir}/no_commit.cbc", "wb") as f:
    f.write(no_commit)

for fname in os.listdir(out_dir):
    path = os.path.join(out_dir, fname)
    print(f"Testing {fname}...")
    result = subprocess.run(
        ["./target/release/cbc", "validate", "-i", path],
        capture_output=True,
        text=True
    )
    if result.returncode == 101:
        print(f"PANIC on {fname}!")
    elif result.returncode == 0:
        print(f"Unexpected VALID on {fname}")
    else:
        print(f"Rejected {fname}: {result.stderr.strip()}")
