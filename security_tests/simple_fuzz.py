import os
import subprocess
import random
import shutil

valid_file = "valid.cbc"
mutation_dir = "fuzz_corpus"

if os.path.exists(mutation_dir):
    shutil.rmtree(mutation_dir)
os.makedirs(mutation_dir)

with open(valid_file, "rb") as f:
    base_data = bytearray(f.read())

print(f"Base file size: {len(base_data)}")

for i in range(50):
    mutated = base_data[:]
    
    mutation_type = random.choice(["flip", "truncate", "zero"])
    
    if mutation_type == "flip":
        pos = random.randint(0, len(mutated) - 1)
        val = mutated[pos]
        # Ensure we actually flip a bit
        flip = random.randint(1, 255)
        mutated[pos] = val ^ flip
        print(f"Mutant {i}: Flip byte {pos} ({val} -> {mutated[pos]})")
    elif mutation_type == "truncate":
        # Force strict truncation
        cut = random.randint(0, len(mutated) - 1) 
        mutated = mutated[:cut]
        print(f"Mutant {i}: Truncate to {len(mutated)} bytes")
    elif mutation_type == "zero":
        start = random.randint(0, len(mutated) - 1)
        length = random.randint(1, 100)
        end = min(start + length, len(mutated))
        # Ensure at least one byte changes
        changed = False
        for j in range(start, end):
            if mutated[j] != 0:
                mutated[j] = 0
                changed = True
            else:
                # If already zero, flip to 1 so it's a mutation
                mutated[j] = 1
                changed = True
        print(f"Mutant {i}: Zero/Flip range {start}-{end}")

    path = os.path.join(mutation_dir, f"mutant_{i}.cbc")
    with open(path, "wb") as f:
        f.write(mutated)
    
    result = subprocess.run(
        ["./target/release/cbc", "validate", "--input", path],
        capture_output=True,
        text=True
    )
    
    if result.returncode == 101: # Panic
        print(f"PANIC DETECTED on {path}!")
        print(result.stderr)
    elif result.returncode == 0:
        print(f"Unexpected VALID on {path}")
    else:
        # Expected failure (exit 1)
        pass

print("Fuzzing complete.")
