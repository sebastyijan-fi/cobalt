import os
import subprocess
import struct

out_dir = "overflow_corpus"
if not os.path.exists(out_dir):
    os.makedirs(out_dir)

def create_artifact(name, count, payload_size):
    # MAGIC: CBC1 (0x43 0x42 0x43 0x31)
    magic = b'CBC1'
    version = struct.pack('<H', 1)
    hash_suite = b'\x01' # Blake3
    commit_mode = b'\x01' # Family A
    bs_payload_size = struct.pack('<I', payload_size)
    bs_count = struct.pack('<I', count)
    nonce = b'\x00' * 16
    flags = struct.pack('<I', 0)
    reserved = struct.pack('<I', 0)
    # We leave MAC empty or random, we want to see if parser calculation crashes
    # BEFORE MAC check (or if MAC check itself crashes)
    # Actually, decode() checks bootstrap MAC first. 
    # To bypass MAC check and hit the logic, we ideally need a valid MAC.
    # But writing a valid MAC requires re-implementing the hash logic in Python.
    # HOWEVER, the overflow vulnerability I suspect happens *after* bootstrap decode, 
    # but *before* verifying blocks.
    # Wait, `BootstrapSegment::decode` verifies CRC/MAC of the *bootstrap*? 
    # No, `BootstrapSegment` structure is:
    # 64 bytes.
    # `bootstrap.params_canonical()` is used for MAC.
    # `cbc-core` doesn't verify bootstrap integrity *inside* `BootstrapSegment::decode`.
    # It verifies it separately?
    # `decoder::validate` step 1: `BootstrapSegment::decode`.
    # Then `blocks_end` calc.
    # THEN `verify_chain` (which uses params).
    # So if I mess up the bootstrap, `decode` sends back a struct.
    # It *does* run `BootstrapSegment::decode`, which just deserializes.
    # So I can put garbage in there, as long as it's valid ints.
    
    mac = b'\x00' * 16 
    reserved64 = b'\x00' * 8
    
    header = magic + version + hash_suite + commit_mode + bs_payload_size + bs_count + nonce + flags + reserved + mac + reserved64
    
    with open(f"{out_dir}/{name}", "wb") as f:
        f.write(header)
        # Add some dummy data just in case
        f.write(b'\x00' * 1024)

# 1. The Overflow Void
# count * size > u64::MAX?
# u32::MAX * u32::MAX < u64::MAX.
# But offset + (count * (size + overhead)) ?
# size + overhead ~ size.
# count * size fits in u64.
# Wait, let's re-calc.
# u32::MAX = 4,294,967,295 (4e9)
# u64::MAX = 18,446,744,073,709,551,615 (1.8e19)
# 4e9 * 4e9 = 1.84467441e19.
# It is VERY close to u64::MAX.
# 0xFFFFFFFF * 0xFFFFFFFF = 0xFFFFFFFE00000001
# overhead is at least 16+32=48.
# (size + 48) * count.
# If size is max, size+48 wraps u32?
# Rust `block_wire_size` takes `u32` returns `usize`.
# `BLOCK_HEADER_SIZE + block_payload_size as usize + COMMITMENT_SIZE`
# On 64-bit, usize is u64.
# `(0xFFFFFFFF + 48)` does not overflow u64.
# But `count * (size + 48)`?
# `0xFFFFFFFF * (0xFFFFFFFF + 48)`
# = `0xFFFFFFFF * 0xFFFFFFFF + 0xFFFFFFFF * 48`
# = `(u64::MAX - something) + large_number`.
# YES. It overflows u64.
# 0xFFFFFFFF = 2^32 - 1.
# (2^32 - 1) * (2^32 - 1 + 48) = (2^32 - 1)^2 + 48*(2^32 - 1)
# = 2^64 - 2*2^32 + 1 + 48*2^32 - 48
# = 2^64 + 46*2^32 - 47.
# This is > 2^64.
# So `blocks_end` calculation WILL wrap around on 64-bit systems.
create_artifact("overflow_void.cbc", 0xFFFFFFFF, 0xFFFFFFFF)

# 2. The Zero Day
create_artifact("zero_day.cbc", 10, 0)

print("Generated artifacts.")

for name in ["overflow_void.cbc", "zero_day.cbc"]:
    path = f"{out_dir}/{name}"
    print(f"Testing {name}...")
    result = subprocess.run(
        ["./target/release/cbc", "validate", "-i", path],
        capture_output=True,
        text=True
    )
    if result.returncode == 101:
        print(f"PANIC DETECTED on {name}!")
        print(result.stderr)
    elif result.returncode == 0:
        print(f"Unexpected VALID on {name}!")
    else:
        print(f"Rejected {name} (Exit code {result.returncode})")
