import struct

# MAGIC: CBC1 (0x43 0x42 0x43 0x31)
magic = b'CBC1'
version = struct.pack('<H', 1)
hash_suite = b'\x01' # Blake3
commit_mode = b'\x01' # Family A
block_size = struct.pack('<I', 4096)
# MALICIOUS: Block count = MAX_U32
block_count = struct.pack('<I', 0xFFFFFFFF)
nonce = b'\x00' * 16
flags = struct.pack('<I', 0)
reserved = struct.pack('<I', 0)
mac = b'\x00' * 16 # Invalid MAC, but we want to see if it allocs before checking MAC
reserved64 = b'\x00' * 8

header = magic + version + hash_suite + commit_mode + block_size + block_count + nonce + flags + reserved + mac + reserved64

with open('bomb.cbc', 'wb') as f:
    f.write(header)
