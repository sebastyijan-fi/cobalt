import struct
import hashlib

try:
    import blake3
except ImportError:
    blake3 = None

class CbcError(Exception):
    pass

class HashSuite:
    BLAKE3 = 0x01
    SHA256 = 0x02

    @staticmethod
    def hash(id, parts):
        if id == HashSuite.BLAKE3:
            if blake3 is None:
                raise ImportError("blake3 python package required for BLAKE3 hash suite")
            h = blake3.blake3()
            for p in parts:
                h.update(p)
            return h.digest()
        elif id == HashSuite.SHA256:
            h = hashlib.sha256()
            for p in parts:
                h.update(p)
            return h.digest()
        else:
            raise CbcError(f"Unknown HashSuite ID: {id}")

class BootstrapSegment:
    SIZE = 64
    MAGIC = b"CBC1"
    VERSION = 1

    def __init__(self, data):
        if len(data) < self.SIZE:
            raise CbcError(f"Bootstrap segment too small: {len(data)}")
        
        self.magic = data[0:4]
        if self.magic != self.MAGIC:
            raise CbcError(f"Invalid magic: {self.magic}")
            
        self.version = struct.unpack("<H", data[4:6])[0]
        if self.version != self.VERSION:
            raise CbcError(f"Unsupported version: {self.version}")
            
        self.hash_suite = data[6]
        self.commitment_mode = data[7]
        self.block_payload_size = struct.unpack("<I", data[8:12])[0]
        self.block_count = struct.unpack("<I", data[12:16])[0]
        self.nonce = data[16:32]
        self.flags = struct.unpack("<I", data[32:36])[0]
        self.reserved1 = struct.unpack("<I", data[36:40])[0]
        self.params_mac = data[40:56]
        self.reserved2 = struct.unpack("<Q", data[56:64])[0]
        
        # Verify ParamsMAC
        params_canonical = bytearray(data[0:40])
        params_canonical[12:16] = b"\x00\x00\x00\x00" # Zero block_count for canonical
        
        expected_mac = HashSuite.hash(self.hash_suite, [b"CBC-v1-params-mac", params_canonical])[0:16]
        if self.params_mac != expected_mac:
            raise CbcError("ParamsMAC mismatch")

    def get_params_hash(self):
        params_canonical = bytearray(struct.pack("<4sHBBII16sII", 
            self.MAGIC, self.VERSION, self.hash_suite, self.commitment_mode,
            self.block_payload_size, 0, self.nonce, self.flags, self.reserved1))
        return HashSuite.hash(self.hash_suite, [params_canonical])

    def get_c0(self):
        params_canonical = bytearray(struct.pack("<4sHBBII16sII", 
            self.MAGIC, self.VERSION, self.hash_suite, self.commitment_mode,
            self.block_payload_size, 0, self.nonce, self.flags, self.reserved1))
        return HashSuite.hash(self.hash_suite, [b"CBC-v1", params_canonical, self.nonce])

class BlockHeader:
    SIZE = 16
    def __init__(self, data):
        self.index, self.payload_len, self.flags, self.local_check = struct.unpack("<IIII", data)

class Block:
    def __init__(self, data, block_payload_size):
        self.raw_header = data[0:16]
        self.header = BlockHeader(self.raw_header)
        self.payload = data[16:16+self.header.payload_len]
        self.padded_payload = data[16:16+block_payload_size]
        self.commitment = data[16+block_payload_size : 16+block_payload_size+32]

def verify_artifact(data):
    bootstrap = BootstrapSegment(data[0:64])
    params_hash = bootstrap.get_params_hash()
    prev_c = bootstrap.get_c0()
    
    offset = 64
    block_wire_size = 16 + bootstrap.block_payload_size + 32
    
    for i in range(bootstrap.block_count):
        block_data = data[offset : offset + block_wire_size]
        block = Block(block_data, bootstrap.block_payload_size)
        
        if block.header.index != i:
            raise CbcError(f"Block index mismatch: expected {i}, got {block.header.index}")
            
        # Verify CI
        ci = HashSuite.hash(bootstrap.hash_suite, [
            b"CBC-v1-block",
            params_hash,
            block.raw_header,
            block.padded_payload,
            prev_c
        ])
        
        if ci != block.commitment:
            raise CbcError(f"Chain commitment mismatch at block {i}")
            
        prev_c = ci
        offset += block_wire_size
        
    return prev_c

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python ref_oracle.py <artifact.cbc>")
        sys.exit(1)
        
    with open(sys.argv[1], "rb") as f:
        artifact_data = f.read()
        
    root = verify_artifact(artifact_data)
    if "--json" in sys.argv:
        import json
        print(json.dumps({"chain_root": root.hex()}))
    else:
        print(f"✓ Verified. Chain Root: {root.hex()}")
