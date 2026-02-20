import cbc_py
import sys

def main():
    artifact_path = "../test.cbc"
    
    print(f"Testing cbc-py with {artifact_path}...")

    # Test inspection
    try:
        info = cbc_py.inspect(artifact_path)
        print("\n[Inspection Result]")
        print(f"Valid Bootstrap: {info.valid_bootstrap}")
        print(f"Version: {info.version}")
        print(f"Hash Suite: {info.hash_suite}")
        print(f"Blocks: {info.block_count}")
        print(f"Block Size: {info.block_payload_size}")
        print(f"Families: {', '.join(info.families)}")
    except ValueError as e:
        print(f"Inspection failed: {e}")
        sys.exit(1)

    # Test validation
    try:
        is_valid = cbc_py.validate(artifact_path)
        print(f"\nValidation Status: {'✓ VALID' if is_valid else '✗ INVALID'}")
    except ValueError as e:
        print(f"Validation failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
