use std::fs;

fn main() {
    let mut data = fs::read("encrypted.cbc").expect("Failed to read encrypted.cbc");

    // Flip a bit in the ciphertext (Block 0)
    // Bootstrap(64) + Header(16) + index(10)
    data[64 + 16 + 10] ^= 0x01;

    // Default block_payload_size is 4096
    let bps = 4096;
    let payload_offset = 64 + 16;
    let padded_payload = &data[payload_offset..payload_offset + bps];

    // We'll use the crc32c crate which is already in scope if we run this via cargo
    let new_crc = crc32c::crc32c(padded_payload);

    // Update local_check (magic_idx + 12 = 64 + 12)
    data[64 + 12..64 + 16].copy_from_slice(&new_crc.to_le_bytes());

    fs::write("tampered_v2.cbc", data).expect("Failed to write tampered_v2.cbc");
}
