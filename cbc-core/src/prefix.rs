/// Family C — Grammar / prefix constraints (§4.3).
///
/// Structural parseability without cryptography.
/// Provides block boundary resynchronization and ambiguity rejection
/// using self-delimiting prefix-free codes.
use crate::error::{CbcError, Result};
use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;

/// Prefix code marker for block boundaries.
/// We use a simple self-delimiting scheme:
///   - Block start marker: 0xFF 0x00 (two-byte unambiguous marker)
///   - Block type tag: Elias gamma coded (but for v0.1 we only have type 0x01 = data block)
///   - Length field: the block_payload_size encoded as a varint
///
/// This is a "lite" Family C that provides the resync and ambiguity properties
/// the spec requires without overcomplicating the v0.1 prototype.
///
/// Block start marker bytes.
pub const BLOCK_START_MARKER: [u8; 2] = [0xFF, 0x00];

/// Block type: data block.
pub const BLOCK_TYPE_DATA: u8 = 0x01;

/// Encode a prefix-framed block boundary marker.
/// Returns the marker bytes that should prepend the block's standard header.
///
/// Format: [0xFF, 0x00, block_type, payload_size_varint...]
pub fn encode_prefix_marker(block_type: u8, payload_size: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8);
    buf.extend_from_slice(&BLOCK_START_MARKER);
    buf.push(block_type);
    encode_varint(payload_size, &mut buf);
    buf
}

/// Decode a prefix-framed block boundary marker.
/// Returns (block_type, payload_size, bytes_consumed).
pub fn decode_prefix_marker(data: &[u8]) -> Result<(u8, u32, usize)> {
    if data.len() < 4 {
        return Err(CbcError::PrefixParseError(
            "insufficient data for prefix marker".to_string(),
        ));
    }

    // Check start marker
    if data[0] != BLOCK_START_MARKER[0] || data[1] != BLOCK_START_MARKER[1] {
        return Err(CbcError::PrefixParseError(format!(
            "invalid block start marker: 0x{:02x} 0x{:02x}",
            data[0], data[1]
        )));
    }

    let block_type = data[2];
    let (payload_size, varint_len) = decode_varint(&data[3..])?;

    Ok((block_type, payload_size, 3 + varint_len))
}

/// Validate prefix parse integrity across a sequence of block data.
///
/// Checks that all prefix markers are unambiguous and self-consistent.
/// `block_data` contains the raw bytes for each block (including prefix markers).
pub fn validate_prefix_parse(block_data: &[&[u8]], expected_payload_size: u32) -> Result<()> {
    for (i, data) in block_data.iter().enumerate() {
        let (block_type, payload_size, _consumed) = decode_prefix_marker(data)
            .map_err(|e| CbcError::PrefixParseError(format!("block {i}: {e}")))?;

        if block_type != BLOCK_TYPE_DATA {
            return Err(CbcError::PrefixParseError(format!(
                "block {i}: unknown block type 0x{block_type:02x}"
            )));
        }

        if payload_size != expected_payload_size {
            return Err(CbcError::PrefixParseError(
                format!(
                    "block {i}: payload size mismatch: expected {expected_payload_size}, got {payload_size}"
                )
            ));
        }
    }

    Ok(())
}

/// Scan for the next valid block boundary in a potentially corrupted stream.
/// Returns the offset of the next block start marker, or None.
pub fn find_next_block_boundary(data: &[u8]) -> Option<usize> {
    for i in 0..data.len().saturating_sub(1) {
        if data[i] == BLOCK_START_MARKER[0] && data[i + 1] == BLOCK_START_MARKER[1] {
            // Try to decode the prefix to validate it's a real marker
            if decode_prefix_marker(&data[i..]).is_ok() {
                return Some(i);
            }
        }
    }
    None
}

// --- Variable-length integer encoding (simple varint) ---

fn encode_varint(mut value: u32, buf: &mut Vec<u8>) {
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            buf.push(byte);
            break;
        } else {
            buf.push(byte | 0x80);
        }
    }
}

fn decode_varint(data: &[u8]) -> Result<(u32, usize)> {
    let mut value: u32 = 0;
    let mut shift = 0;

    for (i, &byte) in data.iter().enumerate() {
        if shift >= 35 {
            return Err(CbcError::PrefixParseError("varint too large".to_string()));
        }
        value |= ((byte & 0x7F) as u32) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return Ok((value, i + 1));
        }
    }

    Err(CbcError::PrefixParseError(
        "unterminated varint".to_string(),
    ))
}

/// Calculate the prefix marker size for a given payload size.
pub fn prefix_marker_size(payload_size: u32) -> usize {
    let mut buf = Vec::new();
    encode_varint(payload_size, &mut buf);
    3 + buf.len() // 2 bytes marker + 1 byte type + varint
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_prefix_marker_roundtrip() {
        let marker = encode_prefix_marker(BLOCK_TYPE_DATA, 4096);
        let (block_type, payload_size, consumed) = decode_prefix_marker(&marker).unwrap();
        assert_eq!(block_type, BLOCK_TYPE_DATA);
        assert_eq!(payload_size, 4096);
        assert_eq!(consumed, marker.len());
    }

    #[test]
    fn test_varint_small() {
        let mut buf = Vec::new();
        encode_varint(127, &mut buf);
        assert_eq!(buf.len(), 1);
        let (val, len) = decode_varint(&buf).unwrap();
        assert_eq!(val, 127);
        assert_eq!(len, 1);
    }

    #[test]
    fn test_varint_large() {
        let mut buf = Vec::new();
        encode_varint(16 * 1024 * 1024, &mut buf);
        let (val, _) = decode_varint(&buf).unwrap();
        assert_eq!(val, 16 * 1024 * 1024);
    }

    #[test]
    fn test_find_boundary() {
        let mut data = vec![0xAA; 100];
        let marker = encode_prefix_marker(BLOCK_TYPE_DATA, 512);
        data[50..50 + marker.len()].copy_from_slice(&marker);
        let found = find_next_block_boundary(&data);
        assert_eq!(found, Some(50));
    }

    #[test]
    fn test_invalid_marker_rejected() {
        let data = [0x00, 0x01, 0x02, 0x03];
        assert!(decode_prefix_marker(&data).is_err());
    }

    #[test]
    fn test_validate_prefix_parse() {
        let markers: Vec<Vec<u8>> = (0..3)
            .map(|_| {
                let mut m = encode_prefix_marker(BLOCK_TYPE_DATA, 512);
                m.extend_from_slice(&[0u8; 100]); // extra data
                m
            })
            .collect();
        let refs: Vec<&[u8]> = markers.iter().map(|m| m.as_slice()).collect();
        assert!(validate_prefix_parse(&refs, 512).is_ok());
    }
}
