use cbc_core::bootstrap::BootstrapSegment;
use cbc_core::footer::StreamFooter;
use cbc_core::{decoder, encoder, EncoderConfig, HashSuite};
use proptest::prelude::*;

// --- Strategies ---

fn hash_suite_strategy() -> impl Strategy<Value = HashSuite> {
    prop_oneof![Just(HashSuite::Blake3), Just(HashSuite::Sha256),]
}

fn bootstrap_segment_strategy() -> impl Strategy<Value = BootstrapSegment> {
    (
        hash_suite_strategy(),
        0..8u8,                             // commitment_mode bits 0-2
        9..24u32,                           // block_payload_size power (2^9 to 2^24)
        1..1000u32,                         // block_count (minimum 1)
        prop::array::uniform16(0..u8::MAX), // bootstrap_nonce
        any::<u32>(),                       // flags
    )
        .prop_map(|(suite, mut mode, power, count, nonce, flags)| {
            mode |= cbc_core::bootstrap::FAMILY_A_BIT; // Ensure A is set
            mode &= 0x07; // Only bits 0-2 allowed
            BootstrapSegment {
                hash_suite: suite,
                commitment_mode: mode,
                block_payload_size: 1 << power,
                block_count: count,
                bootstrap_nonce: nonce,
                flags,
            }
        })
}

fn encoded_receipt_strategy() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 4..1024)
}

fn footer_strategy(has_merkle: bool) -> impl Strategy<Value = StreamFooter> {
    let merkle_strat = if has_merkle {
        prop::array::uniform32(0..u8::MAX).prop_map(Some).boxed()
    } else {
        Just(None).boxed()
    };

    (
        prop::array::uniform32(0..u8::MAX), // chain_root
        merkle_strat,                       // merkle_root
        prop::collection::vec(encoded_receipt_strategy(), 0..10), // receipt_slots
    )
        .prop_map(|(cr, mr, receipts)| StreamFooter {
            chain_root: cr,
            merkle_root: mr,
            receipt_count: receipts.len() as u32,
            receipt_slots: receipts,
            footer_commitment: [0u8; 32], // Placeholder, to be computed in test
        })
}

// --- Properties ---

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn test_bootstrap_roundtrip(bootstrap in bootstrap_segment_strategy()) {
        let encoded = bootstrap.encode();
        let decoded = BootstrapSegment::decode(&encoded).unwrap();
        prop_assert_eq!(bootstrap.hash_suite, decoded.hash_suite);
        prop_assert_eq!(bootstrap.commitment_mode, decoded.commitment_mode);
        prop_assert_eq!(bootstrap.block_payload_size, decoded.block_payload_size);
        prop_assert_eq!(bootstrap.block_count, decoded.block_count);
        prop_assert_eq!(bootstrap.bootstrap_nonce, decoded.bootstrap_nonce);
        prop_assert_eq!(bootstrap.flags, decoded.flags);
    }

    #[test]
    fn test_footer_roundtrip(
        footer in footer_strategy(true),
        has_merkle in any::<bool>(),
        params_hash in prop::array::uniform32(0..u8::MAX),
        suite in hash_suite_strategy()
    ) {
        let mut footer = footer;
        if !has_merkle { footer.merkle_root = None; }

        let encoded = StreamFooter::encode(
            footer.chain_root,
            footer.merkle_root,
            &footer.receipt_slots,
            &params_hash,
            suite
        );
        let decoded = StreamFooter::decode(&encoded, has_merkle, &params_hash, suite).unwrap();

        prop_assert_eq!(footer.chain_root, decoded.chain_root);
        prop_assert_eq!(footer.merkle_root, decoded.merkle_root);
        prop_assert_eq!(footer.receipt_slots, decoded.receipt_slots);
    }

    #[test]
    fn test_decoder_no_panic(data in prop::collection::vec(any::<u8>(), 0..8192)) {
        // The decoder should NEVER panic, even on randomized junk.
        let _ = decoder::decode(&data, None);
    }

    #[test]
    fn test_full_roundtrip_family_a(
        payload in prop::collection::vec(any::<u8>(), 1..10000),
        suite in hash_suite_strategy(),
        power in 9..14u32, // 2^9 (512) to 2^13 (8192)
        nonce in prop::array::uniform16(0..u8::MAX),
    ) {
        let bps = 1 << power;
        let config = EncoderConfig {
            hash_suite: suite,
            commitment_mode: cbc_core::bootstrap::FAMILY_A_BIT,
            block_payload_size: bps,
            flags: 0,
            encryption_key: None,
        };

        let artifact = encoder::encode(&config, &payload, nonce, &[]).unwrap();
        let decoded = decoder::decode(&artifact, None).unwrap();

        prop_assert_eq!(decoded.payload, payload);
        prop_assert_eq!(decoded.bootstrap.hash_suite, suite);
        prop_assert_eq!(decoded.bootstrap.block_payload_size, bps);
    }
}
