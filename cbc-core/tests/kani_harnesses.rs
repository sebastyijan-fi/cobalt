// Kani verification harnesses for cbc-core.
//
// These proofs are only compiled and executed under `kani`. They are
// intentionally gated behind `#[cfg(kani)]` so that normal `cargo test`
// and `cargo clippy` never see the kani-specific imports or attributes.

#[cfg(kani)]
mod proofs {
    use cbc_core::bootstrap::BootstrapSegment;
    use cbc_core::footer::StreamFooter;
    use cbc_core::{decoder, HashSuite};

    #[kani::proof]
    fn verify_bootstrap_decode() {
        let data: [u8; 64] = kani::any();
        let _ = BootstrapSegment::decode(&data);
    }

    #[kani::proof]
    fn verify_footer_decode_family_a() {
        let data: [u8; 128] = kani::any(); // Bounded size for verification
        let params_hash: [u8; 32] = kani::any();
        let suite = if kani::any::<bool>() {
            HashSuite::Blake3
        } else {
            HashSuite::Sha256
        };
        let _ = StreamFooter::decode(&data, false, &params_hash, suite);
    }

    #[kani::proof]
    fn verify_decoder_no_panic() {
        // We limit the input size for symbolic execution to keep the proof tractable.
        // Proving panic-freedom for a 256-byte buffer covers the primary logic branches.
        let data: [u8; 256] = kani::any();
        let _ = decoder::decode(&data, None);
    }
}
