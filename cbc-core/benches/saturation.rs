use cbc_core::bootstrap::FAMILY_A_BIT;
use cbc_core::streaming::StreamingEncoder;
use cbc_core::{EncoderConfig, HashSuite};
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

fn bench_saturation(c: &mut Criterion) {
    let mut group = c.benchmark_group("cbc_saturation");

    // We test at 10MB to see how it scales beyond the cache of some systems.
    let size = 10 * 1024 * 1024;
    let payload = vec![0x42u8; size];
    group.throughput(Throughput::Bytes(size as u64));

    // Case 1: Blake3 (Unencrypted)
    let config_b3 = EncoderConfig {
        hash_suite: HashSuite::Blake3,
        commitment_mode: FAMILY_A_BIT,
        block_payload_size: 65536, // Large blocks for throughput
        flags: 0,
        encryption_key: None,
    };

    group.bench_function("streaming_encode_blake3_10mb", |b| {
        b.iter(|| {
            let mut encoder = StreamingEncoder::new(&config_b3, [0u8; 16]);
            let mut artifact = Vec::new();
            for chunk in payload.chunks(16384) {
                artifact.extend(encoder.feed(black_box(chunk)).unwrap().concat());
            }
            let (final_blocks, _) = encoder.finalize(&[]).unwrap();
            artifact.extend(final_blocks);
        })
    });

    // Case 2: SHA256 (Unencrypted)
    let config_sha = EncoderConfig {
        hash_suite: HashSuite::Sha256,
        commitment_mode: FAMILY_A_BIT,
        block_payload_size: 65536,
        flags: 0,
        encryption_key: None,
    };

    group.bench_function("streaming_encode_sha256_10mb", |b| {
        b.iter(|| {
            let mut encoder = StreamingEncoder::new(&config_sha, [0u8; 16]);
            let mut artifact = Vec::new();
            for chunk in payload.chunks(16384) {
                artifact.extend(encoder.feed(black_box(chunk)).unwrap().concat());
            }
            let (final_blocks, _) = encoder.finalize(&[]).unwrap();
            artifact.extend(final_blocks);
        })
    });

    group.finish();
}

criterion_group!(benches, bench_saturation);
criterion_main!(benches);
