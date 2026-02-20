use cbc_core::bootstrap::FAMILY_A_BIT;
use cbc_core::{decoder, encoder, EncoderConfig, HashSuite};
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

fn bench_encode_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("cbc_throughput");

    // Benchmark at different payload sizes: 10KB, 1MB
    for size in [10 * 1024, 1024 * 1024] {
        let payload = vec![0x42u8; size];
        group.throughput(Throughput::Bytes(size as u64));

        let config = EncoderConfig {
            hash_suite: HashSuite::Blake3,
            commitment_mode: FAMILY_A_BIT,
            block_payload_size: 4096,
            flags: 0,
            encryption_key: None,
        };

        group.bench_function(format!("encode_{}kb", size / 1024), |b| {
            b.iter(|| {
                encoder::encode(
                    black_box(&config),
                    black_box(&payload),
                    black_box([0u8; 16]),
                    black_box(&[]),
                )
                .unwrap()
            })
        });

        let artifact = encoder::encode(&config, &payload, [0u8; 16], &[]).unwrap();
        group.bench_function(format!("decode_{}kb", size / 1024), |b| {
            b.iter(|| decoder::decode(black_box(&artifact), None).unwrap())
        });
    }

    group.finish();
}

criterion_group!(benches, bench_encode_decode);
criterion_main!(benches);
