use criterion::{black_box, criterion_group, criterion_main, Criterion};

use common::DefenseAlert;
use defense::TelecomCorrelationEngine;

fn make_alert(alert_type: u32, severity: u32, context: u64, timestamp_ns: u64) -> DefenseAlert {
    DefenseAlert {
        alert_type,
        severity,
        pid: 1000,
        _pad: 0,
        timestamp_ns,
        context,
        details: [0u8; 16],
    }
}

fn bench_ingest_single(c: &mut Criterion) {
    c.bench_function("ingest_single_alert", |b| {
        b.iter(|| {
            let mut engine = TelecomCorrelationEngine::new(60);
            let alert = make_alert(1, 3, 12345, 1_000_000_000);
            black_box(engine.ingest_alert(&alert));
        });
    });
}

fn bench_ingest_burst(c: &mut Criterion) {
    c.bench_function("ingest_100_alerts", |b| {
        b.iter(|| {
            let mut engine = TelecomCorrelationEngine::new(60);
            for i in 0..100u64 {
                let alert_type = (i % 24 + 1) as u32;
                let alert = make_alert(alert_type, 3, 12345, i * 100_000_000);
                black_box(engine.ingest_alert(&alert));
            }
        });
    });
}

fn bench_correlation_multi_cell(c: &mut Criterion) {
    c.bench_function("ingest_100_alerts_10_cells", |b| {
        b.iter(|| {
            let mut engine = TelecomCorrelationEngine::new(60);
            for i in 0..100u64 {
                let cell_id = (i % 10) as u64;
                let alert_type = (i % 24 + 1) as u32;
                let alert = make_alert(alert_type, 3, cell_id, i * 100_000_000);
                black_box(engine.ingest_alert(&alert));
            }
        });
    });
}

fn bench_sustained_load(c: &mut Criterion) {
    c.bench_function("sustained_1000_alerts", |b| {
        b.iter(|| {
            let mut engine = TelecomCorrelationEngine::new(5);
            for i in 0..1000u64 {
                let cell_id = (i % 50) as u64;
                let alert_type = (i % 24 + 1) as u32;
                let severity = (i % 4 + 1) as u32;
                let alert = make_alert(alert_type, severity, cell_id, i * 10_000_000);
                black_box(engine.ingest_alert(&alert));
            }
        });
    });
}

criterion_group!(
    benches,
    bench_ingest_single,
    bench_ingest_burst,
    bench_correlation_multi_cell,
    bench_sustained_load,
);
criterion_main!(benches);
