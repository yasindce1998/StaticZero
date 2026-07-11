//! Prometheus metrics for alert rates, threat counts, and engine health.

use anyhow::Result;
use prometheus::{
    Encoder, GaugeVec, IntCounter, IntCounterVec, IntGauge, Opts, Registry, TextEncoder,
};

#[derive(Clone)]
pub struct Metrics {
    pub registry: Registry,
    pub alerts_total: IntCounterVec,
    pub threats_total: IntCounterVec,
    pub alerts_per_second: GaugeVec,
    pub correlation_window_active: IntGauge,
    pub uptime_seconds: IntGauge,
    pub events_processed: IntCounter,
    pub false_positives_overridden: IntCounter,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new().expect("failed to initialize metrics")
    }
}

impl Metrics {
    pub fn new() -> Result<Self> {
        let registry = Registry::new();

        let alerts_total = IntCounterVec::new(
            Opts::new(
                "staticzero_alerts_total",
                "Total alerts by type and severity",
            ),
            &["alert_type", "severity"],
        )?;

        let threats_total = IntCounterVec::new(
            Opts::new(
                "staticzero_threats_total",
                "Total correlated threats by category",
            ),
            &["category"],
        )?;

        let alerts_per_second = GaugeVec::new(
            Opts::new("staticzero_alerts_per_second", "Alert rate per type"),
            &["alert_type"],
        )?;

        let correlation_window_active = IntGauge::new(
            "staticzero_correlation_windows_active",
            "Number of active correlation windows",
        )?;

        let uptime_seconds =
            IntGauge::new("staticzero_uptime_seconds", "Engine uptime in seconds")?;

        let events_processed = IntCounter::new(
            "staticzero_events_processed_total",
            "Total events processed by the correlation engine",
        )?;

        let false_positives_overridden = IntCounter::new(
            "staticzero_false_positives_overridden_total",
            "Threats below confidence threshold that were overridden",
        )?;

        registry.register(Box::new(alerts_total.clone()))?;
        registry.register(Box::new(threats_total.clone()))?;
        registry.register(Box::new(alerts_per_second.clone()))?;
        registry.register(Box::new(correlation_window_active.clone()))?;
        registry.register(Box::new(uptime_seconds.clone()))?;
        registry.register(Box::new(events_processed.clone()))?;
        registry.register(Box::new(false_positives_overridden.clone()))?;

        Ok(Self {
            registry,
            alerts_total,
            threats_total,
            alerts_per_second,
            correlation_window_active,
            uptime_seconds,
            events_processed,
            false_positives_overridden,
        })
    }

    pub fn encode(&self) -> String {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder
            .encode(&metric_families, &mut buffer)
            .expect("prometheus encoding is infallible");
        String::from_utf8(buffer).expect("prometheus output is valid UTF-8")
    }

    pub fn record_alert(&self, alert_type: u32, severity: u32) {
        self.alerts_total
            .with_label_values(&[&alert_type.to_string(), &severity.to_string()])
            .inc();
        self.events_processed.inc();
    }

    pub fn record_threat(&self, category: &str) {
        self.threats_total.with_label_values(&[category]).inc();
    }

    pub fn record_false_positive_override(&self) {
        self.false_positives_overridden.inc();
    }
}
