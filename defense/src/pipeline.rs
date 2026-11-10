//! Shared ring-buffer decoding and alert processing used by the daemon and smoke tests.

use std::mem::size_of;
use std::sync::Arc;

use anyhow::{ensure, Result};
use common::DefenseAlert;

use crate::adaptive::AdaptiveThresholds;
use crate::bus::{BusMessage, InProcessBus, MessagePublisher, ThreatEnvelope};
use crate::server::AppState;
use crate::{format_alert_details, CorrelatedThreat, TelecomCorrelationEngine};

pub fn decode_alert(bytes: &[u8]) -> Result<DefenseAlert> {
    ensure!(
        bytes.len() == size_of::<DefenseAlert>(),
        "invalid DefenseAlert record length: {} (expected {})",
        bytes.len(),
        size_of::<DefenseAlert>()
    );
    // DefenseAlert is repr(C), contains only integers/byte arrays, and all bit
    // patterns are valid. Ring buffer slices need not be naturally aligned.
    Ok(unsafe { bytes.as_ptr().cast::<DefenseAlert>().read_unaligned() })
}

pub struct AlertPipeline {
    engine: TelecomCorrelationEngine,
    state: Arc<AppState>,
    adaptive: Arc<tokio::sync::Mutex<AdaptiveThresholds>>,
    bus: Arc<InProcessBus>,
}

impl AlertPipeline {
    pub fn new(
        window_secs: u64,
        state: Arc<AppState>,
        adaptive: Arc<tokio::sync::Mutex<AdaptiveThresholds>>,
        bus: Arc<InProcessBus>,
    ) -> Self {
        Self {
            engine: TelecomCorrelationEngine::new(window_secs),
            state,
            adaptive,
            bus,
        }
    }

    pub async fn process(&mut self, alert: &DefenseAlert) -> Result<Option<CorrelatedThreat>> {
        self.state
            .metrics
            .record_alert(alert.alert_type, alert.severity);
        let details = format_alert_details(alert);
        if let Some(ref store) = self.state.store {
            store.lock().await.insert_alert(
                alert.timestamp_ns,
                alert.alert_type,
                alert.severity,
                alert.pid,
                alert.context,
                &details,
            )?;
        }
        let threat = self.engine.ingest_alert(alert);
        *self.state.correlation_metrics.write().await = self.engine.metrics.clone();
        let Some(threat) = threat else {
            return Ok(None);
        };
        if !self
            .adaptive
            .lock()
            .await
            .should_fire(&threat.category, threat.confidence)
        {
            return Ok(None);
        }
        self.state
            .metrics
            .record_threat(&format!("{:?}", threat.category));
        if let Some(ref store) = self.state.store {
            store.lock().await.insert_threat(&threat)?;
        }
        self.bus
            .publish(
                "threats",
                &BusMessage::Threat(ThreatEnvelope::from(&threat)),
            )
            .await?;
        Ok(Some(threat))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_ring_records_are_rejected() {
        assert!(decode_alert(&[]).is_err());
        assert!(decode_alert(&[0; 47]).is_err());
        assert!(decode_alert(&[0; 49]).is_err());
        let buffer = [0; 49];
        assert_eq!(decode_alert(&buffer[1..]).unwrap().alert_type, 0);
    }
}
