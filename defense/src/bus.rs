use std::sync::Arc;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc};

use crate::CorrelatedThreat;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BusMessage {
    Alert {
        timestamp_ns: u64,
        alert_type: u32,
        severity: u32,
        pid: u32,
        context: u64,
        details: String,
    },
    Threat(ThreatEnvelope),
    FeedbackOverride {
        threat_id: u64,
        is_false_positive: bool,
        reason: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEnvelope {
    pub threat_id: u64,
    pub confidence: f64,
    pub severity: u8,
    pub category: String,
    pub description: String,
    pub layers: Vec<String>,
}

impl From<&CorrelatedThreat> for ThreatEnvelope {
    fn from(t: &CorrelatedThreat) -> Self {
        Self {
            threat_id: t.threat_id,
            confidence: t.confidence,
            severity: t.severity,
            category: format!("{:?}", t.category),
            description: t.description.clone(),
            layers: t.layers_involved.iter().map(|l| format!("{:?}", l)).collect(),
        }
    }
}

/// Trait for publishing messages to the bus
#[async_trait::async_trait]
pub trait MessagePublisher: Send + Sync {
    async fn publish(&self, topic: &str, message: &BusMessage) -> Result<()>;
}

/// Trait for subscribing to messages from the bus
#[async_trait::async_trait]
pub trait MessageSubscriber: Send + Sync {
    async fn subscribe(&self, topic: &str) -> Result<Box<dyn MessageStream>>;
}

/// Stream of messages from a subscription
#[async_trait::async_trait]
pub trait MessageStream: Send {
    async fn next(&mut self) -> Option<BusMessage>;
}

/// In-process message bus using tokio broadcast channels (default, no external deps)
pub struct InProcessBus {
    alert_tx: broadcast::Sender<BusMessage>,
    threat_tx: broadcast::Sender<BusMessage>,
    feedback_tx: mpsc::Sender<BusMessage>,
    feedback_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<BusMessage>>>,
}

impl InProcessBus {
    pub fn new(capacity: usize) -> Self {
        let (alert_tx, _) = broadcast::channel(capacity);
        let (threat_tx, _) = broadcast::channel(capacity);
        let (feedback_tx, feedback_rx) = mpsc::channel(capacity);
        Self {
            alert_tx,
            threat_tx,
            feedback_tx,
            feedback_rx: Arc::new(tokio::sync::Mutex::new(feedback_rx)),
        }
    }

    pub fn alert_sender(&self) -> broadcast::Sender<BusMessage> {
        self.alert_tx.clone()
    }

    pub fn threat_sender(&self) -> broadcast::Sender<BusMessage> {
        self.threat_tx.clone()
    }

    pub fn feedback_sender(&self) -> mpsc::Sender<BusMessage> {
        self.feedback_tx.clone()
    }

    pub fn subscribe_alerts(&self) -> broadcast::Receiver<BusMessage> {
        self.alert_tx.subscribe()
    }

    pub fn subscribe_threats(&self) -> broadcast::Receiver<BusMessage> {
        self.threat_tx.subscribe()
    }

    pub async fn recv_feedback(&self) -> Option<BusMessage> {
        self.feedback_rx.lock().await.recv().await
    }
}

#[async_trait::async_trait]
impl MessagePublisher for InProcessBus {
    async fn publish(&self, topic: &str, message: &BusMessage) -> Result<()> {
        match topic {
            "alerts" => {
                let _ = self.alert_tx.send(message.clone());
            }
            "threats" => {
                let _ = self.threat_tx.send(message.clone());
            }
            "feedback" => {
                self.feedback_tx
                    .send(message.clone())
                    .await
                    .map_err(|e| anyhow::anyhow!("feedback send failed: {}", e))?;
            }
            _ => anyhow::bail!("unknown topic: {}", topic),
        }
        Ok(())
    }
}

pub struct BroadcastStream {
    rx: broadcast::Receiver<BusMessage>,
}

#[async_trait::async_trait]
impl MessageStream for BroadcastStream {
    async fn next(&mut self) -> Option<BusMessage> {
        self.rx.recv().await.ok()
    }
}

#[async_trait::async_trait]
impl MessageSubscriber for InProcessBus {
    async fn subscribe(&self, topic: &str) -> Result<Box<dyn MessageStream>> {
        match topic {
            "alerts" => Ok(Box::new(BroadcastStream {
                rx: self.alert_tx.subscribe(),
            })),
            "threats" => Ok(Box::new(BroadcastStream {
                rx: self.threat_tx.subscribe(),
            })),
            _ => anyhow::bail!("unknown topic: {}", topic),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_in_process_bus_publish_subscribe() {
        let bus = InProcessBus::new(64);
        let mut rx = bus.subscribe_threats();

        let msg = BusMessage::Threat(ThreatEnvelope {
            threat_id: 1,
            confidence: 0.92,
            severity: 4,
            category: "ManInTheMiddle".into(),
            description: "test".into(),
            layers: vec!["Radio".into(), "Nas".into()],
        });

        bus.publish("threats", &msg).await.unwrap();

        let received = rx.recv().await.unwrap();
        if let BusMessage::Threat(envelope) = received {
            assert_eq!(envelope.threat_id, 1);
            assert_eq!(envelope.category, "ManInTheMiddle");
        } else {
            panic!("expected Threat message");
        }
    }

    #[tokio::test]
    async fn test_feedback_channel() {
        let bus = InProcessBus::new(64);

        let msg = BusMessage::FeedbackOverride {
            threat_id: 42,
            is_false_positive: true,
            reason: "known benign tower".into(),
        };

        bus.publish("feedback", &msg).await.unwrap();

        let received = bus.recv_feedback().await.unwrap();
        if let BusMessage::FeedbackOverride {
            threat_id,
            is_false_positive,
            ..
        } = received
        {
            assert_eq!(threat_id, 42);
            assert!(is_false_positive);
        } else {
            panic!("expected FeedbackOverride");
        }
    }
}
