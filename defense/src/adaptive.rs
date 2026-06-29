use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::ThreatCategory;

/// Tracks operator feedback and adjusts confidence thresholds dynamically.
/// When operators mark threats as false positives, the threshold for that
/// category is raised. When they confirm real threats, it's lowered slightly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptiveThresholds {
    category_thresholds: HashMap<String, CategoryState>,
    global_min: f64,
    global_max: f64,
    learning_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CategoryState {
    threshold: f64,
    true_positives: u64,
    false_positives: u64,
    total_feedback: u64,
}

impl AdaptiveThresholds {
    pub fn new(base_threshold: f64) -> Self {
        let mut category_thresholds = HashMap::new();
        let categories = [
            "ImsiCatching",
            "ManInTheMiddle",
            "ProtocolDowngrade",
            "SignalingAbuse",
            "TollFraud",
            "LocationTracking",
            "DataInterception",
            "ServiceDenial",
            "SliceEscape",
            "RoamingExploit",
        ];
        for cat in categories {
            category_thresholds.insert(
                cat.to_string(),
                CategoryState {
                    threshold: base_threshold,
                    true_positives: 0,
                    false_positives: 0,
                    total_feedback: 0,
                },
            );
        }

        Self {
            category_thresholds,
            global_min: 0.4,
            global_max: 0.98,
            learning_rate: 0.05,
        }
    }

    pub fn threshold_for(&self, category: &ThreatCategory) -> f64 {
        let key = format!("{:?}", category);
        self.category_thresholds
            .get(&key)
            .map(|s| s.threshold)
            .unwrap_or(0.6)
    }

    pub fn record_feedback(&mut self, category: &ThreatCategory, is_false_positive: bool) {
        let key = format!("{:?}", category);
        let state = self
            .category_thresholds
            .entry(key)
            .or_insert(CategoryState {
                threshold: 0.6,
                true_positives: 0,
                false_positives: 0,
                total_feedback: 0,
            });

        state.total_feedback += 1;

        if is_false_positive {
            state.false_positives += 1;
            // Raise threshold — require higher confidence to fire
            state.threshold = (state.threshold + self.learning_rate).min(self.global_max);
        } else {
            state.true_positives += 1;
            // Lower threshold slightly — we're catching real threats
            state.threshold =
                (state.threshold - self.learning_rate * 0.5).max(self.global_min);
        }
    }

    pub fn should_fire(&self, category: &ThreatCategory, confidence: f64) -> bool {
        confidence >= self.threshold_for(category)
    }

    pub fn false_positive_rate(&self, category: &ThreatCategory) -> f64 {
        let key = format!("{:?}", category);
        self.category_thresholds
            .get(&key)
            .map(|s| {
                if s.total_feedback == 0 {
                    0.0
                } else {
                    s.false_positives as f64 / s.total_feedback as f64
                }
            })
            .unwrap_or(0.0)
    }

    pub fn stats(&self) -> HashMap<String, ThresholdStats> {
        self.category_thresholds
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    ThresholdStats {
                        threshold: v.threshold,
                        true_positives: v.true_positives,
                        false_positives: v.false_positives,
                        false_positive_rate: if v.total_feedback == 0 {
                            0.0
                        } else {
                            v.false_positives as f64 / v.total_feedback as f64
                        },
                    },
                )
            })
            .collect()
    }

    pub fn serialize_state(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".into())
    }

    pub fn load_state(json: &str) -> Option<Self> {
        serde_json::from_str(json).ok()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdStats {
    pub threshold: f64,
    pub true_positives: u64,
    pub false_positives: u64,
    pub false_positive_rate: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ThreatCategory;

    #[test]
    fn test_initial_threshold() {
        let at = AdaptiveThresholds::new(0.6);
        assert!((at.threshold_for(&ThreatCategory::ManInTheMiddle) - 0.6).abs() < f64::EPSILON);
        assert!((at.threshold_for(&ThreatCategory::ImsiCatching) - 0.6).abs() < f64::EPSILON);
    }

    #[test]
    fn test_false_positive_raises_threshold() {
        let mut at = AdaptiveThresholds::new(0.6);
        at.record_feedback(&ThreatCategory::ManInTheMiddle, true);
        let new_threshold = at.threshold_for(&ThreatCategory::ManInTheMiddle);
        assert!(new_threshold > 0.6);
        assert!((new_threshold - 0.65).abs() < f64::EPSILON);
    }

    #[test]
    fn test_true_positive_lowers_threshold() {
        let mut at = AdaptiveThresholds::new(0.7);
        at.record_feedback(&ThreatCategory::SignalingAbuse, false);
        let new_threshold = at.threshold_for(&ThreatCategory::SignalingAbuse);
        assert!(new_threshold < 0.7);
    }

    #[test]
    fn test_threshold_capped_at_max() {
        let mut at = AdaptiveThresholds::new(0.95);
        for _ in 0..20 {
            at.record_feedback(&ThreatCategory::LocationTracking, true);
        }
        assert!(at.threshold_for(&ThreatCategory::LocationTracking) <= 0.98);
    }

    #[test]
    fn test_threshold_capped_at_min() {
        let mut at = AdaptiveThresholds::new(0.5);
        for _ in 0..20 {
            at.record_feedback(&ThreatCategory::SliceEscape, false);
        }
        assert!(at.threshold_for(&ThreatCategory::SliceEscape) >= 0.4);
    }

    #[test]
    fn test_should_fire() {
        let at = AdaptiveThresholds::new(0.7);
        assert!(at.should_fire(&ThreatCategory::ManInTheMiddle, 0.92));
        assert!(!at.should_fire(&ThreatCategory::ManInTheMiddle, 0.5));
    }

    #[test]
    fn test_false_positive_rate() {
        let mut at = AdaptiveThresholds::new(0.6);
        at.record_feedback(&ThreatCategory::TollFraud, true);
        at.record_feedback(&ThreatCategory::TollFraud, true);
        at.record_feedback(&ThreatCategory::TollFraud, false);
        let fpr = at.false_positive_rate(&ThreatCategory::TollFraud);
        assert!((fpr - 2.0 / 3.0).abs() < 0.01);
    }

    #[test]
    fn test_serialize_and_load_state() {
        let mut at = AdaptiveThresholds::new(0.6);
        at.record_feedback(&ThreatCategory::ManInTheMiddle, true);
        at.record_feedback(&ThreatCategory::ImsiCatching, false);

        let json = at.serialize_state();
        let loaded = AdaptiveThresholds::load_state(&json).unwrap();

        assert!(
            (loaded.threshold_for(&ThreatCategory::ManInTheMiddle)
                - at.threshold_for(&ThreatCategory::ManInTheMiddle))
            .abs()
                < f64::EPSILON
        );
    }

    #[test]
    fn test_stats_output() {
        let mut at = AdaptiveThresholds::new(0.6);
        at.record_feedback(&ThreatCategory::RoamingExploit, true);
        at.record_feedback(&ThreatCategory::RoamingExploit, false);

        let stats = at.stats();
        let roaming = stats.get("RoamingExploit").unwrap();
        assert_eq!(roaming.true_positives, 1);
        assert_eq!(roaming.false_positives, 1);
        assert!((roaming.false_positive_rate - 0.5).abs() < f64::EPSILON);
    }
}
