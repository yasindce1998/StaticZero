use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tracing::{error, info};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub engine: EngineConfig,
    #[serde(default)]
    pub persistence: PersistenceConfig,
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub thresholds: ThresholdConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineConfig {
    #[serde(default = "default_correlation_window")]
    pub correlation_window_secs: u64,
    #[serde(default = "default_true")]
    pub telecom_detect: bool,
    #[serde(default)]
    pub telecom_advanced: bool,
    #[serde(default)]
    pub json_output: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_db_path")]
    pub db_path: PathBuf,
    #[serde(default = "default_retention_hours")]
    pub retention_hours: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdConfig {
    #[serde(default = "default_min_confidence")]
    pub min_confidence: f64,
    #[serde(default = "default_mitm_confidence")]
    pub mitm_confidence: f64,
    #[serde(default = "default_imsi_catch_confidence")]
    pub imsi_catch_confidence: f64,
    #[serde(default = "default_signaling_abuse_confidence")]
    pub signaling_abuse_confidence: f64,
    #[serde(default = "default_location_tracking_min_cells")]
    pub location_tracking_min_cells: usize,
}

fn default_correlation_window() -> u64 {
    60
}
fn default_true() -> bool {
    true
}
fn default_db_path() -> PathBuf {
    PathBuf::from("/var/lib/staticzero/alerts.db")
}
fn default_retention_hours() -> u64 {
    168
}
fn default_listen_addr() -> String {
    "0.0.0.0:9100".to_string()
}
fn default_min_confidence() -> f64 {
    0.6
}
fn default_mitm_confidence() -> f64 {
    0.92
}
fn default_imsi_catch_confidence() -> f64 {
    0.88
}
fn default_signaling_abuse_confidence() -> f64 {
    0.85
}
fn default_location_tracking_min_cells() -> usize {
    3
}


impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            correlation_window_secs: default_correlation_window(),
            telecom_detect: true,
            telecom_advanced: false,
            json_output: false,
        }
    }
}

impl Default for PersistenceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            db_path: default_db_path(),
            retention_hours: default_retention_hours(),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen_addr: default_listen_addr(),
        }
    }
}

impl Default for ThresholdConfig {
    fn default() -> Self {
        Self {
            min_confidence: default_min_confidence(),
            mitm_confidence: default_mitm_confidence(),
            imsi_catch_confidence: default_imsi_catch_confidence(),
            signaling_abuse_confidence: default_signaling_abuse_confidence(),
            location_tracking_min_cells: default_location_tracking_min_cells(),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("reading config from {}", path.display()))?;
        let config: Config = toml::from_str(&content).with_context(|| "parsing config TOML")?;
        Ok(config)
    }

    pub fn load_or_default(path: &Path) -> Self {
        match Self::load(path) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(
                    "Failed to load config from {}: {}. Using defaults.",
                    path.display(),
                    e
                );
                Self::default()
            }
        }
    }
}

pub struct ConfigWatcher {
    _watcher: RecommendedWatcher,
}

impl ConfigWatcher {
    pub fn start(config_path: PathBuf, tx: watch::Sender<Arc<Config>>) -> Result<Self> {
        let path = config_path.clone();
        let mut watcher =
            notify::recommended_watcher(move |res: Result<Event, notify::Error>| match res {
                Ok(event) => {
                    if event.kind.is_modify() || event.kind.is_create() {
                        info!("Config file changed, reloading");
                        match Config::load(&path) {
                            Ok(new_config) => {
                                let _ = tx.send(Arc::new(new_config));
                                info!("Config reloaded successfully");
                            }
                            Err(e) => {
                                error!("Failed to reload config: {}. Keeping previous config.", e);
                            }
                        }
                    }
                }
                Err(e) => error!("Config watch error: {}", e),
            })?;

        watcher.watch(&config_path, RecursiveMode::NonRecursive)?;
        Ok(Self { _watcher: watcher })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.engine.correlation_window_secs, 60);
        assert!(config.engine.telecom_detect);
        assert!(!config.engine.telecom_advanced);
        assert!(config.persistence.enabled);
        assert!(config.server.enabled);
        assert_eq!(config.server.listen_addr, "0.0.0.0:9100");
    }

    #[test]
    fn test_parse_toml() {
        let toml_str = r#"
[engine]
correlation_window_secs = 120
telecom_advanced = true
json_output = true

[persistence]
db_path = "/tmp/test.db"
retention_hours = 24

[server]
listen_addr = "127.0.0.1:8080"

[thresholds]
min_confidence = 0.7
mitm_confidence = 0.95
location_tracking_min_cells = 5
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.engine.correlation_window_secs, 120);
        assert!(config.engine.telecom_advanced);
        assert_eq!(config.persistence.retention_hours, 24);
        assert_eq!(config.server.listen_addr, "127.0.0.1:8080");
        assert!((config.thresholds.min_confidence - 0.7).abs() < f64::EPSILON);
        assert_eq!(config.thresholds.location_tracking_min_cells, 5);
    }
}
