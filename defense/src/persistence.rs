use std::path::Path;

use anyhow::{Context, Result};
use rusqlite::{params, Connection};

use crate::CorrelatedThreat;

pub struct AlertStore {
    conn: Connection,
}

impl AlertStore {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)
            .with_context(|| format!("failed to open database at {}", path.display()))?;

        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "wal_autocheckpoint", 1000)?;

        let store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<()> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp_ns INTEGER NOT NULL,
                alert_type INTEGER NOT NULL,
                severity INTEGER NOT NULL,
                pid INTEGER NOT NULL,
                context INTEGER NOT NULL,
                details TEXT NOT NULL,
                ingested_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                threat_id INTEGER NOT NULL UNIQUE,
                confidence REAL NOT NULL,
                severity INTEGER NOT NULL,
                category TEXT NOT NULL,
                layers TEXT NOT NULL,
                description TEXT NOT NULL,
                events_json TEXT NOT NULL,
                detected_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp_ns);
            CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(alert_type);
            CREATE INDEX IF NOT EXISTS idx_threats_category ON threats(category);
            CREATE INDEX IF NOT EXISTS idx_threats_detected ON threats(detected_at);",
        )?;
        Ok(())
    }

    pub fn insert_alert(
        &self,
        timestamp_ns: u64,
        alert_type: u32,
        severity: u32,
        pid: u32,
        context: u64,
        details: &str,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO alerts (timestamp_ns, alert_type, severity, pid, context, details)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                timestamp_ns as i64,
                alert_type,
                severity,
                pid,
                context as i64,
                details
            ],
        )?;
        Ok(())
    }

    pub fn insert_threat(&self, threat: &CorrelatedThreat) -> Result<()> {
        let layers: Vec<String> = threat
            .layers_involved
            .iter()
            .map(|l| format!("{:?}", l))
            .collect();
        let events_json = serde_json::to_string(&threat.events)?;

        self.conn.execute(
            "INSERT OR REPLACE INTO threats (threat_id, confidence, severity, category, layers, description, events_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                threat.threat_id as i64,
                threat.confidence,
                threat.severity as u32,
                format!("{:?}", threat.category),
                layers.join(","),
                threat.description,
                events_json,
            ],
        )?;
        Ok(())
    }

    pub fn recent_alerts(&self, limit: u32) -> Result<Vec<StoredAlert>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, timestamp_ns, alert_type, severity, pid, context, details, ingested_at
             FROM alerts ORDER BY timestamp_ns DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], |row| {
            Ok(StoredAlert {
                id: row.get(0)?,
                timestamp_ns: row.get::<_, i64>(1)? as u64,
                alert_type: row.get(2)?,
                severity: row.get(3)?,
                pid: row.get(4)?,
                context: row.get::<_, i64>(5)? as u64,
                details: row.get(6)?,
                ingested_at: row.get(7)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!(e))
    }

    pub fn recent_threats(&self, limit: u32) -> Result<Vec<StoredThreat>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, threat_id, confidence, severity, category, layers, description, detected_at
             FROM threats ORDER BY detected_at DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], |row| {
            Ok(StoredThreat {
                id: row.get(0)?,
                threat_id: row.get::<_, i64>(1)? as u64,
                confidence: row.get(2)?,
                severity: row.get(3)?,
                category: row.get(4)?,
                layers: row.get(5)?,
                description: row.get(6)?,
                detected_at: row.get(7)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!(e))
    }

    pub fn alert_count_since(&self, since_ns: u64) -> Result<u64> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM alerts WHERE timestamp_ns >= ?1",
            params![since_ns as i64],
            |row| row.get(0),
        )?;
        Ok(count as u64)
    }

    pub fn threat_count_by_category(&self) -> Result<Vec<(String, u64)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT category, COUNT(*) FROM threats GROUP BY category")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64))
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!(e))
    }
}

#[derive(Debug, Clone)]
pub struct StoredAlert {
    pub id: i64,
    pub timestamp_ns: u64,
    pub alert_type: u32,
    pub severity: u32,
    pub pid: u32,
    pub context: u64,
    pub details: String,
    pub ingested_at: String,
}

#[derive(Debug, Clone)]
pub struct StoredThreat {
    pub id: i64,
    pub threat_id: u64,
    pub confidence: f64,
    pub severity: u32,
    pub category: String,
    pub layers: String,
    pub description: String,
    pub detected_at: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CorrelatedThreat, TelecomEvent, TelecomLayer, ThreatCategory};

    #[test]
    fn test_open_in_memory_and_migrate() {
        let store = AlertStore::open_in_memory().unwrap();
        assert_eq!(store.alert_count_since(0).unwrap(), 0);
    }

    #[test]
    fn test_insert_and_query_alerts() {
        let store = AlertStore::open_in_memory().unwrap();
        store
            .insert_alert(1_000_000_000, 19, 3, 100, 0xABCD, "cell_id=43981, signal_delta=0")
            .unwrap();
        store
            .insert_alert(2_000_000_000, 20, 4, 101, 0x1234, "cell_id=4660, target_rat=0")
            .unwrap();

        let alerts = store.recent_alerts(10).unwrap();
        assert_eq!(alerts.len(), 2);
        assert_eq!(alerts[0].timestamp_ns, 2_000_000_000);
        assert_eq!(alerts[1].alert_type, 19);
    }

    #[test]
    fn test_insert_and_query_threats() {
        let store = AlertStore::open_in_memory().unwrap();
        let threat = CorrelatedThreat {
            threat_id: 1,
            confidence: 0.92,
            severity: 4,
            category: ThreatCategory::ManInTheMiddle,
            layers_involved: vec![TelecomLayer::Radio, TelecomLayer::Nas],
            events: vec![TelecomEvent {
                timestamp_ns: 1_000_000_000,
                layer: TelecomLayer::Radio,
                event_type: 19,
                cell_id: 0xABCD,
                imsi_hash: 0,
                details: "test".to_string(),
            }],
            description: "Rogue BTS + downgrade".to_string(),
        };

        store.insert_threat(&threat).unwrap();
        let threats = store.recent_threats(10).unwrap();
        assert_eq!(threats.len(), 1);
        assert_eq!(threats[0].category, "ManInTheMiddle");
        assert!((threats[0].confidence - 0.92).abs() < f64::EPSILON);
    }

    #[test]
    fn test_threat_count_by_category() {
        let store = AlertStore::open_in_memory().unwrap();
        for i in 0..3 {
            let threat = CorrelatedThreat {
                threat_id: i + 1,
                confidence: 0.9,
                severity: 4,
                category: ThreatCategory::ManInTheMiddle,
                layers_involved: vec![TelecomLayer::Radio],
                events: vec![],
                description: "test".to_string(),
            };
            store.insert_threat(&threat).unwrap();
        }

        let counts = store.threat_count_by_category().unwrap();
        assert_eq!(counts.len(), 1);
        assert_eq!(counts[0].1, 3);
    }
}
