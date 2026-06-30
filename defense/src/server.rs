use std::sync::Arc;
use std::time::Instant;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use tokio::sync::{Mutex, RwLock};

use crate::metrics::Metrics;
use crate::persistence::AlertStore;
use crate::TelecomCorrelationMetrics;

pub struct AppState {
    pub metrics: Metrics,
    pub store: Option<Mutex<AlertStore>>,
    pub correlation_metrics: RwLock<TelecomCorrelationMetrics>,
    pub start_time: Instant,
}

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/metrics", get(metrics_handler))
        .route("/api/v1/threats", get(recent_threats))
        .route("/api/v1/alerts", get(recent_alerts))
        .route("/api/v1/stats", get(stats))
        .with_state(state)
}

async fn health() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

async fn ready(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let uptime = state.start_time.elapsed().as_secs();
    if uptime < 2 {
        return (StatusCode::SERVICE_UNAVAILABLE, "warming up".to_string());
    }
    (StatusCode::OK, "ready".to_string())
}

async fn metrics_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    state
        .metrics
        .uptime_seconds
        .set(state.start_time.elapsed().as_secs() as i64);

    let cm = state.correlation_metrics.read().await;
    state
        .metrics
        .correlation_window_active
        .set(cm.multi_layer_correlations as i64);

    (
        StatusCode::OK,
        [("content-type", "text/plain; charset=utf-8")],
        state.metrics.encode(),
    )
}

async fn recent_threats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let Some(ref store) = state.store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "persistence disabled".to_string(),
        );
    };
    let store = store.lock().await;
    match store.recent_threats(50) {
        Ok(threats) => {
            let json = serde_json::to_string_pretty(
                &threats
                    .iter()
                    .map(|t| {
                        serde_json::json!({
                            "threat_id": t.threat_id,
                            "confidence": t.confidence,
                            "severity": t.severity,
                            "category": t.category,
                            "layers": t.layers,
                            "description": t.description,
                            "detected_at": t.detected_at,
                        })
                    })
                    .collect::<Vec<_>>(),
            )
            .unwrap_or_else(|_| "[]".into());
            (StatusCode::OK, json)
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("query failed: {}", e),
        ),
    }
}

async fn recent_alerts(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let Some(ref store) = state.store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "persistence disabled".to_string(),
        );
    };
    let store = store.lock().await;
    match store.recent_alerts(100) {
        Ok(alerts) => {
            let json = serde_json::to_string_pretty(
                &alerts
                    .iter()
                    .map(|a| {
                        serde_json::json!({
                            "timestamp_ns": a.timestamp_ns,
                            "alert_type": a.alert_type,
                            "severity": a.severity,
                            "pid": a.pid,
                            "context": a.context,
                            "details": a.details,
                            "ingested_at": a.ingested_at,
                        })
                    })
                    .collect::<Vec<_>>(),
            )
            .unwrap_or_else(|_| "[]".into());
            (StatusCode::OK, json)
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("query failed: {}", e),
        ),
    }
}

async fn stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let cm = state.correlation_metrics.read().await;
    let json = serde_json::json!({
        "uptime_seconds": state.start_time.elapsed().as_secs(),
        "events_processed": cm.events_processed,
        "threats_detected": cm.threats_detected,
        "multi_layer_correlations": cm.multi_layer_correlations,
        "false_positive_overrides": cm.false_positive_overrides,
    });
    (StatusCode::OK, serde_json::to_string_pretty(&json).unwrap())
}
