use crate::sandbox::{self, SandboxConfig};
use crate::types::{ExecuteRequest, ExecuteResponse, MAX_BODY_BYTES};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    routing::{get, post},
};
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::Semaphore;

#[derive(Clone)]
struct AppState {
    cfg: SandboxConfig,
    permits: Arc<Semaphore>,
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

type ApiError = (StatusCode, Json<ErrorBody>);

fn error(code: StatusCode, message: impl Into<String>) -> ApiError {
    (code, Json(ErrorBody { error: message.into() }))
}

pub fn router(cfg: SandboxConfig, max_concurrency: usize) -> Router {
    let state = AppState {
        cfg,
        permits: Arc::new(Semaphore::new(max_concurrency)),
    };
    Router::new()
        .route("/healthz", get(|| async { Json(serde_json::json!({"status": "ok"})) }))
        .route("/readyz", get(ready))
        .route("/execute", post(execute))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

async fn ready(State(state): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    sandbox::prerequisites(&state.cfg)
        .map_err(|e| error(StatusCode::SERVICE_UNAVAILABLE, e.to_string()))?;
    Ok(Json(serde_json::json!({"status": "ready"})))
}

async fn execute(
    State(state): State<AppState>,
    Json(req): Json<ExecuteRequest>,
) -> Result<Json<ExecuteResponse>, ApiError> {
    req.validate().map_err(|e| error(StatusCode::BAD_REQUEST, e.to_string()))?;
    let permit = state.permits.clone().try_acquire_owned()
        .map_err(|_| error(StatusCode::TOO_MANY_REQUESTS, "concurrency limit reached"))?;
    let cfg = state.cfg.clone();
    // Dropping a disconnected HTTP request does not cancel spawn_blocking.
    // The permit and sandbox guard remain owned by the background worker.
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        sandbox::execute(req, &cfg)
    })
    .await
    .map_err(|e| error(StatusCode::INTERNAL_SERVER_ERROR, format!("execution worker failed: {e}")))?;
    result.map(Json).map_err(|e| error(StatusCode::SERVICE_UNAVAILABLE, e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    #[tokio::test]
    async fn health_route() {
        let response = router(SandboxConfig::default(), 1)
            .oneshot(Request::builder().uri("/healthz").body(Body::empty()).unwrap())
            .await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn invalid_language_rejected_before_launch() {
        let response = router(SandboxConfig::default(), 1)
            .oneshot(
                Request::builder().uri("/execute").method("POST")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"language":"ruby","code":"puts 1"}"#)).unwrap(),
            )
            .await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
