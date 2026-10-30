//! zkCert prover API. Phase 0 only exposes `GET /health`; the prove/vkey routes arrive in Phase 5.

use axum::{routing::get, Json, Router};
use serde::Serialize;
use std::net::SocketAddr;

#[derive(Serialize)]
struct Health {
    status: &'static str,
    version: &'static str,
}

async fn health() -> Json<Health> {
    Json(Health {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}

fn app() -> Router {
    Router::new().route("/health", get(health))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    // Bind to localhost by default; the server will handle sensitive uploads, so exposing it
    // on all interfaces must be an explicit choice.
    let addr: SocketAddr = std::env::var("ZKCERT_SERVER_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8080".into())
        .parse()
        .expect("ZKCERT_SERVER_ADDR must be host:port");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind");
    tracing::info!("zkcert-server listening on http://{addr}");
    axum::serve(listener, app())
        .with_graceful_shutdown(async {
            tokio::signal::ctrl_c().await.ok();
        })
        .await
        .expect("server error");
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    #[tokio::test]
    async fn health_returns_ok() {
        let res = app()
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), 200);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert!(std::str::from_utf8(&body)
            .unwrap()
            .contains("\"status\":\"ok\""));
    }

    #[tokio::test]
    async fn unknown_route_is_404() {
        let res = app()
            .oneshot(Request::get("/nope").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), 404);
    }
}
