//! Mock oracle for local development of the zkPassport OPRF service.
//!
//! This binary starts a lightweight Axum HTTP server that unconditionally
//! returns `verified: true` for every proof-verification request on
//! `POST /oprf/verify`. It is **not** intended for production use.
//!
//! Configure the bind address via the `MOCK_ORACLE_BIND_ADDR` environment
//! variable (default: `0.0.0.0:3000`).

use std::net::SocketAddr;

use axum::{
    Json, Router,
    response::IntoResponse,
    routing::{get, post},
};
use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::net::TcpListener;

#[derive(Parser, Debug)]
#[command(
    name = "mock-oracle",
    about = "Mock oracle server for zkPassport OPRF local development"
)]
struct Args {
    /// Address to bind the server to
    #[arg(long, env = "MOCK_ORACLE_BIND_ADDR", default_value = "0.0.0.0:3000")]
    bind_addr: SocketAddr,
}

#[derive(Serialize, Deserialize)]
struct OracleVerifyResponse {
    verified: bool,
    error: Option<String>,
}

async fn health() -> impl IntoResponse {
    "ok"
}

async fn verify(_body: Json<Value>) -> Json<OracleVerifyResponse> {
    tracing::debug!("received verify request, returning verified=true");
    Json(OracleVerifyResponse {
        verified: true,
        error: None,
    })
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let app = Router::new()
        .route("/", get(health))
        .route("/oprf/verify", post(verify));

    tracing::info!("starting mock-oracle on {}", args.bind_addr);
    let listener = TcpListener::bind(args.bind_addr)
        .await
        .expect("failed to bind");

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            tokio::signal::ctrl_c()
                .await
                .expect("failed to install CTRL+C handler");
        })
        .await
        .expect("server error");
}
