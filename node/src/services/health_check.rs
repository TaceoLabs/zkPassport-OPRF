//! Oracle health-check background task.
//!
//! This module implements an outbound, periodic poll of the external
//! proof-verifier oracle's health endpoint. It does **not** expose any HTTP
//! endpoint on the node itself — there is no `/health` route or liveness probe
//! served by this code.
//!
//! # Behavior
//!
//! [`oracle_health_check_task`] runs forever in a `tokio::time::interval` loop.
//! On each tick it calls [`oracle_health_check`], which performs a single
//! `GET` to the configured URL and interprets the result.
//!
//! All reporting is via [`tracing`]; the task maintains no shared state and
//! does not affect service startup or graceful shutdown.
//!
//! # Configuration
//!
//! The task is configured through [`ZkPassportNodeConfig`](crate::config::ZkPassportNodeConfig):
//!
//! | Field | Env var | Required | Default |
//! |-------|---------|----------|---------|
//! | `oracle_health_check_url` | `TACEO_OPRF_NODE__SERVICE__ORACLE_HEALTH_CHECK_URL` | yes | — |
//! | `oracle_health_check_interval` | `TACEO_OPRF_NODE__SERVICE__ORACLE_HEALTH_CHECK_INTERVAL` | no | `5m` (humantime) |

use std::time::Duration;

use reqwest::{StatusCode, Url};

use crate::metrics;

#[derive(Debug, thiserror::Error)]
enum HealthCheckError {
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
    #[error("Unhealthy oracle with status: {status}, body: {body}")]
    Unhealthy { status: StatusCode, body: String },
}

pub(crate) async fn oracle_health_check_task(
    health_interval: Duration,
    health_url: Url,
) -> eyre::Result<tokio::task::JoinHandle<()>> {
    tracing::info!("spawning health check task");
    let mut interval = tokio::time::interval(health_interval);
    loop {
        interval.tick().await;

        match oracle_health_check(health_url.clone()).await {
            Ok(()) => {
                metrics::oracle::healthy();
                tracing::trace!("oracle healthy");
            }
            Err(HealthCheckError::Reqwest(err)) => {
                metrics::oracle::sick();
                tracing::error!(%err, "cannot reach oracle health url");
            }
            Err(HealthCheckError::Unhealthy { status, body }) => {
                metrics::oracle::sick();
                tracing::error!(%status, %body, "oracle health check returned non-200 status");
            }
        }
    }
}

async fn oracle_health_check(health_url: Url) -> Result<(), HealthCheckError> {
    let response = reqwest::get(health_url.clone()).await?;
    let status = response.status();
    if status == StatusCode::OK {
        Ok(())
    } else {
        let body = response
            .text()
            .await
            .unwrap_or_else(|err| format!("<failed to read body: {err}>"));
        Err(HealthCheckError::Unhealthy { status, body })
    }
}
