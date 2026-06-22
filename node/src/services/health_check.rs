use std::time::Duration;

use reqwest::{StatusCode, Url};

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
            Ok(()) => tracing::info!("oracle healthy"),
            Err(HealthCheckError::Reqwest(err)) => {
                tracing::error!(%err, "cannot reach oracle health url");
            }
            Err(HealthCheckError::Unhealthy { status, body }) => {
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
