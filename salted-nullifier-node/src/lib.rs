use std::sync::Arc;

use eyre::Context;
use salted_nullifier_authentication::SaltedNullifierOprfRequestAuthenticator;
use taceo_oprf::service::{StartedServices, secret_manager::SecretManagerService};
use tokio_util::sync::CancellationToken;

use crate::config::SaltedNullifierOprfNodeConfig;

pub mod config;
pub mod metrics;

pub async fn start(
    config: SaltedNullifierOprfNodeConfig,
    secret_manager: SecretManagerService,
    cancellation_token: CancellationToken,
) -> eyre::Result<(axum::Router, tokio::task::JoinHandle<eyre::Result<()>>)> {
    tracing::info!("starting oprf-service with config: {config:#?}");
    let service_config = config.node_config;
    let started_services = StartedServices::default();

    tracing::info!("init oprf request auth service..");
    let oprf_req_auth_service = Arc::new(
        SaltedNullifierOprfRequestAuthenticator::init(config.oracle_url)
            .await
            .context("while spawning authenticator")?,
    );

    tracing::info!("init oprf service..");
    let result = taceo_oprf::service::OprfServiceBuilder::init(
        service_config,
        secret_manager,
        started_services.clone(),
        cancellation_token.clone(),
    )
    .await?
    .module("/zkpassport", oprf_req_auth_service)
    .build();
    Ok(result)
}
