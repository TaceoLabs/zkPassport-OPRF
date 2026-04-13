use std::sync::Arc;

use eyre::Context;
use taceo_oprf::service::{StartedServices, secret_manager::SecretManagerService};
use tokio_util::sync::CancellationToken;
use zkpassport_oprf_authentication::AuthModules;

use crate::{config::ZkPassportNodeConfig, services::FaceMatchAuthenticator};

pub mod config;
pub mod metrics;
pub(crate) mod services;

pub async fn start(
    config: ZkPassportNodeConfig,
    secret_manager: SecretManagerService,
    cancellation_token: CancellationToken,
) -> eyre::Result<(axum::Router, tokio::task::JoinHandle<eyre::Result<()>>)> {
    tracing::info!("starting oprf-service with config: {config:#?}");
    let node_config = config.node_config;
    let started_services = StartedServices::default();

    tracing::info!("connecting to RPC..");
    let rpc_provider =
        taceo_nodes_common::web3::RpcProviderBuilder::with_config(&config.rpc_provider_config)
            .environment(node_config.environment)
            .build()
            .await
            .context("while init blockchain connection")?;

    tracing::info!("init oprf request auth service..");
    let oprf_req_auth_service = Arc::new(
        FaceMatchAuthenticator::init(config.oracle_url)
            .await
            .context("while spawning authenticator")?,
    );

    tracing::info!("init oprf service..");
    let result = taceo_oprf::service::OprfServiceBuilder::init(
        node_config,
        secret_manager,
        rpc_provider,
        started_services.clone(),
        cancellation_token.clone(),
    )
    .await?
    .module(
        &format!("/{}", AuthModules::FaceMatch),
        oprf_req_auth_service,
    )
    .build();
    Ok(result)
}
