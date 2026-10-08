//! zkPassport OPRF node — service initialization and wiring.
//!
//! This crate provides the [`start`] function, which:
//!
//! 1. Spawns a background oracle health-check task that periodically polls
//!    the oracle's health endpoint and logs the result (see `services::health_check`).
//! 2. Initializes the `FaceMatchAuthenticator` and the `RegisterAuthenticator`
//!    that verify zkPassport proofs through an oracle.
//! 3. Builds an [`OprfServiceBuilder`](taceo_oprf::service::OprfServiceBuilder)
//!    and registers the face-match and register authentication modules.
//! 4. Nests the HTTP API (`/api`, e.g. commitment rotation backed by the
//!    passport registrations DB) next to the OPRF routes.
//!
//! The returned Axum router is consumed by the binary in `main.rs`.

use std::sync::Arc;

use axum::Router;
use eyre::Context;
use taceo_oprf::{
    service::{StartedServices, secret_manager::SecretManagerService},
    types::service::NodeInformation,
};
use zkpassport_oprf_authentication::AuthModules;

use crate::{
    auth_modules::{face_match::FaceMatchAuthenticator, register::RegisterAuthenticator},
    config::ZkPassportNodeConfig,
    services::{health_check, oracle_proxy::OracleProxy},
};

pub(crate) mod api;
pub(crate) mod auth_modules;
pub mod config;
pub mod metrics;
pub(crate) mod services;

pub use services::postgres::ZkPassportDb;

/// Initialize and wire the zkPassport OPRF service.
///
/// # Parameters
/// - `config` — node configuration (oracle URLs, OPRF service config)
/// - `secret_manager` — back-end for loading and storing OPRF key shares
/// - `zkpassport_db` — initialized users database, with migrations applied at startup
/// - `node_information` — identity and peer information for the OPRF service
/// - `version_str` — version reported by the OPRF service
///
/// # Returns
/// The Axum [`Router`] to be served by the HTTP listener.
///
/// # Errors
/// Returns an error if the oracle client cannot be initialized. The oracle
/// health-check task is spawned detached and only logs its results; it does not
/// affect the return value of this function.
pub fn start(
    config: ZkPassportNodeConfig,
    secret_manager: SecretManagerService,
    zkpassport_db: ZkPassportDb,
    node_information: &NodeInformation,
    version_str: String,
) -> eyre::Result<axum::Router> {
    let node_config = config.node_config;
    let started_services = StartedServices::default();

    // we use the client-builder to avoid panic if we cannot install tls backend
    let oracle_client = reqwest::ClientBuilder::new()
        .timeout(config.oracle_request_timeout)
        .build()
        .context("while building reqwest client")?;

    tokio::task::spawn(health_check::oracle_health_check_task(
        oracle_client.clone(),
        config.oracle_health_check_interval,
        config.oracle_health_check_url,
        config.oracle_retry_layer,
    ));

    tracing::info!("init oprf request auth service..");
    let oracle_proxy = OracleProxy::init(
        oracle_client,
        config.oracle_base_url,
        node_config.environment,
        config.oracle_retry_layer,
    )
    .context("while building oracle proxy")?;
    let face_match_auth_service = Arc::new(FaceMatchAuthenticator::init(oracle_proxy.clone()));
    let register_auth_service = Arc::new(RegisterAuthenticator::init(oracle_proxy.clone()));

    tracing::info!("init oprf service..");
    let oprf_router = taceo_oprf::service::OprfServiceBuilder::init(
        node_config,
        secret_manager,
        started_services.clone(),
        node_information,
        version_str,
    )
    .cors_for_info()
    .module(
        &format!("/{}", AuthModules::FaceMatch),
        face_match_auth_service,
    )
    .module(
        &format!("/{}", AuthModules::Register),
        register_auth_service,
    )
    .build();

    Ok(Router::new()
        .nest("/api", api::routes(oracle_proxy, zkpassport_db))
        .merge(oprf_router))
}
