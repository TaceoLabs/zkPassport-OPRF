//! zkPassport OPRF node — service initialization and wiring.
//!
//! This crate provides the [`start`] function, which:
//!
//! 1. Initializes the `FaceMatchAuthenticator` and the `RegisterAuthenticator`
//!    that verify zkPassport proofs through an oracle.
//! 2. Builds an [`OprfServiceBuilder`](taceo_oprf::service::OprfServiceBuilder)
//!    and registers the face-match and register authentication modules.
//! 3. Nests the HTTP API (`/api`, e.g. commitment rotation backed by the
//!    passport registrations DB) next to the OPRF routes.
//!
//! The returned Axum router is consumed by the binary in `main.rs`.

use std::sync::Arc;

use axum::Router;
use eyre::Context;
use taceo_oprf::{
    service::{
        StartedServices, config::OprfNodeServiceConfig, secret_manager::SecretManagerService,
    },
    types::service::NodeInformation,
};
use zkpassport_oprf_authentication::AuthModules;

use crate::{
    auth_modules::{
        face_match::FaceMatchAuthenticator, nullifier::NullifierAuthenticator,
        register::RegisterAuthenticator,
    },
    config::ZkPassportNodeConfig,
    services::oracle_proxy::{OracleProxyService, proof_verifier::ProofVerifierOracle},
};

pub(crate) mod api;
pub(crate) mod auth_modules;
pub mod config;
pub mod metrics;
pub(crate) mod services;
#[cfg(test)]
mod tests;

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
/// Returns an error if the oracle client cannot be initialized.
pub fn start(
    config: ZkPassportNodeConfig,
    secret_manager: SecretManagerService,
    zkpassport_db: ZkPassportDb,
    node_information: &NodeInformation,
    version_str: String,
) -> eyre::Result<axum::Router> {
    // we use the client-builder to avoid panic if we cannot install tls backend
    let oracle_client = reqwest::ClientBuilder::new()
        .timeout(config.oracle_request_timeout)
        .build()
        .context("while building reqwest client")?;

    tracing::info!("init oprf request auth service..");
    let oracle_proxy: OracleProxyService = Arc::new(
        ProofVerifierOracle::init(
            oracle_client,
            config.oracle_base_url,
            config.node_config.environment,
            config.oracle_retry_layer,
        )
        .context("while building oracle proxy")?,
    );
    Ok(router(
        config.node_config,
        oracle_proxy,
        secret_manager,
        zkpassport_db,
        node_information,
        version_str,
    ))
}

/// Wires the authentication modules and the HTTP API around `oracle_proxy`.
fn router(
    node_config: OprfNodeServiceConfig,
    oracle_proxy: OracleProxyService,
    secret_manager: SecretManagerService,
    zkpassport_db: ZkPassportDb,
    node_information: &NodeInformation,
    version_str: String,
) -> Router {
    let face_match_auth_service = Arc::new(FaceMatchAuthenticator::init(oracle_proxy.clone()));
    let register_auth_service = Arc::new(RegisterAuthenticator::init(oracle_proxy.clone()));
    let nullifier_auth_service = Arc::new(NullifierAuthenticator::init(
        oracle_proxy.clone(),
        zkpassport_db.clone(),
    ));

    tracing::info!("init oprf service..");
    let oprf_router = taceo_oprf::service::OprfServiceBuilder::init(
        node_config,
        secret_manager,
        StartedServices::default(),
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
    .module(
        &format!("/{}", AuthModules::Nullifier),
        nullifier_auth_service,
    )
    .build();

    Router::new()
        .nest("/api", api::routes(oracle_proxy, zkpassport_db))
        .merge(oprf_router)
}
