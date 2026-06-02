#![deny(missing_docs)]
#![deny(clippy::all, clippy::pedantic)]
#![deny(
    clippy::allow_attributes_without_reason,
    clippy::assertions_on_result_states,
    clippy::dbg_macro,
    clippy::decimal_literal_representation,
    clippy::iter_over_hash_type,
    clippy::let_underscore_must_use,
    clippy::missing_assert_message,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::undocumented_unsafe_blocks,
    clippy::unnecessary_safety_comment,
    clippy::unwrap_used
)]
//! zkPassport OPRF node — service initialization and wiring.
//!
//! This crate provides the [`start`] function, which:
//!
//! 1. Initializes the `FaceMatchAuthenticator`
//!    that verifies zkPassport proofs through an oracle.
//! 2. Builds an [`OprfServiceBuilder`](taceo_oprf::service::OprfServiceBuilder)
//!    and registers the face-match authentication module.
//!
//! The returned Axum router is consumed by the binary in `main.rs`.

use std::sync::Arc;

use eyre::Context;
use taceo_oprf::service::{StartedServices, secret_manager::SecretManagerService};
use tokio_util::sync::CancellationToken;
use zkpassport_oprf_authentication::AuthModules;

use crate::{config::ZkPassportNodeConfig, services::FaceMatchAuthenticator};

pub mod config;
pub mod metrics;
pub(crate) mod services;

/// Initialize and wire the zkPassport OPRF service.
///
/// # Parameters
/// - `config` — node configuration (oracle URLs, OPRF service config)
/// - `secret_manager` — back-end for loading and storing OPRF key shares
/// - `cancellation_token` — signals all background tasks to shut down
///
/// # Returns
/// The Axum [`Router`](axum::Router) to be served by the HTTP listener.
///
/// # Errors
/// Returns an error if the oracle health-check fails or the OPRF service cannot initialize.
pub async fn start(
    config: ZkPassportNodeConfig,
    secret_manager: SecretManagerService,
    cancellation_token: CancellationToken,
) -> eyre::Result<axum::Router> {
    tracing::info!("starting oprf-service with config: {config:#?}");
    let node_config = config.node_config;
    let started_services = StartedServices::default();

    tracing::info!("init oprf request auth service..");
    let oprf_req_auth_service = Arc::new(
        FaceMatchAuthenticator::init(config.oracle_health_check_url, config.oracle_verifier_url)
            .await
            .context("while spawning authenticator")?,
    );

    tracing::info!("init oprf service..");
    let router = taceo_oprf::service::OprfServiceBuilder::init(
        node_config,
        secret_manager,
        started_services.clone(),
        cancellation_token.clone(),
    )
    .await?
    .cors_for_info()
    .module(
        &format!("/{}", AuthModules::FaceMatch),
        oprf_req_auth_service,
    )
    .build();

    Ok(router)
}
