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
//! 1. Spawns a background oracle health-check task that periodically polls
//!    the oracle's health endpoint and logs the result (see `services::health_check`).
//! 2. Initializes the `FaceMatchAuthenticator`
//!    that verifies zkPassport proofs through an oracle.
//! 3. Builds an [`OprfServiceBuilder`](taceo_oprf::service::OprfServiceBuilder)
//!    and registers the face-match authentication module.
//!
//! The returned Axum router is consumed by the binary in `main.rs`.

use std::sync::Arc;

use eyre::Context;
use taceo_oprf::{
    service::{StartedServices, secret_manager::SecretManagerService},
    types::service::NodeInformation,
};
use tokio_util::sync::CancellationToken;
use zkpassport_oprf_authentication::AuthModules;

use crate::{
    config::ZkPassportNodeConfig,
    services::{face_match::FaceMatchAuthenticator, health_check},
};

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
/// Returns an error if the `FaceMatchAuthenticator` fails to initialize or the OPRF service
/// cannot be set up. The oracle health-check task is spawned detached and only logs its results
/// — it does not affect the return value of this function.
pub fn start(
    config: ZkPassportNodeConfig,
    secret_manager: SecretManagerService,
    node_information: NodeInformation,
    cancellation_token: CancellationToken,
) -> eyre::Result<axum::Router> {
    let node_config = config.node_config;
    let started_services = StartedServices::default();

    tokio::task::spawn(health_check::oracle_health_check_task(
        config.oracle_health_check_interval,
        config.oracle_health_check_url,
    ));

    tracing::info!("init oprf request auth service..");
    let oprf_req_auth_service = Arc::new(
        FaceMatchAuthenticator::init(config.oracle_verifier_url)
            .context("while spawning authenticator")?,
    );

    tracing::info!("init oprf service..");
    let router = taceo_oprf::service::OprfServiceBuilder::init(
        node_config,
        secret_manager,
        started_services.clone(),
        node_information,
        cancellation_token,
    )?
    .cors_for_info()
    .module(
        &format!("/{}", AuthModules::FaceMatch),
        oprf_req_auth_service,
    )
    .build();

    Ok(router)
}

#[cfg(test)]
mod tests {
    use crate::services::face_match::FaceMatchAuthenticator;

    #[tokio::test]
    #[ignore = "requires Docker and a running proof-verifier container; full test is follow-up work"]
    async fn success_test() -> eyre::Result<()> {
        let proof_verifier_url =
            zkpassport_oprf_test_utils::containers::get_proof_verifier_url().await;
        let _auth_service = FaceMatchAuthenticator::init(proof_verifier_url)?;
        // TODO: build OprfRequest from fixtures and assert authenticate succeeds
        Ok(())
    }
}
