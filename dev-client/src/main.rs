//! Development and testing client for the zkPassport OPRF service.
//!
//! This binary exercises the full distributed OPRF + zkPassport authentication
//! flow against a local or remote setup. It loads fixture data (proofs,
//! `privateNullifier`, `beta`) from the `zkpassport-oprf-test-utils` crate and
//! delegates to the upstream [`taceo_oprf::dev_client::DevClient`] framework
//! for stress tests, reshare tests, and delete tests.
//!
//! Run via:
//!
//! ```sh
//! just run-dev-client <command>
//! ```

use std::num::NonZeroUsize;

use alloy::{primitives::U160, providers::DynProvider, transports::http::reqwest};
use clap::Parser;
use eyre::Context;
use rand::{CryptoRng, Rng};
use taceo_oprf::{
    client::Connector,
    core::oprf::BlindingFactor,
    dev_client::{DevClient, DevClientConfig, StressTestItem, health_checks},
    types::{
        OprfKeyId, ShareEpoch, api::OprfRequest, async_trait::async_trait, crypto::OprfPublicKey,
    },
};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt as _, util::SubscriberInitExt as _};
use uuid::Uuid;
use zkpassport_oprf_authentication::{AuthModules, FaceMatchRequestAuth};

#[derive(Clone, Parser, Debug)]
struct ZkPassportOprfDevClientConfig {
    #[clap(long, env = "OPRF_DEV_CLIENT_OPRF_KEY_ID")]
    pub oprf_key_id: Option<U160>,
    #[clap(flatten)]
    pub inner: DevClientConfig,
}

struct FaceMatchDevClient {
    oprf_key_id: Option<U160>,
}

#[derive(Clone)]
struct FaceMatchDevClientSetup {
    oprf_key_id: OprfKeyId,
    oprf_public_key: OprfPublicKey,
}

fn install_tracing(env_filter: &str) {
    let fmt_layer = fmt::layer().compact();
    let filter_layer = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(env_filter))
        .unwrap();

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .init();
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    install_tracing("taceo=trace,warn");
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("can install");
    let config = ZkPassportOprfDevClientConfig::parse();
    tracing::info!("starting oprf-dev-client with config: {config:#?}");
    let dev_client = FaceMatchDevClient {
        oprf_key_id: config.oprf_key_id,
    };
    taceo_oprf::dev_client::run(config.inner, dev_client).await?;
    Ok(())
}

#[async_trait]
impl DevClient for FaceMatchDevClient {
    type Setup = FaceMatchDevClientSetup;
    type RequestAuth = FaceMatchRequestAuth;

    async fn setup_oprf_test(
        &self,
        config: &DevClientConfig,
        provider: DynProvider,
    ) -> eyre::Result<Self::Setup> {
        let (oprf_key_id, oprf_public_key) = if let Some(oprf_key_id) = self.oprf_key_id {
            let oprf_key_id = OprfKeyId::new(oprf_key_id);
            let share_epoch = ShareEpoch::from(config.share_epoch);
            let oprf_public_key = health_checks::oprf_public_key_from_services(
                oprf_key_id,
                share_epoch,
                &config.nodes,
                config.max_wait_time,
            )
            .await?;
            (oprf_key_id, oprf_public_key)
        } else {
            let (oprf_key_id, oprf_public_key) = taceo_oprf::dev_client::init_key_gen(
                &config.nodes,
                config.oprf_key_registry_contract,
                provider,
                config.max_wait_time,
            )
            .await?;
            (oprf_key_id, oprf_public_key)
        };
        Ok(FaceMatchDevClientSetup {
            oprf_key_id,
            oprf_public_key,
        })
    }

    async fn run_oprf(
        &self,
        config: &DevClientConfig,
        setup: Self::Setup,
        connector: Connector,
    ) -> eyre::Result<ShareEpoch> {
        let fixture = zkpassport_oprf_test_utils::fixtures::load_fixture_data();

        // remove this if we update the upstream crate
        let threshold = NonZeroUsize::try_from(config.threshold).context("threshold is 0")?;

        // Use the fixture's privateNullifier and beta so the blinded query
        // matches the oprf_auth proof and passes oracle verification
        let verifiable_oprf_output = zkpassport_oprf_client::face_match_oprf(
            &config.nodes,
            threshold,
            setup.oprf_key_id,
            fixture.proofs,
            fixture.private_nullifier,
            fixture.beta,
            connector,
        )
        .await
        .context("while computing oprf with face-match")?;

        Ok(verifiable_oprf_output.epoch)
    }

    async fn prepare_stress_test_item<R: Rng + CryptoRng + Send>(
        &self,
        setup: &Self::Setup,
        _rng: &mut R,
    ) -> eyre::Result<StressTestItem<Self::RequestAuth>> {
        let request_id = Uuid::new_v4();
        let fixture = zkpassport_oprf_test_utils::fixtures::load_fixture_data();
        let blinding_factor =
            BlindingFactor::from_scalar(fixture.beta).expect("Invalid blinding factor");
        let blinded_query =
            taceo_oprf::core::oprf::client::blind_query(fixture.private_nullifier, blinding_factor);
        let init_request = OprfRequest {
            request_id,
            blinded_query: blinded_query.blinded_query(),
            auth: FaceMatchRequestAuth {
                oprf_key_id: setup.oprf_key_id,
                proofs: fixture.proofs,
            },
        };
        Ok(StressTestItem {
            request_id,
            blinded_query,
            init_request,
            auth_module: AuthModules::FaceMatch.to_string(),
        })
    }

    fn get_oprf_key(&self, setup: &Self::Setup) -> OprfPublicKey {
        setup.oprf_public_key
    }

    fn get_oprf_key_id(&self, setup: &Self::Setup) -> OprfKeyId {
        setup.oprf_key_id
    }

    async fn run_delegate_oprf(
        &self,
        _config: &DevClientConfig,
        _setup: Self::Setup,
        _delegate_service: Option<String>,
        _client: &reqwest::Client,
    ) -> eyre::Result<ShareEpoch> {
        eyre::bail!("Delegate pattern not supported for zkPassport dev-client")
    }
}
