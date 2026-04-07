use alloy::{primitives::U160, providers::DynProvider};
use ark_ff::UniformRand as _;
use clap::Parser;
use eyre::Context;
use rand::{CryptoRng, Rng, SeedableRng as _};
use salted_nullifier_authentication::SaltedNullifierRequestAuth;
use taceo_oprf::{
    client::Connector,
    core::oprf::BlindingFactor,
    dev_client::{DevClient, DevClientConfig, StressTestItem, oprf_test_utils::health_checks},
    types::{
        OprfKeyId, ShareEpoch, api::OprfRequest, async_trait::async_trait, crypto::OprfPublicKey,
    },
};
use uuid::Uuid;

#[derive(Clone, Parser, Debug)]
struct SaltedNullifierDevClientConfig {
    #[clap(long, env = "OPRF_DEV_CLIENT_OPRF_KEY_ID")]
    pub oprf_key_id: Option<U160>,
    #[clap(flatten)]
    pub inner: DevClientConfig,
}

struct SaltedNullifierDevClient {
    oprf_key_id: Option<U160>,
}

#[derive(Clone)]
struct SaltedNullifierDevClientSetup {
    oprf_key_id: OprfKeyId,
    oprf_public_key: OprfPublicKey,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    taceo_nodes_observability::install_tracing(
        "taceo_oprf_dev_client=trace,salted_nullifier_dev_client=trace,warn",
    );
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("can install");
    let config = SaltedNullifierDevClientConfig::parse();
    tracing::info!("starting oprf-dev-client with config: {config:#?}");
    let dev_client = SaltedNullifierDevClient {
        oprf_key_id: config.oprf_key_id,
    };
    taceo_oprf::dev_client::run(config.inner, dev_client).await?;
    Ok(())
}

#[async_trait]
impl DevClient for SaltedNullifierDevClient {
    type Setup = SaltedNullifierDevClientSetup;
    type RequestAuth = SaltedNullifierRequestAuth;

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
        Ok(SaltedNullifierDevClientSetup {
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
        let mut rng = rand_chacha::ChaCha12Rng::from_entropy();

        // TODO compute a client-side proof and receive the encrypted unsalted nullifier
        let _action = ark_babyjubjub::Fq::rand(&mut rng);

        // TODO: pass real ZKPassport proofs from the client
        let proofs = vec![];

        // the client example internally checks the DLog equality
        let verifiable_oprf_output = salted_nullifier_client::salted_nullifier(
            &config.nodes,
            config.threshold,
            setup.oprf_key_id,
            proofs,
            connector,
            &mut rng,
        )
        .await
        .context("while computing salted nullifier")?;

        Ok(verifiable_oprf_output.epoch)
    }

    async fn prepare_stress_test_item<R: Rng + CryptoRng + Send>(
        &self,
        setup: &Self::Setup,
        rng: &mut R,
    ) -> eyre::Result<StressTestItem<Self::RequestAuth>> {
        let request_id = Uuid::new_v4();
        let action = ark_babyjubjub::Fq::rand(rng);
        let blinding_factor = BlindingFactor::rand(rng);
        let query = action;
        let blinded_query =
            taceo_oprf::core::oprf::client::blind_query(query, blinding_factor.clone());
        let init_request = OprfRequest {
            request_id,
            blinded_query: blinded_query.blinded_query(),
            auth: SaltedNullifierRequestAuth {
                oprf_key_id: setup.oprf_key_id,
                proofs: vec![],
            },
        };
        Ok(StressTestItem {
            request_id,
            blinded_query,
            init_request,
        })
    }

    fn get_oprf_key(&self, setup: &Self::Setup) -> OprfPublicKey {
        setup.oprf_public_key
    }

    fn get_oprf_key_id(&self, setup: &Self::Setup) -> OprfKeyId {
        setup.oprf_key_id
    }

    fn auth_module(&self) -> String {
        "face".to_owned()
    }
}
