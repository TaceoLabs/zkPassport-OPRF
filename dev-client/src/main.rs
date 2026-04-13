use alloy::{primitives::U160, providers::DynProvider};
use ark_ff::PrimeField;
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
use uuid::Uuid;
use zkpassport_oprf_authentication::{AuthModules, FaceMatchRequestAuth, ZKPassportProofResult};

struct FixtureData {
    proofs: Vec<ZKPassportProofResult>,
    private_nullifier: ark_babyjubjub::Fq,
    beta: ark_babyjubjub::Fr,
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    let hex = if !hex.len().is_multiple_of(2) {
        format!("0{hex}")
    } else {
        hex.to_string()
    };
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("Invalid hex"))
        .collect()
}

/// Load ZKPassport proofs, privateNullifier, and beta from the fixtures file.
fn load_fixture_data() -> FixtureData {
    let fixture_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/zkpassport-proofs.json"
    );
    let data = std::fs::read_to_string(fixture_path)
        .unwrap_or_else(|e| panic!("Failed to read fixture file {fixture_path}: {e}"));
    let value: serde_json::Value =
        serde_json::from_str(&data).expect("Failed to parse fixture JSON");

    let proofs: Vec<ZKPassportProofResult> =
        serde_json::from_value(value["proofs"].clone()).expect("Failed to parse proofs");

    let pn_hex = value["privateNullifier"]
        .as_str()
        .expect("Missing privateNullifier");
    let private_nullifier = ark_babyjubjub::Fq::from_be_bytes_mod_order(&hex_to_bytes(pn_hex));

    let beta_hex = value["beta"].as_str().expect("Missing beta");
    let beta = ark_babyjubjub::Fr::from_be_bytes_mod_order(&hex_to_bytes(beta_hex));

    FixtureData {
        proofs,
        private_nullifier,
        beta,
    }
}

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

#[tokio::main]
async fn main() -> eyre::Result<()> {
    taceo_nodes_observability::install_tracing("taceo=trace,warn");
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
        let fixture = load_fixture_data();

        // Use the fixture's privateNullifier and beta so the blinded query
        // matches the oprf_auth proof and passes oracle verification
        let verifiable_oprf_output = zkpassport_oprf_client::face_match_oprf(
            &config.nodes,
            config.threshold,
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
        let fixture = load_fixture_data();
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
}
