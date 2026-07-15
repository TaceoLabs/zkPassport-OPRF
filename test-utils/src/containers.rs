//! Testcontainer harness for the proof-verifier service.
//!
//! Only compiled when the `containers` feature is enabled.

use reqwest::Url;
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor, wait::HttpWaitStrategy},
    runners::AsyncRunner,
};
use tokio::sync::OnceCell;

const PROOF_VERIFIER_IMAGE: &str =
    "europe-west2-docker.pkg.dev/proof-verifier/proof-verifier/proof-verifier";
const PROOF_VERIFIER_TAG: &str = "57456d6dca5af880a0228bd79f069ce8ed13e18a";
const PROOF_VERIFIER_INTERNAL_PORT: u16 = 8080;

static PROOF_VERIFIER: OnceCell<(Url, ContainerAsync<GenericImage>)> = OnceCell::const_new();

/// Start the proof-verifier container (once) and return its URL.
///
/// Uses a process-wide [`OnceCell`] so the container is shared across tests
/// in the same test binary run.
pub async fn get_proof_verifier_url() -> Url {
    let (url, _) = PROOF_VERIFIER
        .get_or_init(|| async {
            let container = GenericImage::new(PROOF_VERIFIER_IMAGE, PROOF_VERIFIER_TAG)
                .with_wait_for(WaitFor::Http(Box::new(
                    HttpWaitStrategy::new("/").with_expected_status_code(200_u16),
                )))
                .with_exposed_port(PROOF_VERIFIER_INTERNAL_PORT.tcp())
                .with_env_var("PORT", PROOF_VERIFIER_INTERNAL_PORT.to_string())
                .with_env_var("HOST", "0.0.0.0")
                .start()
                .await
                .expect("Cannot start test-container");

            let host_port = container
                .get_host_port_ipv4(PROOF_VERIFIER_INTERNAL_PORT)
                .await
                .expect("Cannot extract port");

            (
                format!("http://127.0.0.1:{host_port}")
                    .parse()
                    .expect("Can parse URL"),
                container,
            )
        })
        .await;
    url.clone()
}
