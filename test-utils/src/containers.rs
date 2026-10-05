//! Testcontainer harness for the proof-verifier service.
//!
//! Only compiled when the `containers` feature is enabled.

use std::sync::{Arc, Weak};

use reqwest::Url;
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor, wait::HttpWaitStrategy},
    runners::AsyncRunner,
};
use tokio::sync::Mutex;

const PROOF_VERIFIER_IMAGE: &str =
    "europe-west2-docker.pkg.dev/proof-verifier/proof-verifier/proof-verifier";
const PROOF_VERIFIER_TAG: &str = "ea007610b71d589ed53381813fed87bc10f30cb9";
const PROOF_VERIFIER_INTERNAL_PORT: u16 = 8080;

/// Handle to the process-wide shared proof-verifier container.
///
/// The container is removed once the last handle is dropped. Hold the handle
/// as long as [`SharedProofVerifier::url`] is used and drop it inside a tokio
/// runtime context (true for `#[tokio::test]` bodies).
pub struct SharedProofVerifier {
    _container: ContainerAsync<GenericImage>,
    /// URL of the proof-verifier service.
    pub url: Url,
}

/// Returns a handle to a process-wide shared proof-verifier container.
///
/// Started lazily; the container lives while at least one handle is alive and
/// may be restarted if uses do not overlap in time.
pub async fn shared_proof_verifier() -> Arc<SharedProofVerifier> {
    static SHARED: Mutex<Weak<SharedProofVerifier>> = Mutex::const_new(Weak::new());
    let mut guard = SHARED.lock().await;
    if let Some(proof_verifier) = guard.upgrade() {
        return proof_verifier;
    }

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

    let proof_verifier = Arc::new(SharedProofVerifier {
        _container: container,
        url: format!("http://127.0.0.1:{host_port}")
            .parse()
            .expect("Can parse URL"),
    });
    *guard = Arc::downgrade(&proof_verifier);
    proof_verifier
}
