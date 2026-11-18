//! End-to-end test against the local setup started by `just run-setup`, with real nodes, key-gen
//! and proof-verifier in `devmode`. Run it through `just e2e-test`.
//!
//! The fixtures only allow one rotation, so the test needs nodes without registrations.

use std::num::NonZeroUsize;

use reqwest::StatusCode;
use ruint::aliases::U160;
use taceo_oprf::types::OprfKeyId;
use zkpassport_oprf_authentication::error_codes;
use zkpassport_oprf_test_utils::{
    fixtures::{IdentifyFixture, load_v2_fixtures},
    node_client::{NodeClient, expect_rejected, expect_statuses},
};

const NODES: [&str; 3] = [
    "http://127.0.0.1:10000",
    "http://127.0.0.1:10001",
    "http://127.0.0.1:10002",
];
const THRESHOLD: usize = 2;
const CUSTOMER_OPRF_KEY_ID: u64 = 2;

#[tokio::test]
#[ignore = "needs the local setup, run via `just e2e-test`"]
async fn v2_lifecycle() -> eyre::Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("can install");
    let client = NodeClient::new(
        NODES.map(str::to_owned).to_vec(),
        NonZeroUsize::try_from(THRESHOLD).expect("THRESHOLD is non-zero"),
    )?;
    let oprf_key_id = OprfKeyId::new(U160::from(CUSTOMER_OPRF_KEY_ID));
    let fixtures = load_v2_fixtures();

    client.identify(&fixtures.identify).await?;

    let statuses = client.register(&fixtures.register).await?;
    expect_statuses(&statuses, &[StatusCode::OK])?;

    client.nullifier(oprf_key_id, &fixtures.query).await?;

    let statuses = client.rotate(&fixtures.rotate).await?;
    expect_statuses(&statuses, &[StatusCode::OK])?;

    // the query fixture still carries the replaced commitment
    let result = client.nullifier(oprf_key_id, &fixtures.query).await;
    expect_rejected(result, error_codes::ORACLE_BAD_REQUEST)?;

    let wrong_proofs = IdentifyFixture {
        proofs: fixtures.register.proofs,
        blinded_query: fixtures.identify.blinded_query,
    };
    let result = client.identify(&wrong_proofs).await;
    expect_rejected(result, error_codes::ORACLE_BAD_REQUEST)?;

    client.face_match(oprf_key_id).await?;
    Ok(())
}
