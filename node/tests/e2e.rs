//! End-to-end test against the local setup started by `just run-setup`, with real nodes, key-gen
//! and proof-verifier in `devmode`. Run it through `just e2e-test`.
//!
//! The fixtures only allow one rotation, so the test needs nodes on which it did not run before.

use std::num::NonZeroUsize;

use reqwest::StatusCode;
use ruint::aliases::U160;
use taceo_oprf::types::OprfKeyId;
use zkpassport_oprf_authentication::{NonIdentifierOprfKeyId, error_codes, identifier_oprf_key_id};
use zkpassport_oprf_test_utils::{
    fixtures::{CommitmentFixture, IdentifyFixture, load_v2_fixtures},
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
    let customer_key_id = NonIdentifierOprfKeyId::new(U160::from(CUSTOMER_OPRF_KEY_ID))
        .expect("not the identifier key");
    let fixtures = load_v2_fixtures();

    let identifier_key = client.oprf_public_key(identifier_oprf_key_id()).await?;
    let customer_key = client
        .oprf_public_key(OprfKeyId::from(customer_key_id))
        .await?;
    assert_ne!(identifier_key.key, customer_key.key);

    assert_eq!(client.identify(&fixtures.identify).await?, identifier_key);
    // the dev-client may have registered the fixture on these nodes
    let statuses = client.register(&fixtures.register).await?;
    expect_statuses(&statuses, &[StatusCode::OK, StatusCode::CONFLICT])?;
    assert_eq!(
        client.nullifier(customer_key_id, &fixtures.query).await?,
        customer_key
    );
    assert_eq!(client.face_match(customer_key_id).await?, customer_key);

    // the verifier binds the proofs to the route and to the values the nodes forward
    let wrong_proofs = IdentifyFixture {
        proofs: fixtures.register.proofs.clone(),
        ..fixtures.identify.clone()
    };
    let result = client.identify(&wrong_proofs).await;
    expect_rejected(result, error_codes::ORACLE_BAD_REQUEST)?;
    let wrong_blinded_query = IdentifyFixture {
        blinded_query: fixtures.register.salted_identifier.inner(),
        ..fixtures.identify.clone()
    };
    let result = client.identify(&wrong_blinded_query).await;
    expect_rejected(result, error_codes::ORACLE_BAD_REQUEST)?;
    let wrong_commitment = CommitmentFixture {
        commitment: fixtures.rotate.commitment,
        ..fixtures.register.clone()
    };
    let statuses = client.register(&wrong_commitment).await?;
    expect_statuses(&statuses, &[StatusCode::BAD_REQUEST])?;
    let wrong_proofs = CommitmentFixture {
        proofs: fixtures.register.proofs.clone(),
        ..fixtures.rotate.clone()
    };
    let statuses = client.rotate(&wrong_proofs).await?;
    expect_statuses(&statuses, &[StatusCode::BAD_REQUEST])?;

    let statuses = client.rotate(&fixtures.rotate).await?;
    expect_statuses(&statuses, &[StatusCode::OK])?;

    // the query fixture still carries the replaced commitment
    let result = client.nullifier(customer_key_id, &fixtures.query).await;
    expect_rejected(result, error_codes::ORACLE_BAD_REQUEST)?;
    // replays change nothing
    let statuses = client.register(&fixtures.register).await?;
    expect_statuses(&statuses, &[StatusCode::CONFLICT])?;
    let statuses = client.rotate(&fixtures.rotate).await?;
    expect_statuses(&statuses, &[StatusCode::CONFLICT])?;
    Ok(())
}
