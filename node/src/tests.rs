//! Integration tests of the full node router: real OPRF client against three in-process nodes.
//!
//! The nodes share one Postgres container (a schema per node), hold Shamir shares of the same
//! OPRF keys, and verify proofs through a shared [`TestOracleProxy`].

use reqwest::StatusCode;
use taceo_oprf::types::ark_babyjubjub::EdwardsAffine;
use zkpassport_oprf_authentication::{SaltedIdentifier, error_codes};

use crate::{
    services::{
        oracle_proxy::test::{OracleCall, TestOracleProxy},
        postgres::DbError,
    },
    tests::harness::{
        NUM_NODES, PN, THRESHOLD, TestNodes, commitment, customer_key_id, service_error,
    },
};

mod harness;

// registration

#[tokio::test]
async fn nullifier_needs_registration_on_threshold_nodes() -> eyre::Result<()> {
    let nodes = TestNodes::start(TestOracleProxy::accept()).await?;
    let id = nodes.identifier(PN).await?;

    nodes.post_registration(0, id, commitment(1)).await?;
    let result = nodes.nullifier_oprf(PN, customer_key_id(), id).await;
    assert_eq!(
        service_error(result).error_code,
        error_codes::UNKNOWN_IDENTIFIER
    );

    nodes.post_registration(1, id, commitment(1)).await?;
    nodes.nullifier_oprf(PN, customer_key_id(), id).await?;
    Ok(())
}

#[tokio::test]
async fn oracle_rejection_reaches_client() -> eyre::Result<()> {
    let nodes = TestNodes::start(TestOracleProxy::reject("invalid proof")).await?;
    let err = service_error(nodes.register_oprf(PN).await);
    assert_eq!(err.error_code, error_codes::ORACLE_BAD_REQUEST);
    assert_eq!(err.msg.as_deref(), Some("invalid proof"));
    Ok(())
}

// nullifier

#[tokio::test]
async fn rotation_keeps_nullifier() -> eyre::Result<()> {
    let nodes = TestNodes::start(TestOracleProxy::knows_preimage_of(commitment(1))).await?;
    let id = nodes.identifier(PN).await?;
    nodes.register_all(id, commitment(1)).await?;
    let before = nodes.nullifier_oprf(PN, customer_key_id(), id).await?;

    for node in 0..NUM_NODES {
        assert_eq!(
            nodes.post_rotation(node, id, commitment(2)).await?,
            StatusCode::OK
        );
    }
    // the request below can only succeed if the nodes now expect the new secret
    nodes.oracle.set_known_preimage(commitment(2));
    let after = nodes.nullifier_oprf(PN, customer_key_id(), id).await?;

    // Rotating the authentication secret must not change the user's nullifier.
    assert_eq!(before.output, after.output);
    Ok(())
}

#[tokio::test]
async fn nullifier_needs_rotation_on_threshold_nodes() -> eyre::Result<()> {
    // after the rotation, the client can only prove knowledge of the new secret
    let nodes = TestNodes::start(TestOracleProxy::knows_preimage_of(commitment(2))).await?;
    let id = nodes.identifier(PN).await?;
    nodes.register_all(id, commitment(1)).await?;

    nodes.post_rotation(0, id, commitment(2)).await?;
    let result = nodes.nullifier_oprf(PN, customer_key_id(), id).await;
    assert_eq!(
        service_error(result).error_code,
        error_codes::ORACLE_BAD_REQUEST
    );

    nodes.post_rotation(1, id, commitment(2)).await?;
    nodes.nullifier_oprf(PN, customer_key_id(), id).await?;
    Ok(())
}

// face match

#[tokio::test]
async fn face_match_oprf() -> eyre::Result<()> {
    let nodes = TestNodes::start(TestOracleProxy::accept()).await?;
    let output = nodes.face_match_oprf(PN, customer_key_id()).await?;

    // every node that authenticated verified the proofs against the client's blinded query
    let calls = nodes.oracle.calls();
    assert!((THRESHOLD..=NUM_NODES).contains(&calls.len()));
    let expected = OracleCall::V1FaceMatch {
        blinded_query: output.blinded_request,
        proofs: vec![],
    };
    assert!(calls.iter().all(|call| *call == expected));
    Ok(())
}

// HTTP API

#[tokio::test]
async fn registration_status_codes() -> eyre::Result<()> {
    let nodes = TestNodes::start(TestOracleProxy::accept()).await?;
    let id = SaltedIdentifier::from(EdwardsAffine::default());
    assert_eq!(
        nodes.post_registration(0, id, commitment(1)).await?,
        StatusCode::OK
    );
    // a retry of the same registration succeeds
    assert_eq!(
        nodes.post_registration(0, id, commitment(1)).await?,
        StatusCode::OK
    );
    assert_eq!(
        nodes.post_registration(0, id, commitment(2)).await?,
        StatusCode::CONFLICT
    );
    Ok(())
}

#[tokio::test]
async fn rotation_status_codes() -> eyre::Result<()> {
    let nodes = TestNodes::start(TestOracleProxy::accept()).await?;
    let id = SaltedIdentifier::from(EdwardsAffine::default());
    assert_eq!(
        nodes.post_rotation(0, id, commitment(1)).await?,
        StatusCode::NOT_FOUND
    );
    nodes.post_registration(0, id, commitment(1)).await?;
    assert_eq!(
        nodes.post_rotation(0, id, commitment(2)).await?,
        StatusCode::OK
    );
    assert_eq!(
        nodes.post_rotation(0, id, commitment(1)).await?,
        StatusCode::CONFLICT
    );
    Ok(())
}

#[tokio::test]
async fn oracle_rejection_is_bad_request() -> eyre::Result<()> {
    let nodes = TestNodes::start(TestOracleProxy::reject("invalid proof")).await?;
    let id = SaltedIdentifier::from(EdwardsAffine::default());
    let db = &nodes.dbs[0];

    assert_eq!(
        nodes.post_registration(0, id, commitment(1)).await?,
        StatusCode::BAD_REQUEST
    );
    // the oracle check runs before anything is stored
    assert!(matches!(
        db.fetch_commitment(id).await,
        Err(DbError::UnknownIdentifier)
    ));

    db.insert_registration(id, commitment(1)).await?;
    assert_eq!(
        nodes.post_rotation(0, id, commitment(2)).await?,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(db.fetch_commitment(id).await?, commitment(1));
    // the 400s come from the oracle, not from rejected request bodies
    assert_eq!(
        nodes.oracle.calls(),
        vec![
            OracleCall::RegistrationCommitment,
            OracleCall::SecretRotation
        ]
    );
    Ok(())
}
