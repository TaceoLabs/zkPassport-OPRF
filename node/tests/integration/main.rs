//! Integration tests of the node: the real OPRF client and plain HTTP against a node started
//! through [`taceo_zkpassport_oprf_node::start`].
//!
//! The node runs with the users DB on a Postgres container and the HTTP oracle client. Its OPRF
//! keys are served from memory and the proof-verifier behind the oracle is faked, see
//! [`harness::FakeVerifier`].

use reqwest::StatusCode;
use serde_json::json;
use taceo_oprf::types::ark_babyjubjub::EdwardsAffine;
use zkpassport_oprf_authentication::{SaltedIdentifier, error_codes};

use crate::harness::{PN, TestNode, commitment, customer_key_id, hex_point, proofs, service_error};

mod harness;

#[tokio::test]
async fn v2_flow() -> eyre::Result<()> {
    let node = TestNode::start().await?;
    let proofs = serde_json::to_value(proofs())?;

    let output = node.register_oprf(PN).await?;
    let id = SaltedIdentifier::from(output.unblinded_response);
    let id_json = serde_json::to_value(id)?;
    assert_eq!(
        node.verifier.take_requests(),
        vec![(
            "/oprf/v2/identify".to_owned(),
            json!({ "proofs": proofs, "blinded_query": hex_point(output.blinded_request) })
        )]
    );

    assert_eq!(
        node.post_registration(id, commitment(1)).await?,
        StatusCode::OK
    );
    assert_eq!(
        node.verifier.take_requests(),
        vec![(
            "/oprf/v2/register".to_owned(),
            json!({ "proofs": proofs, "I": id_json, "commitment": "1" })
        )]
    );

    let before = node.nullifier_oprf(PN, customer_key_id(), id).await?;
    assert_eq!(
        node.verifier.take_requests(),
        vec![(
            "/oprf/v2/query".to_owned(),
            json!({
                "proofs": proofs,
                "blinded_query": hex_point(before.blinded_request),
                "I": id_json,
                "commitment": "1"
            })
        )]
    );

    assert_eq!(node.post_rotation(id, commitment(2)).await?, StatusCode::OK);
    assert_eq!(
        node.verifier.take_requests(),
        vec![(
            "/oprf/v2/rotate".to_owned(),
            json!({ "proofs": proofs, "I": id_json, "commitment": "2" })
        )]
    );

    // the node now verifies against the rotated commitment
    let after = node.nullifier_oprf(PN, customer_key_id(), id).await?;
    assert_eq!(
        node.verifier.take_requests(),
        vec![(
            "/oprf/v2/query".to_owned(),
            json!({
                "proofs": proofs,
                "blinded_query": hex_point(after.blinded_request),
                "I": id_json,
                "commitment": "2"
            })
        )]
    );
    // Rotating the authentication secret must not change the user's nullifier.
    assert_eq!(before.output, after.output);
    Ok(())
}

#[tokio::test]
async fn commitments_are_neither_overwritten_nor_reused() -> eyre::Result<()> {
    let node = TestNode::start().await?;
    let id = SaltedIdentifier::from(EdwardsAffine::default());
    assert_eq!(
        node.post_registration(id, commitment(1)).await?,
        StatusCode::OK
    );
    // a second registration cannot replace the commitment
    assert_eq!(
        node.post_registration(id, commitment(2)).await?,
        StatusCode::CONFLICT
    );

    assert_eq!(node.post_rotation(id, commitment(2)).await?, StatusCode::OK);
    // replays cannot restore the commitment the rotation replaced
    assert_eq!(
        node.post_rotation(id, commitment(1)).await?,
        StatusCode::CONFLICT
    );
    assert_eq!(
        node.post_registration(id, commitment(1)).await?,
        StatusCode::CONFLICT
    );

    node.verifier.take_requests();
    node.nullifier_oprf(PN, customer_key_id(), id).await?;
    let requests = node.verifier.take_requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].1["commitment"], "2");
    Ok(())
}

#[tokio::test]
async fn face_match_oprf() -> eyre::Result<()> {
    let node = TestNode::start().await?;
    let output = node.face_match_oprf(PN, customer_key_id()).await?;
    assert_eq!(
        node.verifier.take_requests(),
        vec![(
            "/verify-oprf-auth".to_owned(),
            json!({
                "blinded_unique_identifier": hex_point(output.blinded_request),
                "proofs": serde_json::to_value(proofs())?,
            })
        )]
    );
    Ok(())
}

#[tokio::test]
async fn verifier_rejects_proofs() -> eyre::Result<()> {
    let node = TestNode::start().await?;
    let id = SaltedIdentifier::from(EdwardsAffine::default());

    node.verifier.reject("invalid proof");
    let err = service_error(node.register_oprf(PN).await);
    assert_eq!(err.error_code, error_codes::ORACLE_BAD_REQUEST);
    assert_eq!(err.msg.as_deref(), Some("invalid proof"));
    assert_eq!(
        node.post_registration(id, commitment(1)).await?,
        StatusCode::BAD_REQUEST
    );

    // the rejected registration stored nothing
    node.verifier.accept();
    assert_eq!(
        node.post_rotation(id, commitment(2)).await?,
        StatusCode::NOT_FOUND
    );

    assert_eq!(
        node.post_registration(id, commitment(1)).await?,
        StatusCode::OK
    );
    node.verifier.reject("invalid proof");
    assert_eq!(
        node.post_rotation(id, commitment(2)).await?,
        StatusCode::BAD_REQUEST
    );

    // the rejected rotation left the commitment as it was
    node.verifier.accept();
    node.verifier.take_requests();
    node.nullifier_oprf(PN, customer_key_id(), id).await?;
    let requests = node.verifier.take_requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].1["commitment"], "1");
    Ok(())
}

#[tokio::test]
async fn verifier_fails() -> eyre::Result<()> {
    let node = TestNode::start().await?;
    node.verifier.respond(
        StatusCode::INTERNAL_SERVER_ERROR,
        json!({ "error": "boom" }),
    );

    let err = service_error(node.register_oprf(PN).await);
    assert_eq!(err.error_code, error_codes::INTERNAL);
    let id = SaltedIdentifier::from(EdwardsAffine::default());
    assert_eq!(
        node.post_registration(id, commitment(1)).await?,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    Ok(())
}

#[tokio::test]
async fn verifier_down() -> eyre::Result<()> {
    let node = TestNode::start_with_verifier_down().await?;

    let err = service_error(node.register_oprf(PN).await);
    assert_eq!(err.error_code, error_codes::ORACLE_NOT_REACHABLE);
    let id = SaltedIdentifier::from(EdwardsAffine::default());
    assert_eq!(
        node.post_registration(id, commitment(1)).await?,
        StatusCode::SERVICE_UNAVAILABLE
    );
    Ok(())
}
