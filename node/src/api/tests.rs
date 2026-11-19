use std::{
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use axum::{Json, Router, http::StatusCode};
use serde_json::json;
use taceo_nodes_common::test_utils::{axum_test::TestServer, test_server};
use taceo_oprf::{
    service::{Environment, config::OprfNodeServiceConfig},
    types::ark_babyjubjub,
};
use tokio::sync::mpsc;
use zkpassport_oprf_authentication::{AuthCommitment, SaltedIdentifier};

use super::{ZkPassportDb, routes};
use crate::{
    OracleProxy as _, ProofVerifierOracle,
    config::RetryLayerConfig,
    services::{oracle_proxy::test::TestOracleProxy, postgres::DbError},
};

#[tokio::test]
async fn http_overload_and_cancellation_cleanup() -> eyre::Result<()> {
    let (_postgres, db) = ZkPassportDb::init_test().await?;
    let (_oracle_server, oracle, mut calls) = blocking_oracle()?;
    let (_api_server, url) = test_server(routes(&config(), Arc::new(oracle.clone()), db));
    let client = reqwest::Client::new();

    {
        let pending = oracle.registration_commitment(identifier(), commitment(), &[]);
        tokio::pin!(pending);
        tokio::select! {
            response = &mut pending => panic!("expected a blocked oracle request: {response:?}"),
            call = calls.recv() => call.expect("oracle received the blocking request"),
        }

        for path in ["/registration", "/rotation"] {
            let response = client
                .post(format!("{url}{path}"))
                .json(&request_body(path))
                .send()
                .await?;
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        }
        assert!(matches!(
            calls.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    let response = client
        .post(format!("{url}/registration"))
        .json(&request_body("/registration"))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    calls
        .try_recv()
        .expect("replacement request reached the oracle");
    assert!(matches!(
        calls.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    Ok(())
}

#[tokio::test]
async fn timeout_does_not_register_and_releases_oracle_capacity() -> eyre::Result<()> {
    let (_postgres, db) = ZkPassportDb::init_test().await?;
    let (_oracle_server, oracle, mut calls) = blocking_oracle()?;
    let mut config = config();
    config.session_lifetime = Duration::from_millis(100);
    let (_api_server, url) = test_server(routes(&config, Arc::new(oracle.clone()), db.clone()));

    let response = reqwest::Client::new()
        .post(format!("{url}/registration"))
        .json(&request_body("/registration"))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    calls
        .try_recv()
        .expect("timed-out request reached the oracle");
    assert!(matches!(
        db.fetch_commitment(identifier()).await,
        Err(DbError::UnknownIdentifier)
    ));
    oracle
        .registration_commitment(identifier(), commitment(), &[])
        .await?;
    Ok(())
}

#[tokio::test]
async fn body_limit_rejects_before_verification_and_accepts_the_boundary() -> eyre::Result<()> {
    let (_postgres, db) = ZkPassportDb::init_test().await?;
    let oracle = Arc::new(TestOracleProxy::reject("invalid proof"));
    let client = reqwest::Client::new();
    for path in ["/registration", "/rotation"] {
        let body = serde_json::to_vec(&request_body(path))?;
        let mut config = config();
        config.ws_max_message_size = body.len();
        let (_api_server, url) = test_server(routes(&config, oracle.clone(), db.clone()));

        let mut oversized = body.clone();
        oversized.push(b' ');
        let response = client
            .post(format!("{url}{path}"))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(oversized)
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert!(
            oracle.take_calls().is_empty(),
            "no verification for an oversized body"
        );

        let response = client
            .post(format!("{url}{path}"))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(oracle.take_calls().len(), 1);
    }
    Ok(())
}

fn blocking_oracle() -> eyre::Result<(TestServer, ProofVerifierOracle, mpsc::UnboundedReceiver<()>)>
{
    let (tx, rx) = mpsc::unbounded_channel();
    let first = Arc::new(AtomicBool::new(true));
    let app = Router::new().fallback(move || {
        let tx = tx.clone();
        let first = first.clone();
        async move {
            tx.send(()).expect("receiver alive");
            if first.swap(false, Ordering::SeqCst) {
                std::future::pending::<()>().await;
            }
            (StatusCode::OK, Json(json!({ "verified": true })))
        }
    });
    let (server, url) = test_server(app);
    let oracle = ProofVerifierOracle::init(
        reqwest::Client::new(),
        url.parse()?,
        Environment::Test,
        RetryLayerConfig {
            verifier_request_min_delay: Duration::from_millis(1),
            verifier_request_max_delay: Duration::from_millis(1),
            verifier_request_max_attempts: 2,
        },
        NonZeroUsize::MIN,
    )?;
    Ok((server, oracle, rx))
}

fn config() -> OprfNodeServiceConfig {
    OprfNodeServiceConfig::with_default_values(
        Environment::Test,
        ">=0.0.0".parse().expect("valid version requirement"),
    )
}

fn request_body(path: &str) -> serde_json::Value {
    let mut body = json!({ "I": identifier(), "proofs": [] });
    let field = if path == "/registration" {
        "commitment"
    } else {
        "new_commitment"
    };
    body[field] = json!(commitment());
    body
}

fn identifier() -> SaltedIdentifier {
    ark_babyjubjub::EdwardsAffine::default().into()
}

fn commitment() -> AuthCommitment {
    ark_babyjubjub::Fq::from(42u64).into()
}
