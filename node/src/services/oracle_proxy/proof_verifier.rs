use std::{fmt::Write as _, num::NonZeroUsize, sync::Arc, time::Instant};

use ark_serialize::CanonicalSerialize as _;
use backon::{ExponentialBuilder, Retryable as _};
use reqwest::{StatusCode, Url};
use serde::{Deserialize, Serialize, Serializer, ser::Error as _};
use taceo_oprf::{
    service::Environment,
    types::{ark_babyjubjub, async_trait::async_trait},
};
use tokio::sync::Semaphore;
use tracing::instrument;
use zkpassport_oprf_authentication::{AuthCommitment, SaltedIdentifier, ZKPassportProofResult};

use crate::{
    config::RetryLayerConfig,
    metrics,
    services::oracle_proxy::{OracleError, OracleProxy, Result},
};

const FACE_MATCH_PATH: &str = "verify-oprf-auth";
const IDENTIFY_PATH: &str = "oprf/v2/identify";
const REGISTER_PATH: &str = "oprf/v2/register";
const QUERY_PATH: &str = "oprf/v2/query";
const ROTATE_PATH: &str = "oprf/v2/rotate";

/// Request body of the oracle's face-match endpoint.
#[derive(Debug, Serialize)]
struct FaceMatchRequest<'a> {
    blinded_unique_identifier: HexPoint,
    proofs: &'a [ZKPassportProofResult],
}

/// Request body of `oprf/v2/identify`.
#[derive(Debug, Serialize)]
struct IdentifyRequest<'a> {
    proofs: &'a [ZKPassportProofResult],
    blinded_query: HexPoint,
}

/// Request body of `oprf/v2/register` and `oprf/v2/rotate`.
#[derive(Debug, Serialize)]
struct CommitmentRequest<'a> {
    proofs: &'a [ZKPassportProofResult],
    #[serde(rename = "I")]
    salted_identifier: SaltedIdentifier,
    /// The commitment to check the registration proof against.
    commitment: AuthCommitment,
}

/// Request body of `oprf/v2/query`.
#[derive(Debug, Serialize)]
struct QueryRequest<'a> {
    proofs: &'a [ZKPassportProofResult],
    blinded_query: HexPoint,
    #[serde(rename = "I")]
    salted_identifier: SaltedIdentifier,
    /// The commitment stored for `I`.
    commitment: AuthCommitment,
}

/// Response body received from the oracle's verification endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct OracleResponse {
    /// Whether the oracle accepted the proofs.
    verified: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Optional error message returned when `verified` is `false`.
    error: Option<String>,
}

/// Full oracle endpoint URLs, derived once from the configured base URL.
#[derive(Debug, Clone)]
struct OracleEndpoints {
    /// `<base>/verify-oprf-auth`, used by v1 face-match authentication.
    face_match: Url,
    /// `<base>/oprf/v2/identify`, used by [`OracleProxy::salted_identifier`].
    identify: Url,
    /// `<base>/oprf/v2/register`, used by [`OracleProxy::registration_commitment`].
    register: Url,
    /// `<base>/oprf/v2/query`, used by [`OracleProxy::preimage_proof`].
    query: Url,
    /// `<base>/oprf/v2/rotate`, used by [`OracleProxy::secret_rotation`].
    rotate: Url,
}

impl OracleEndpoints {
    /// Appends each endpoint path to `base_url`.
    ///
    /// In [`Environment::Dev`] every endpoint gets `?devmode=true`; other environments
    /// get no query. Any query on `base_url` is dropped.
    fn new(mut base_url: Url, environment: Environment) -> eyre::Result<Self> {
        // `Url::join` replaces the last path segment unless the base ends with '/'
        if !base_url.path().ends_with('/') {
            let path = format!("{}/", base_url.path());
            base_url.set_path(&path);
        }
        let endpoint = |path: &str| -> eyre::Result<Url> {
            let mut url = base_url.join(path)?;
            if environment.is_dev() {
                url.set_query(Some("devmode=true"));
            }
            Ok(url)
        };
        Ok(Self {
            face_match: endpoint(FACE_MATCH_PATH)?,
            identify: endpoint(IDENTIFY_PATH)?,
            register: endpoint(REGISTER_PATH)?,
            query: endpoint(QUERY_PATH)?,
            rotate: endpoint(ROTATE_PATH)?,
        })
    }
}

/// [`OracleProxy`] backed by the zkPassport proof-verifier, with shared retry policy.
#[derive(Debug, Clone)]
pub struct ProofVerifierOracle {
    client: reqwest::Client,
    endpoints: OracleEndpoints,
    backoff: ExponentialBuilder,
    permits: Arc<Semaphore>,
}

impl ProofVerifierOracle {
    /// Creates an oracle that sends its requests with `client` to the endpoints below `base_url`.
    ///
    /// # Errors
    /// Returns an error if the endpoint URLs cannot be derived from `base_url`.
    pub fn init(
        client: reqwest::Client,
        base_url: Url,
        environment: Environment,
        retry_layer: RetryLayerConfig,
        max_concurrent_requests: NonZeroUsize,
    ) -> eyre::Result<Self> {
        Ok(Self {
            client,
            endpoints: OracleEndpoints::new(base_url, environment)?,
            backoff: retry_layer.exponential_backoff(),
            permits: Arc::new(Semaphore::new(max_concurrent_requests.get())),
        })
    }

    /// Posts `body` to `url`, retrying transient failures.
    ///
    /// `Ok(())` iff the oracle answered 200. A 400 becomes [`OracleError::BadRequest`] with the
    /// oracle's error message.
    #[instrument(level = "info", skip_all, fields(url=%url))]
    async fn post(&self, url: &Url, body: &impl Serialize) -> Result<()> {
        tracing::trace!("sending verify request to oracle: {url}");
        (|| async {
            let (status, body) = {
                let _permit = self.permits.try_acquire()?;
                let response = self.client.post(url.clone()).json(body).send().await?;
                let status = response.status();
                if status == StatusCode::OK {
                    tracing::trace!("oracle verified proofs successfully");
                    return Ok(());
                }
                let body = response.text().await?;
                Result::Ok((status, body))
            }?;
            if status == StatusCode::BAD_REQUEST {
                tracing::trace!("received BAD REQUEST from oracle");
                let error_msg = match serde_json::from_str::<OracleResponse>(&body) {
                    Ok(response) => response.error.unwrap_or_else(|| "unknown".to_owned()),
                    Err(err) => {
                        tracing::warn!(%err, "could not parse oracle verify response: {err}");
                        "unknown".to_owned()
                    }
                };
                Err(OracleError::BadRequest(error_msg))
            } else if status == StatusCode::REQUEST_TIMEOUT {
                tracing::trace!("oracle request ran into timeout");
                Err(OracleError::OracleTimeout)
            } else {
                tracing::trace!("unknown status code: {status}");
                Err(OracleError::UnexpectedStatusCode { status, body })
            }
        })
        .retry(self.backoff)
        .sleep(tokio::time::sleep)
        .when(is_retryable_error)
        .notify(|err, duration| {
            metrics::oracle::inc_retries();
            tracing::warn!(%err, retry_in = ?duration, "retrying request to {url}");
        })
        .await
    }
}

#[async_trait]
impl OracleProxy for ProofVerifierOracle {
    async fn salted_identifier(
        &self,
        blinded_query: ark_babyjubjub::EdwardsAffine,
        proofs: &[ZKPassportProofResult],
    ) -> Result<()> {
        let request = IdentifyRequest {
            proofs,
            blinded_query: HexPoint(blinded_query),
        };
        let start = Instant::now();
        let result = self.post(&self.endpoints.identify, &request).await;
        metrics::oracle::record_identify_duration(start.elapsed());
        result
    }

    async fn registration_commitment(
        &self,
        salted_identifier: SaltedIdentifier,
        commitment: AuthCommitment,
        proofs: &[ZKPassportProofResult],
    ) -> Result<()> {
        let request = CommitmentRequest {
            proofs,
            salted_identifier,
            commitment,
        };
        let start = Instant::now();
        let result = self.post(&self.endpoints.register, &request).await;
        metrics::oracle::record_register_duration(start.elapsed());
        result
    }

    async fn preimage_proof(
        &self,
        blinded_query: ark_babyjubjub::EdwardsAffine,
        salted_identifier: SaltedIdentifier,
        auth_commitment: AuthCommitment,
        proofs: &[ZKPassportProofResult],
    ) -> Result<()> {
        let request = QueryRequest {
            proofs,
            blinded_query: HexPoint(blinded_query),
            salted_identifier,
            commitment: auth_commitment,
        };
        let start = Instant::now();
        let result = self.post(&self.endpoints.query, &request).await;
        metrics::oracle::record_query_duration(start.elapsed());
        result
    }

    async fn secret_rotation(
        &self,
        salted_identifier: SaltedIdentifier,
        new_commitment: AuthCommitment,
        proofs: &[ZKPassportProofResult],
    ) -> Result<()> {
        let request = CommitmentRequest {
            proofs,
            salted_identifier,
            commitment: new_commitment,
        };
        let start = Instant::now();
        let result = self.post(&self.endpoints.rotate, &request).await;
        metrics::oracle::record_rotate_duration(start.elapsed());
        result
    }

    async fn v1_face_match(
        &self,
        blinded_query: ark_babyjubjub::EdwardsAffine,
        proofs: &[ZKPassportProofResult],
    ) -> Result<()> {
        let request = FaceMatchRequest {
            blinded_unique_identifier: HexPoint(blinded_query),
            proofs,
        };
        let start = Instant::now();
        let result = self.post(&self.endpoints.face_match, &request).await;
        metrics::oracle::record_face_match_duration(start.elapsed());
        result
    }
}

/// A `BabyJubJub` affine point, serialized as the hex string `"0x<x><y>"`.
///
/// Both coordinates are big-endian, matching the public outputs of the circuits.
#[derive(Debug)]
struct HexPoint(ark_babyjubjub::EdwardsAffine);

impl Serialize for HexPoint {
    fn serialize<S: Serializer>(&self, ser: S) -> std::result::Result<S::Ok, S::Error> {
        let mut hex = String::from("0x");
        for coordinate in [self.0.x, self.0.y] {
            let mut little_endian = Vec::new();
            coordinate
                .serialize_compressed(&mut little_endian)
                .map_err(S::Error::custom)?;
            for byte in little_endian.iter().rev() {
                write!(hex, "{byte:02x}").expect("writing to a string cannot fail");
            }
        }
        ser.serialize_str(&hex)
    }
}

fn is_retryable_error(e: &OracleError) -> bool {
    // Transport-level failures: no usable response came back.
    //
    // HTTP status failures worth retrying:
    // * 429 TOO MANY REQUESTS
    // * 502 BAD GATEWAY
    // * 503 SERVICE UNAVAILABLE
    // * 504 GATEWAY TIMEOUT
    //
    // We do not retry INTERNAL SERVER ERROR, nor REQUEST TIMEOUT: the oracle already spent its
    // full verification budget on these proofs and would likely time out again.
    match e {
        OracleError::OracleNotReachable(error) => error.is_connect(),
        OracleError::UnexpectedStatusCode { status, .. } => matches!(
            *status,
            StatusCode::TOO_MANY_REQUESTS
                | StatusCode::BAD_GATEWAY
                | StatusCode::SERVICE_UNAVAILABLE
                | StatusCode::GATEWAY_TIMEOUT
        ),
        OracleError::BadRequest(_)
        | OracleError::InvalidMessage(_)
        | OracleError::OracleTimeout
        | OracleError::Overloaded(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use axum::{Json, Router, http::StatusCode as AxumStatus, routing::post};
    use serde_json::json;
    use taceo_nodes_common::test_utils::{axum_test::TestServer, test_server};

    use super::*;

    /// Serves `app` and returns a [`ProofVerifierOracle`] pointing at it.
    ///
    /// The server stops when the returned [`TestServer`] is dropped.
    fn serve(
        app: Router,
        retry: RetryLayerConfig,
    ) -> eyre::Result<(TestServer, ProofVerifierOracle)> {
        let (server, url) = test_server(app);
        let oracle = ProofVerifierOracle::init(
            reqwest::Client::new(),
            url.parse()?,
            Environment::Test,
            retry,
            NonZeroUsize::MIN,
        )?;
        Ok((server, oracle))
    }

    /// Serves a mock oracle answering the face-match endpoint with `status` and `body`.
    fn mock_oracle(
        status: AxumStatus,
        body: serde_json::Value,
    ) -> eyre::Result<(TestServer, ProofVerifierOracle)> {
        let app = Router::new().route(
            &format!("/{FACE_MATCH_PATH}"),
            post(move || {
                let body = body.clone();
                async move { (status, Json(body)) }
            }),
        );
        serve(app, RetryLayerConfig::disabled())
    }

    async fn face_match(oracle: &ProofVerifierOracle) -> Result<()> {
        let fixture = zkpassport_oprf_test_utils::fixtures::load_fixture_data();
        let blinding_factor = taceo_oprf::core::oprf::BlindingFactor::from_scalar(fixture.beta)
            .expect("Invalid blinding factor");
        let blinded_query =
            taceo_oprf::core::oprf::client::blind_query(fixture.private_nullifier, blinding_factor)
                .blinded_query();
        oracle.v1_face_match(blinded_query, &fixture.proofs).await
    }

    #[tokio::test]
    async fn face_match_ok_test() -> eyre::Result<()> {
        let (_server, oracle) = mock_oracle(AxumStatus::OK, json!({ "verified": true }))?;
        face_match(&oracle).await?;
        Ok(())
    }

    #[tokio::test]
    async fn face_match_bad_request_test() -> eyre::Result<()> {
        let (_server, oracle) = mock_oracle(
            AxumStatus::BAD_REQUEST,
            json!({ "verified": false, "error": "invalid proof" }),
        )?;
        let err = face_match(&oracle).await.expect_err("Should fail");
        assert!(matches!(err, OracleError::BadRequest(msg) if msg == "invalid proof"));
        Ok(())
    }

    #[tokio::test]
    async fn face_match_bad_request_without_reason_test() -> eyre::Result<()> {
        let (_server, oracle) = mock_oracle(AxumStatus::BAD_REQUEST, json!({ "verified": false }))?;
        let err = face_match(&oracle).await.expect_err("Should fail");
        assert!(matches!(err, OracleError::BadRequest(msg) if msg == "unknown"));

        let app = Router::new().route(
            &format!("/{FACE_MATCH_PATH}"),
            post(|| async { (AxumStatus::BAD_REQUEST, "not json") }),
        );
        let (_server, oracle) = serve(app, RetryLayerConfig::disabled())?;
        let err = face_match(&oracle).await.expect_err("Should fail");
        assert!(matches!(err, OracleError::BadRequest(msg) if msg == "unknown"));
        Ok(())
    }

    #[tokio::test]
    async fn face_match_unexpected_status_test() -> eyre::Result<()> {
        let (_server, oracle) = mock_oracle(
            AxumStatus::INTERNAL_SERVER_ERROR,
            json!({ "error": "boom" }),
        )?;
        let err = face_match(&oracle).await.expect_err("Should fail");
        assert!(matches!(
            err,
            OracleError::UnexpectedStatusCode { status, .. } if status == StatusCode::INTERNAL_SERVER_ERROR
        ));
        Ok(())
    }

    #[tokio::test]
    async fn face_match_timeout_test() -> eyre::Result<()> {
        let (_server, oracle) = mock_oracle(AxumStatus::REQUEST_TIMEOUT, json!({}))?;
        let err = face_match(&oracle).await.expect_err("Should fail");
        assert!(matches!(err, OracleError::OracleTimeout));
        Ok(())
    }

    #[tokio::test]
    async fn face_match_unreachable_test() -> eyre::Result<()> {
        // Port 1 on loopback is never open; any connection attempt immediately
        // returns ECONNREFUSED without waiting for a timeout.
        let oracle = ProofVerifierOracle::init(
            reqwest::Client::new(),
            "http://127.0.0.1:1".parse()?,
            Environment::Test,
            RetryLayerConfig::disabled(),
            NonZeroUsize::MIN,
        )?;
        let err = face_match(&oracle).await.expect_err("Should fail");
        assert!(matches!(err, OracleError::OracleNotReachable(err) if err.is_connect()));
        Ok(())
    }

    #[tokio::test]
    async fn face_match_request_body_test() -> eyre::Result<()> {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let app = Router::new().route(
            &format!("/{FACE_MATCH_PATH}"),
            post(move |Json(body): Json<serde_json::Value>| async move {
                tx.send(body).expect("receiver alive");
                (AxumStatus::OK, Json(json!({ "verified": true })))
            }),
        );
        let (_server, oracle) = serve(app, RetryLayerConfig::disabled())?;
        face_match(&oracle).await?;
        let body = rx.recv().await.expect("oracle received a request");
        // the expected values were produced by zkPassport, not by our serialization
        let fixture = zkpassport_oprf_test_utils::fixtures::load_fixture_json();
        assert_eq!(
            body,
            json!({
                "blinded_unique_identifier": fixture["blinded_unique_identifier"],
                "proofs": fixture["proofs"],
            })
        );
        Ok(())
    }

    #[tokio::test]
    async fn face_match_retries_test() -> eyre::Result<()> {
        let calls = Arc::new(AtomicUsize::new(0));
        let app = Router::new().route(
            &format!("/{FACE_MATCH_PATH}"),
            post({
                let calls = Arc::clone(&calls);
                move || async move {
                    if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                        (AxumStatus::SERVICE_UNAVAILABLE, Json(json!({})))
                    } else {
                        (AxumStatus::OK, Json(json!({ "verified": true })))
                    }
                }
            }),
        );
        let retry = RetryLayerConfig {
            verifier_request_min_delay: Duration::from_millis(1),
            verifier_request_max_delay: Duration::from_millis(1),
            verifier_request_max_attempts: 1,
        };
        let (_server, oracle) = serve(app, retry)?;
        face_match(&oracle).await?;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        Ok(())
    }

    #[tokio::test]
    async fn v2_request_bodies_test() -> eyre::Result<()> {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let record = |path: &'static str| {
            let tx = tx.clone();
            post(move |Json(body): Json<serde_json::Value>| async move {
                tx.send((path, body)).expect("receiver alive");
                (AxumStatus::OK, Json(json!({ "verified": true })))
            })
        };
        let app = Router::new()
            .route(&format!("/{IDENTIFY_PATH}"), record(IDENTIFY_PATH))
            .route(&format!("/{REGISTER_PATH}"), record(REGISTER_PATH))
            .route(&format!("/{QUERY_PATH}"), record(QUERY_PATH))
            .route(&format!("/{ROTATE_PATH}"), record(ROTATE_PATH));
        let (_server, oracle) = serve(app, RetryLayerConfig::disabled())?;

        let fixture = zkpassport_oprf_test_utils::fixtures::load_fixture_data();
        let blinding_factor = taceo_oprf::core::oprf::BlindingFactor::from_scalar(fixture.beta)
            .expect("Invalid blinding factor");
        let blinded_query =
            taceo_oprf::core::oprf::client::blind_query(fixture.private_nullifier, blinding_factor)
                .blinded_query();
        let id = SaltedIdentifier::from(ark_babyjubjub::EdwardsAffine::default());
        let commitment = AuthCommitment::from(ark_babyjubjub::Fq::from(42u64));
        let proofs = &fixture.proofs;
        let proofs_json = serde_json::to_value(proofs)?;
        // produced by zkPassport, not by our serialization
        let hex_query =
            &zkpassport_oprf_test_utils::fixtures::load_fixture_json()["blinded_unique_identifier"];

        oracle.salted_identifier(blinded_query, proofs).await?;
        oracle
            .registration_commitment(id, commitment, proofs)
            .await?;
        oracle
            .preimage_proof(blinded_query, id, commitment, proofs)
            .await?;
        oracle.secret_rotation(id, commitment, proofs).await?;

        let mut bodies = Vec::new();
        while let Ok(received) = rx.try_recv() {
            bodies.push(received);
        }
        assert_eq!(
            bodies,
            vec![
                (
                    IDENTIFY_PATH,
                    json!({ "proofs": proofs_json, "blinded_query": hex_query })
                ),
                (
                    REGISTER_PATH,
                    json!({ "proofs": proofs_json, "I": ["0", "1"], "commitment": "42" })
                ),
                (
                    QUERY_PATH,
                    json!({
                        "proofs": proofs_json,
                        "blinded_query": hex_query,
                        "I": ["0", "1"],
                        "commitment": "42"
                    })
                ),
                (
                    ROTATE_PATH,
                    json!({ "proofs": proofs_json, "I": ["0", "1"], "commitment": "42" })
                ),
            ]
        );
        Ok(())
    }

    #[tokio::test]
    async fn retryable_errors() -> eyre::Result<()> {
        let status_error = |status| OracleError::UnexpectedStatusCode {
            status,
            body: String::new(),
        };
        for status in [
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::BAD_GATEWAY,
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::GATEWAY_TIMEOUT,
        ] {
            assert!(is_retryable_error(&status_error(status)), "{status}");
        }
        for status in [
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::NOT_FOUND,
            StatusCode::UNAUTHORIZED,
        ] {
            assert!(!is_retryable_error(&status_error(status)), "{status}");
        }
        assert!(!is_retryable_error(&OracleError::OracleTimeout));
        assert!(!is_retryable_error(&OracleError::BadRequest(
            "invalid proof".to_owned()
        )));
        let invalid_json = serde_json::from_str::<serde_json::Value>("{").expect_err("not JSON");
        assert!(!is_retryable_error(&OracleError::InvalidMessage(
            invalid_json
        )));

        // Port 1 on loopback is never open, see `face_match_unreachable_test`.
        let connect_error = reqwest::Client::new()
            .get("http://127.0.0.1:1")
            .send()
            .await
            .expect_err("connection refused");
        assert!(is_retryable_error(&OracleError::OracleNotReachable(
            connect_error
        )));
        let builder_error = reqwest::Client::new()
            .get("not a url")
            .build()
            .expect_err("invalid URL");
        assert!(!is_retryable_error(&OracleError::OracleNotReachable(
            builder_error
        )));
        Ok(())
    }

    #[test]
    fn endpoints_from_base_url() -> eyre::Result<()> {
        for base in ["http://oracle:8080/api", "http://oracle:8080/api/"] {
            let endpoints = OracleEndpoints::new(base.parse()?, Environment::Dev)?;
            assert_eq!(
                endpoints.face_match.as_str(),
                "http://oracle:8080/api/verify-oprf-auth?devmode=true"
            );
            assert_eq!(
                endpoints.identify.as_str(),
                "http://oracle:8080/api/oprf/v2/identify?devmode=true"
            );
            assert_eq!(
                endpoints.register.as_str(),
                "http://oracle:8080/api/oprf/v2/register?devmode=true"
            );
            assert_eq!(
                endpoints.query.as_str(),
                "http://oracle:8080/api/oprf/v2/query?devmode=true"
            );
            assert_eq!(
                endpoints.rotate.as_str(),
                "http://oracle:8080/api/oprf/v2/rotate?devmode=true"
            );
        }
        for environment in [Environment::Test, Environment::Prod] {
            let endpoints = OracleEndpoints::new("http://oracle:8080".parse()?, environment)?;
            assert_eq!(
                endpoints.face_match.as_str(),
                "http://oracle:8080/verify-oprf-auth"
            );
        }
        Ok(())
    }
}
