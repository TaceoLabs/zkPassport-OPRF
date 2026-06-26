use std::fmt::Write as _;
use std::time::Duration;

use ark_serialize::CanonicalSerialize;
use backon::{ExponentialBuilder, Retryable as _};
use eyre::Context as _;
use reqwest::{ClientBuilder, StatusCode, Url};
use serde::ser::Error;

use serde::{Deserialize, Serialize, Serializer};
use taceo_oprf::types::{
    OprfKeyId,
    api::{OprfRequest, OprfRequestAuthenticator, OprfRequestAuthenticatorError},
    ark_babyjubjub,
    async_trait::async_trait,
};
use tracing::instrument;
use zkpassport_oprf_authentication::{AuthErrorKind, FaceMatchRequestAuth, ZKPassportProofResult};

use crate::config::RetryLayerConfig;

/// Request body sent to the oracle's proof-verification endpoint (`POST /oprf/verify`).
#[derive(Debug, Clone, Serialize)]
struct OracleVerifyRequest {
    #[serde(serialize_with = "serialize_point_to_hex")]
    /// The blinded unique identifier (`BabyJubJub` affine point), hex-encoded as `"0x<x><y>"`.
    blinded_unique_identifier: ark_babyjubjub::EdwardsAffine,
    /// The zkPassport proofs submitted by the client.
    proofs: Vec<ZKPassportProofResult>,
}

/// Response body received from the oracle's verification endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct OracleVerifyResponse {
    /// Whether the oracle accepted the proofs.
    verified: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Optional error message returned when `verified` is `false`.
    error: Option<String>,
}

/// Errors that can occur while authenticating an OPRF request via the face-match oracle.
#[derive(Debug, thiserror::Error)]
pub enum FaceMatchAuthError {
    /// Cannot reach oracle
    #[error(transparent)]
    OracleNotReachable(#[from] reqwest::Error),
    /// Oracle returned with BAD REQUEST
    #[error("Bad Request: {0}")]
    BadRequest(String),
    /// Oracle returned a non-success HTTP status
    #[error("Unexpected status code: {status} with body: {body}")]
    UnexpectedStatusCode { status: StatusCode, body: String },
    /// Serde
    #[error(transparent)]
    InvalidMessage(#[from] serde_json::Error),
}

impl From<FaceMatchAuthError> for AuthErrorKind {
    fn from(value: FaceMatchAuthError) -> Self {
        match value {
            FaceMatchAuthError::OracleNotReachable(_) => Self::OracleNotReachable,
            FaceMatchAuthError::BadRequest(reason) => Self::OracleBadRequest(reason),
            FaceMatchAuthError::UnexpectedStatusCode { .. }
            | FaceMatchAuthError::InvalidMessage(_) => Self::Internal,
        }
    }
}

impl FaceMatchAuthError {
    /// Log the error at the appropriate tracing level.
    #[inline]
    pub(crate) fn log(&self) {
        if matches!(self, FaceMatchAuthError::BadRequest(_)) {
            tracing::warn!(err=%self, auth_error=true, "{self}");
        } else {
            tracing::error!(err=%self, "{self}");
        }
    }
}

/// Authenticator that verifies zkPassport face-match proofs by forwarding them to an oracle.
///
/// Implements [`OprfRequestAuthenticator`] and is registered on the OPRF service builder
/// for the `face` authentication module.
pub struct FaceMatchAuthenticator {
    client: reqwest::Client,
    verify_url: Url,
    backon: ExponentialBuilder,
}

impl FaceMatchAuthenticator {
    /// Initialize the authenticator.
    ///
    /// Builds an HTTP client and stores the `verify_url` used for subsequent
    /// proof-verification requests. Oracle reachability is not checked here; a
    /// separate background task polls the oracle's health endpoint (see
    /// [`crate::services::health_check`]).
    ///
    /// # Errors
    /// Returns an error if the HTTP client cannot be built.
    pub fn init(
        verify_url: Url,
        request_timeout: Duration,
        retry_layer: RetryLayerConfig,
    ) -> eyre::Result<Self> {
        // we use the client-builder to avoid panic if we cannot install tls backend
        let client = ClientBuilder::new()
            .timeout(request_timeout)
            .build()
            .context("while building reqwest client")?;

        Ok(Self {
            client,
            verify_url,
            backon: ExponentialBuilder::new()
                .with_min_delay(retry_layer.verifier_request_min_delay)
                .with_max_delay(retry_layer.verifier_request_max_delay)
                .with_max_times(retry_layer.verifier_request_max_attempts),
        })
    }

    /// Send the OPRF request's blinded query and proofs to the oracle and return the key ID.
    async fn authenticate_inner(
        &self,
        request: &OprfRequest<FaceMatchRequestAuth>,
    ) -> Result<OprfKeyId, FaceMatchAuthError> {
        let body = OracleVerifyRequest {
            blinded_unique_identifier: request.blinded_query,
            proofs: request.auth.proofs.clone(),
        };

        tracing::trace!("sending verify request to oracle: {}", self.verify_url);
        let response = self
            .client
            .post(self.verify_url.clone())
            .json(&body)
            .send()
            .await?;

        let status = response.status();

        if status == StatusCode::OK {
            tracing::trace!("oracle verified proofs successfully");
            Ok(request.auth.oprf_key_id)
        } else if status == StatusCode::BAD_REQUEST {
            tracing::trace!("received BAD REQUEST from oracle");
            let body = response.text().await?;
            let error_msg = match serde_json::from_str::<OracleVerifyResponse>(&body) {
                Ok(response) => response.error.unwrap_or_else(|| "unknown".to_owned()),
                Err(err) => {
                    tracing::error!(%err,"could not parse oracle verify response: {err}");
                    "unknown".to_owned()
                }
            };

            Err(FaceMatchAuthError::BadRequest(error_msg))
        } else {
            tracing::trace!("unknown status code: {status}");
            let body = response.text().await?;
            Err(FaceMatchAuthError::UnexpectedStatusCode { status, body })
        }
    }
}

fn is_retryable_error(e: &FaceMatchAuthError) -> bool {
    // Transport-level failures: no usable response came back.
    //
    // HTTP status failures worth retrying:
    // * 408 REQUEST TIMEOUT
    // * 429 TOO MANY REQUESTS
    // * 502 BAD GATEWAY
    // * 503 SERVICE UNAVAILABLE
    // * 504 GATEWAY TIMEOUT
    //
    // we do not retry INTERNAL SERVER ERROR
    match e {
        FaceMatchAuthError::OracleNotReachable(error) => error.is_connect(),
        FaceMatchAuthError::UnexpectedStatusCode { status, .. } => matches!(
            *status,
            StatusCode::REQUEST_TIMEOUT
                | StatusCode::TOO_MANY_REQUESTS
                | StatusCode::BAD_GATEWAY
                | StatusCode::SERVICE_UNAVAILABLE
                | StatusCode::GATEWAY_TIMEOUT
        ),
        FaceMatchAuthError::BadRequest(_) | FaceMatchAuthError::InvalidMessage(_) => false,
    }
}

#[async_trait]
impl OprfRequestAuthenticator for FaceMatchAuthenticator {
    type RequestAuth = FaceMatchRequestAuth;

    #[instrument(level = "info", skip_all)]
    async fn authenticate(
        &self,
        request: &OprfRequest<Self::RequestAuth>,
    ) -> Result<OprfKeyId, OprfRequestAuthenticatorError> {
        (|| async { self.authenticate_inner(request).await })
            .retry(self.backon)
            .when(is_retryable_error)
            .notify(|err, duration| {
                tracing::warn!(
                    ?err,
                    "Retrying request to verifier oracle in db after {duration:?}: {err}"
                );
            })
            .await
            .inspect_err(FaceMatchAuthError::log)
            .map_err(|err| AuthErrorKind::from(err).into())
    }
}

/// Serialize a `BabyJubJub` affine point to a `"0x<x><y>"` hex string.
///
/// Coordinates are serialized in big-endian byte order to match the circuit's
/// public output format. `ark-serialize` returns little-endian bytes, so both
/// coordinate byte vectors are reversed before encoding.
fn serialize_point_to_hex<S: Serializer>(
    point: &ark_babyjubjub::EdwardsAffine,
    ser: S,
) -> Result<S::Ok, S::Error> {
    // Serialize x and y coordinates in big-endian to match the circuit's public output format
    // `blinded_query` in circuit returns (x, y) as Field elements which are big-endian
    let mut x_bytes = Vec::new();
    point
        .x
        .serialize_compressed(&mut x_bytes)
        .map_err(S::Error::custom)?;

    x_bytes.reverse(); // ark serializes in little-endian, circuit outputs are big-endian

    let mut y_bytes = Vec::new();
    point
        .y
        .serialize_compressed(&mut y_bytes)
        .map_err(S::Error::custom)?;
    y_bytes.reverse();

    let mut hex_x = String::with_capacity(x_bytes.len() * 2);
    for b in &x_bytes {
        write!(&mut hex_x, "{b:02x}").expect("Write to a string should never panic");
    }

    let mut hex_y = String::with_capacity(y_bytes.len() * 2);
    for b in &y_bytes {
        write!(&mut hex_y, "{b:02x}").expect("Write to a string should never panic");
    }
    ser.serialize_str(&format!("0x{hex_x}{hex_y}"))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ruint::aliases::U160;
    use taceo_oprf::{
        core::oprf::BlindingFactor,
        types::{
            OprfKeyId,
            api::{OprfRequest, OprfRequestAuthenticator as _},
            ark_babyjubjub,
        },
    };
    use uuid::Uuid;
    use zkpassport_oprf_authentication::{FaceMatchRequestAuth, error_codes};
    use zkpassport_oprf_test_utils::fixtures::FixtureData;

    use crate::{config::RetryLayerConfig, services::face_match::FaceMatchAuthenticator};

    async fn auth_service() -> eyre::Result<FaceMatchAuthenticator> {
        let proof_verifier_url =
            zkpassport_oprf_test_utils::containers::get_proof_verifier_url().await;
        FaceMatchAuthenticator::init(
            proof_verifier_url.join("verify-oprf-auth?devmode=true")?,
            Duration::from_secs(10),
            RetryLayerConfig::disabled(),
        )
    }

    fn build_request(fixture: FixtureData) -> OprfRequest<FaceMatchRequestAuth> {
        let blinding_factor =
            BlindingFactor::from_scalar(fixture.beta).expect("Invalid blinding factor");
        let blinded_query =
            taceo_oprf::core::oprf::client::blind_query(fixture.private_nullifier, blinding_factor);
        OprfRequest {
            request_id: Uuid::new_v4(),
            blinded_query: blinded_query.blinded_query(),
            auth: FaceMatchRequestAuth {
                oprf_key_id: OprfKeyId::new(U160::from(1)),
                proofs: fixture.proofs,
            },
        }
    }

    #[tokio::test]
    async fn success_test() -> eyre::Result<()> {
        let fixture = zkpassport_oprf_test_utils::fixtures::load_fixture_data();
        let request = build_request(fixture);
        let oprf_key = auth_service().await?.authenticate(&request).await?;
        assert_eq!(oprf_key.into_inner(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn invalid_proof_test() -> eyre::Result<()> {
        let mut fixture = zkpassport_oprf_test_utils::fixtures::load_fixture_data();
        fixture.proofs[0].proof = Some("invalid value".to_string());
        let request = build_request(fixture);

        let is_err = auth_service()
            .await?
            .authenticate(&request)
            .await
            .expect_err("Should fail");
        assert_eq!(is_err.code(), error_codes::ORACLE_BAD_REQUEST);
        assert_eq!(is_err.message(), "Cannot convert undefined to a BigInt");

        Ok(())
    }

    #[tokio::test]
    async fn swapped_base_proofs_test() -> eyre::Result<()> {
        let mut fixture = zkpassport_oprf_test_utils::fixtures::load_fixture_data();
        let dummy = fixture.proofs[0].proof.clone();
        fixture.proofs[0].proof = fixture.proofs[1].proof.clone();
        fixture.proofs[1].proof = dummy;
        let request = build_request(fixture);

        let is_err = auth_service()
            .await?
            .authenticate(&request)
            .await
            .expect_err("Should fail");
        assert_eq!(is_err.code(), error_codes::ORACLE_BAD_REQUEST);
        assert_eq!(
            is_err.message(),
            "Proof verification failed: {\"sig_check_dsc\":{\"certificate\":{\"expected\":\"A valid root from ZKPassport Registry\",\"received..."
        );

        Ok(())
    }

    #[tokio::test]
    async fn wrong_proof_count_test() -> eyre::Result<()> {
        let mut fixture = zkpassport_oprf_test_utils::fixtures::load_fixture_data();
        fixture.proofs.pop();
        let request = build_request(fixture);

        let is_err = auth_service()
            .await?
            .authenticate(&request)
            .await
            .expect_err("Should fail");
        assert_eq!(is_err.code(), error_codes::ORACLE_BAD_REQUEST);
        assert_eq!(
            is_err.message(),
            "Expected 5 subproofs (3 base + facematch + oprf_auth), got 4"
        );

        Ok(())
    }

    #[tokio::test]
    async fn missing_facematch_proof_test() -> eyre::Result<()> {
        let mut fixture = zkpassport_oprf_test_utils::fixtures::load_fixture_data();
        fixture.proofs[3].proof = None;
        let request = build_request(fixture);

        let is_err = auth_service()
            .await?
            .authenticate(&request)
            .await
            .expect_err("Should fail");
        assert_eq!(is_err.code(), error_codes::ORACLE_BAD_REQUEST);
        assert_eq!(is_err.message(), "Missing required facematch proof");

        Ok(())
    }

    #[tokio::test]
    async fn missing_oprf_auth_proof_test() -> eyre::Result<()> {
        let mut fixture = zkpassport_oprf_test_utils::fixtures::load_fixture_data();
        fixture.proofs[4].proof = None;
        let request = build_request(fixture);

        let is_err = auth_service()
            .await?
            .authenticate(&request)
            .await
            .expect_err("Should fail");
        assert_eq!(is_err.code(), error_codes::ORACLE_BAD_REQUEST);
        assert_eq!(is_err.message(), "Missing required oprf_auth proof");

        Ok(())
    }

    #[tokio::test]
    async fn blinded_identifier_mismatch_test() -> eyre::Result<()> {
        let fixture = zkpassport_oprf_test_utils::fixtures::load_fixture_data();

        // Blind with scalar 2 instead of the fixture's beta so the transmitted point
        // diverges from the one baked into the oprf_auth proof.
        let different_beta = ark_babyjubjub::Fr::from(2u64);
        let blinding_factor =
            BlindingFactor::from_scalar(different_beta).expect("Invalid blinding factor");
        let blinded_query =
            taceo_oprf::core::oprf::client::blind_query(fixture.private_nullifier, blinding_factor);
        let request = OprfRequest {
            request_id: Uuid::new_v4(),
            blinded_query: blinded_query.blinded_query(),
            auth: FaceMatchRequestAuth {
                oprf_key_id: OprfKeyId::new(U160::from(1)),
                proofs: fixture.proofs,
            },
        };

        let is_err = auth_service()
            .await?
            .authenticate(&request)
            .await
            .expect_err("Should fail");
        assert_eq!(is_err.code(), error_codes::ORACLE_BAD_REQUEST);
        assert_eq!(
            is_err.message(),
            "blinded_unique_identifier does not match oprf_auth proof output"
        );

        Ok(())
    }

    #[tokio::test]
    async fn oracle_unreachable_test() -> eyre::Result<()> {
        // Port 1 on loopback is never open; any connection attempt immediately
        // returns ECONNREFUSED without waiting for a timeout.
        let auth_service = FaceMatchAuthenticator::init(
            "http://127.0.0.1:1/verify-oprf-auth".parse()?,
            Duration::from_secs(10),
            RetryLayerConfig::disabled(),
        )?;
        let fixture = zkpassport_oprf_test_utils::fixtures::load_fixture_data();
        let request = build_request(fixture);

        let is_err = auth_service
            .authenticate(&request)
            .await
            .expect_err("Should fail");
        assert_eq!(is_err.code(), error_codes::ORACLE_NOT_REACHABLE);
        assert_eq!(is_err.message(), "oracle not reachable - try again later");

        Ok(())
    }

    #[tokio::test]
    async fn oracle_empty_proofs() -> eyre::Result<()> {
        let fixture = zkpassport_oprf_test_utils::fixtures::load_fixture_data();
        let mut request = build_request(fixture);
        request.auth.proofs.clear();

        let is_err = auth_service()
            .await?
            .authenticate(&request)
            .await
            .expect_err("Should fail");
        assert_eq!(is_err.code(), error_codes::ORACLE_BAD_REQUEST);
        assert_eq!(
            is_err.message(),
            "Expected 5 subproofs (3 base + facematch + oprf_auth), got 0"
        );

        Ok(())
    }
}
