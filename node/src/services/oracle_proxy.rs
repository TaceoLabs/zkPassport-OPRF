use std::fmt::Write as _;

use ark_serialize::CanonicalSerialize as _;
use backon::{ExponentialBuilder, Retryable as _};
use reqwest::{StatusCode, Url};
use serde::ser::Error;
use serde::{Deserialize, Serialize, Serializer};
use taceo_oprf::{service::Environment, types::ark_babyjubjub};
use tracing::instrument;
use zkpassport_oprf_authentication::{AuthErrorKind, ZKPassportProofResult};

use crate::config::RetryLayerConfig;

type Result<T> = std::result::Result<T, OracleError>;

#[derive(Debug, thiserror::Error)]
pub(crate) enum OracleError {
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

impl From<OracleError> for AuthErrorKind {
    fn from(value: OracleError) -> Self {
        match value {
            OracleError::OracleNotReachable(_) => Self::OracleNotReachable,
            OracleError::BadRequest(reason) => Self::OracleBadRequest(reason),
            OracleError::UnexpectedStatusCode { .. } | OracleError::InvalidMessage(_) => {
                Self::Internal
            }
        }
    }
}

/// Request body sent to the oracle's face-match verification endpoint.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct OracleFaceMatchRequest {
    #[serde(serialize_with = "serialize_point_to_hex")]
    /// The blinded unique identifier (`BabyJubJub` affine point), hex-encoded as `"0x<x><y>"`.
    blinded_unique_identifier: ark_babyjubjub::EdwardsAffine,
    /// The zkPassport proofs submitted by the client.
    proofs: Vec<ZKPassportProofResult>,
}

impl OracleFaceMatchRequest {
    pub(crate) fn new(
        blinded_unique_identifier: ark_babyjubjub::EdwardsAffine,
        proofs: Vec<ZKPassportProofResult>,
    ) -> Self {
        Self {
            blinded_unique_identifier,
            proofs,
        }
    }
}

/// Response body received from the oracle's verification endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct OracleFaceMatchResponse {
    /// Whether the oracle accepted the proofs.
    verified: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Optional error message returned when `verified` is `false`.
    error: Option<String>,
}

const FACE_MATCH_PATH: &str = "verify-oprf-auth";
const PASSPORT_PROOF_PATH: &str = "verify-passport-proof";

/// Full oracle endpoint URLs, derived once from the configured base URL.
#[derive(Debug, Clone)]
struct OracleEndpoints {
    /// `<base>/verify-oprf-auth`, used by v1 face-match authentication.
    face_match: Url,
    /// `<base>/verify-passport-proof`, used by v2 registration and preimage proofs.
    passport_proof: Url,
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
            passport_proof: endpoint(PASSPORT_PROOF_PATH)?,
        })
    }
}

/// HTTP client for all oracle endpoints, with shared retry policy.
#[derive(Debug, Clone)]
pub(crate) struct OracleProxy {
    client: reqwest::Client,
    endpoints: OracleEndpoints,
    backoff: ExponentialBuilder,
}

impl OracleProxy {
    pub(crate) fn init(
        client: reqwest::Client,
        base_url: Url,
        environment: Environment,
        retry_layer: RetryLayerConfig,
    ) -> eyre::Result<Self> {
        Ok(Self {
            client,
            endpoints: OracleEndpoints::new(base_url, environment)?,
            backoff: retry_layer.exponential_backoff(),
        })
    }

    #[instrument(level = "debug", skip_all)]
    #[expect(dead_code, reason = "is just a stub")]
    pub(crate) async fn registration(&self) -> Result<()> {
        tracing::trace!(
            "sending verify request to oracle: {}",
            self.endpoints.passport_proof
        );
        Ok(())
    }

    #[instrument(level = "debug", skip_all)]
    #[expect(dead_code, reason = "is just a stub")]
    pub(crate) async fn preimage_proof(&self) -> Result<()> {
        tracing::trace!(
            "sending verify request to oracle: {}",
            self.endpoints.passport_proof
        );
        Ok(())
    }

    #[instrument(level = "debug", skip_all)]
    pub(crate) async fn face_match(&self, request: &OracleFaceMatchRequest) -> Result<()> {
        tracing::trace!(
            "sending verify request to oracle: {}",
            self.endpoints.face_match
        );
        self.with_retry("face_match", || async {
            let response = self
                .client
                .post(self.endpoints.face_match.clone())
                .json(request)
                .send()
                .await?;
            let status = response.status();
            if status == StatusCode::OK {
                tracing::trace!("oracle verified proofs successfully");
                Ok(())
            } else if status == StatusCode::BAD_REQUEST {
                tracing::trace!("received BAD REQUEST from oracle");
                let body = response.text().await?;
                let error_msg = match serde_json::from_str::<OracleFaceMatchResponse>(&body) {
                    Ok(response) => response.error.unwrap_or_else(|| "unknown".to_owned()),
                    Err(err) => {
                        tracing::error!(%err,"could not parse oracle verify response: {err}");
                        "unknown".to_owned()
                    }
                };

                Err(OracleError::BadRequest(error_msg))
            } else {
                tracing::trace!("unknown status code: {status}");
                let body = response.text().await?;
                Err(OracleError::UnexpectedStatusCode { status, body })
            }
        })
        .await
    }

    pub(crate) async fn with_retry<F, Fut, T>(&self, op_name: &str, f: F) -> Result<T>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        f.retry(self.backoff)
            .sleep(tokio::time::sleep)
            .when(is_retryable_error)
            .notify(|err, duration| {
                tracing::warn!(%err, retry_in = ?duration, "retrying {op_name} request to oracle");
            })
            .await
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
) -> std::result::Result<S::Ok, S::Error> {
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

fn is_retryable_error(e: &OracleError) -> bool {
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
        OracleError::OracleNotReachable(error) => error.is_connect(),
        OracleError::UnexpectedStatusCode { status, .. } => matches!(
            *status,
            StatusCode::REQUEST_TIMEOUT
                | StatusCode::TOO_MANY_REQUESTS
                | StatusCode::BAD_GATEWAY
                | StatusCode::SERVICE_UNAVAILABLE
                | StatusCode::GATEWAY_TIMEOUT
        ),
        OracleError::BadRequest(_) | OracleError::InvalidMessage(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_from_base_url() -> eyre::Result<()> {
        for base in ["http://oracle:8080/api", "http://oracle:8080/api/"] {
            let endpoints = OracleEndpoints::new(base.parse()?, Environment::Dev)?;
            assert_eq!(
                endpoints.face_match.as_str(),
                "http://oracle:8080/api/verify-oprf-auth?devmode=true"
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
