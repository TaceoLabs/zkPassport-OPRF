use std::fmt::Write as _;

use ark_serialize::CanonicalSerialize as _;
use backon::{ExponentialBuilder, Retryable as _};
use reqwest::{StatusCode, Url};
use serde::ser::Error;
use serde::{Deserialize, Serialize, Serializer};
use taceo_oprf::types::ark_babyjubjub;
use zkpassport_oprf_authentication::ZKPassportProofResult;

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

#[derive(Debug, Clone)]
pub(crate) struct OracleProxy {
    client: reqwest::Client,
    face_match_url: Url,
    backoff: ExponentialBuilder,
}

impl OracleProxy {
    pub(crate) fn init(
        client: reqwest::Client,
        face_match_url: Url,
        retry_layer: RetryLayerConfig,
    ) -> Self {
        Self {
            client,
            face_match_url,
            backoff: retry_layer.exponential_backoff(),
        }
    }

    pub(crate) async fn face_match(&self, request: &OracleFaceMatchRequest) -> Result<()> {
        tracing::trace!("sending verify request to oracle: {}", self.face_match_url);
        self.with_retry("face_match", || async {
            let response = self
                .client
                .post(self.face_match_url.clone())
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
