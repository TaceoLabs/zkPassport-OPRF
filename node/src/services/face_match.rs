use std::fmt::Write as _;

use ark_serialize::CanonicalSerialize;
use eyre::Context as _;
use reqwest::{ClientBuilder, Url};
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
    /// Oracle rejected the proofs
    #[error("Oracle verification failed: {0}")]
    OracleVerificationFailed(String),
    /// Internal server error
    #[error(transparent)]
    Internal(#[from] eyre::Report),
}

impl From<FaceMatchAuthError> for AuthErrorKind {
    fn from(value: FaceMatchAuthError) -> Self {
        match value {
            FaceMatchAuthError::OracleNotReachable(_) => Self::OracleNotReachable,
            FaceMatchAuthError::OracleVerificationFailed(_) => Self::OracleVerificationFailed,
            FaceMatchAuthError::Internal(_) => Self::Internal,
        }
    }
}

impl FaceMatchAuthError {
    /// Log the error at the appropriate tracing level.
    ///
    /// [`Internal`](Self::Internal) errors are logged at `error` level with a full
    /// report chain; all other variants are logged at `debug` level.
    pub(crate) fn log(&self) {
        match self {
            FaceMatchAuthError::OracleNotReachable(_) => {
                tracing::warn!(err=?self,"oracle not reachable: {self}");
            }
            FaceMatchAuthError::OracleVerificationFailed(_) => {
                tracing::warn!(auth_error = true, err=?self, "{self}");
            }
            FaceMatchAuthError::Internal(report) => {
                tracing::error!(err=?report, "Internal Server Error");
            }
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
}

impl FaceMatchAuthenticator {
    /// Initialize the authenticator and verify the oracle is reachable.
    ///
    /// Builds an HTTP client, pings the oracle's health endpoint, and constructs the
    /// `verify_url` used for subsequent proof-verification requests.
    ///
    /// # Errors
    /// Returns an error if the HTTP client cannot be built or the oracle does not
    /// respond with `200 OK`.
    pub fn init(verify_url: Url) -> eyre::Result<Self> {
        // we use the client-builder to avoid panic if we cannot install tls backend
        let client = ClientBuilder::new()
            .build()
            .context("while building reqwest client")?;
        Ok(Self { client, verify_url })
    }

    /// Send the OPRF request's blinded query and proofs to the oracle and return the key ID.
    ///
    /// Returns [`FaceMatchAuthError::OracleVerificationFailed`] if the oracle
    /// reports `verified: false`.
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

        // classify a non-success HTTP status as OracleNotReachable, but log the body for diagnostics
        if let Err(err) = response.error_for_status_ref() {
            let body = response
                .text()
                .await
                .unwrap_or_else(|err| format!("<failed to read body: {err}>"));
            tracing::warn!(%body, "oracle verify endpoint returned non-success status");
            return Err(err.into());
        }

        let response = response
            .text()
            .await
            .context("while fetching response from oracle")?;

        let oracle_response = serde_json::from_str::<OracleVerifyResponse>(&response)
            .with_context(|| format!("while parsing oracle response: {response}"))?;

        if !oracle_response.verified {
            let error_msg = oracle_response
                .error
                .unwrap_or_else(|| "unknown".to_owned());
            return Err(FaceMatchAuthError::OracleVerificationFailed(error_msg));
        }

        tracing::debug!("oracle verified proofs successfully");
        Ok(request.auth.oprf_key_id)
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
        self.authenticate_inner(request)
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
