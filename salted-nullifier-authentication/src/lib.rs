use ark_serialize::CanonicalSerialize;
use async_trait::async_trait;
use axum::{http::StatusCode, response::IntoResponse};
use eyre::Context;
use reqwest::{ClientBuilder, Url};
use serde::{Deserialize, Serialize};
use taceo_oprf::types::{
    OprfKeyId,
    api::{OprfRequest, OprfRequestAuthenticator},
};
use uuid::Uuid;

/// A single ZKPassport proof, matching the `ProofResult` type from `@zkpassport/utils`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ZKPassportProofResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vkey_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub committed_inputs: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<u32>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SaltedNullifierRequestAuth {
    pub oprf_key_id: OprfKeyId,
    pub proofs: Vec<ZKPassportProofResult>,
}

#[derive(Serialize)]
struct OracleVerifyRequest {
    blinded_unique_identifier: String,
    proofs: Vec<ZKPassportProofResult>,
}

#[derive(Deserialize)]
struct OracleVerifyResponse {
    verified: bool,
    error: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum SaltedNullifierAuthError {
    /// Cannot reach oracle
    #[error(transparent)]
    OracleNotReachable(#[from] reqwest::Error),
    /// Oracle rejected the proofs
    #[error("Oracle verification failed: {0}")]
    OracleVerificationFailed(String),
    /// Internal server error
    #[error(transparent)]
    InternalServerError(#[from] eyre::Report),
}

impl IntoResponse for SaltedNullifierAuthError {
    fn into_response(self) -> axum::response::Response {
        tracing::debug!("{self:?}");
        match self {
            SaltedNullifierAuthError::OracleNotReachable(_) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "cannot reach oracle".to_owned(),
            )
                .into_response(),
            SaltedNullifierAuthError::OracleVerificationFailed(msg) => {
                (StatusCode::UNAUTHORIZED, msg).into_response()
            }
            SaltedNullifierAuthError::InternalServerError(err) => {
                let error_id = Uuid::new_v4();
                tracing::error!("{error_id} - {err:?}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("An internal server error has occurred. Error ID={error_id}"),
                )
                    .into_response()
            }
        }
    }
}

pub struct SaltedNullifierOprfRequestAuthenticator {
    client: reqwest::Client,
    oracle_url: Url,
}

impl SaltedNullifierOprfRequestAuthenticator {
    pub async fn init(oracle_url: Url) -> eyre::Result<Self> {
        // we use the client-builder to avoid panic if we cannot install tls backend
        let client = ClientBuilder::new()
            .build()
            .context("while building reqwest client")?;
        tracing::info!("pinging oracle at: {oracle_url}");
        let response = client
            .get(oracle_url.clone())
            .send()
            .await
            .context("while trying to reach oracle")?;
        let status_code = response.status();
        if status_code == StatusCode::OK {
            tracing::info!("oracle is healthy!");
        } else {
            tracing::warn!("cannot reach oracle: {response:?}");
            eyre::bail!("cannot reach oracle");
        }
        Ok(Self { client, oracle_url })
    }
}

fn serialize_point_to_hex(point: &ark_babyjubjub::EdwardsAffine) -> eyre::Result<String> {
    // Serialize x and y coordinates in big-endian to match the circuit's public output format
    // `blinded_query` in circuit returns (x, y) as Field elements which are big-endian
    let mut x_bytes = Vec::new();
    point
        .x
        .serialize_compressed(&mut x_bytes)
        .context("while serializing blinded query x coordinate")?;
    x_bytes.reverse(); // ark serializes in little-endian, circuit outputs are big-endian

    let mut y_bytes = Vec::new();
    point
        .y
        .serialize_compressed(&mut y_bytes)
        .context("while serializing blinded query y coordinate")?;
    y_bytes.reverse();

    let hex_x = x_bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let hex_y = y_bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    Ok(format!("0x{hex_x}{hex_y}"))
}

#[async_trait]
impl OprfRequestAuthenticator for SaltedNullifierOprfRequestAuthenticator {
    type RequestAuth = SaltedNullifierRequestAuth;
    type RequestAuthError = SaltedNullifierAuthError;

    async fn authenticate(
        &self,
        request: &OprfRequest<Self::RequestAuth>,
    ) -> Result<OprfKeyId, Self::RequestAuthError> {
        let blinded_unique_identifier = serialize_point_to_hex(&request.blinded_query)?;

        let verify_url = self
            .oracle_url
            .join("oprf/verify")
            .context("while building oracle verify URL")?;

        let body = OracleVerifyRequest {
            blinded_unique_identifier,
            proofs: request.auth.proofs.clone(),
        };

        tracing::debug!("sending verify request to oracle: {verify_url}");
        let response = self
            .client
            .post(verify_url)
            .json(&body)
            .send()
            .await
            .context("while sending verify request to oracle")?;

        let oracle_response: OracleVerifyResponse = response
            .json()
            .await
            .context("while parsing oracle response")?;

        if !oracle_response.verified {
            let error_msg = oracle_response
                .error
                .unwrap_or_else(|| "unknown".to_owned());
            return Err(SaltedNullifierAuthError::OracleVerificationFailed(
                error_msg,
            ));
        }

        tracing::debug!("oracle verified proofs successfully");
        Ok(request.auth.oprf_key_id)
    }
}
