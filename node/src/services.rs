use ark_serialize::CanonicalSerialize;
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
use zkpassport_oprf_authentication::{AuthErrorKind, FaceMatchRequestAuth, ZKPassportProofResult};

#[derive(Debug, Clone, Serialize)]
pub struct OracleVerifyRequest {
    #[serde(serialize_with = "serialize_point_to_hex")]
    blinded_unique_identifier: ark_babyjubjub::EdwardsAffine,
    proofs: Vec<ZKPassportProofResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleVerifyResponse {
    verified: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

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
    pub fn log(&self) {
        if let Self::Internal(report) = self {
            tracing::error!("{report:?}");
        } else {
            tracing::debug!("{self}");
        }
    }
}

pub struct FaceMatchAuthenticator {
    client: reqwest::Client,
    verify_url: Url,
}

impl FaceMatchAuthenticator {
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
        Ok(Self {
            client,
            verify_url: oracle_url
                .join("oprf/verify")
                .context("while building oracle-url")?,
        })
    }

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

        let oracle_response: OracleVerifyResponse = response
            .json()
            .await
            .context("while parsing oracle response")?;

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

    async fn authenticate(
        &self,
        request: &OprfRequest<Self::RequestAuth>,
    ) -> Result<OprfKeyId, OprfRequestAuthenticatorError> {
        Ok(self
            .authenticate_inner(request)
            .await
            .inspect_err(FaceMatchAuthError::log)
            .map_err(AuthErrorKind::from)?)
    }
}

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

    let hex_x = x_bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let hex_y = y_bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    ser.serialize_str(&format!("0x{hex_x}{hex_y}"))
}
