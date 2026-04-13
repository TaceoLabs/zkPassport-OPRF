use serde::{Deserialize, Serialize};
use taceo_oprf::types::{OprfKeyId, api::OprfRequestAuthenticatorError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthModules {
    FaceMatch,
}

impl core::fmt::Display for AuthModules {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("face")
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct FaceMatchRequestAuth {
    pub oprf_key_id: OprfKeyId,
    pub proofs: Vec<ZKPassportProofResult>,
}

/// A single ZKPassport proof, matching the `ProofResult` type from `@zkpassport/utils`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ZKPassportProofResult {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vkey_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub committed_inputs: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<u32>,
}

#[derive(Copy, Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuthErrorKind {
    #[error("oracle_not_reachable")]
    OracleNotReachable,
    #[error("oracle_verification_failed")]
    OracleVerificationFailed,
    #[error("internal_server_error")]
    Internal,
}

pub mod error_codes {
    /// Error code for [`super::AuthErrorKind::OracleNotReachable`].
    pub const ORACLE_NOT_REACHABLE: u16 = 4500;
    /// Error code for [`super::AuthErrorKind::OracleVerificationFailed`].
    pub const ORACLE_VERIFICATION_FAILED: u16 = 4501;
    /// Error code for [`super::AuthErrorKind::Internal`].
    pub const INTERNAL: u16 = 1011;
}

impl From<AuthErrorKind> for u16 {
    fn from(value: AuthErrorKind) -> Self {
        match value {
            AuthErrorKind::OracleNotReachable => error_codes::ORACLE_NOT_REACHABLE,
            AuthErrorKind::OracleVerificationFailed => error_codes::ORACLE_VERIFICATION_FAILED,
            AuthErrorKind::Internal => error_codes::INTERNAL,
        }
    }
}

impl From<AuthErrorKind> for OprfRequestAuthenticatorError {
    fn from(value: AuthErrorKind) -> Self {
        let code = u16::from(value);
        let message = match value {
            AuthErrorKind::OracleNotReachable => {
                taceo_oprf::types::close_frame_message!("oracle not reachable - try again later")
            }
            AuthErrorKind::OracleVerificationFailed => {
                taceo_oprf::types::close_frame_message!("proof verification failed")
            }
            AuthErrorKind::Internal => {
                taceo_oprf::types::close_frame_message!("internal")
            }
        };
        OprfRequestAuthenticatorError::with_message(code, message)
    }
}
