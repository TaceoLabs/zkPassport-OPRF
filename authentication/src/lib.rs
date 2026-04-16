//! Authentication types for the zkPassport OPRF service.
//!
//! This crate defines the types and error handling used to authenticate
//! OPRF requests via zkPassport zero-knowledge proofs for different authentication modules. It provides:
//!
//! * [`FaceMatchRequestAuth`] — the authentication payload sent by a client,
//!   containing an OPRF key ID and a list of zkPassport proofs.
//! * [`ZKPassportProofResult`] — a single ZKPassport proof matching the
//!   `ProofResult` type from `@zkpassport/utils`.
//! * [`AuthModules`] — an enum of supported authentication modules
//!   (currently `FaceMatch`).
//! * [`AuthErrorKind`] — authentication error variants with numeric
//!   [`error_codes`] and conversions to the upstream
//!   `OprfRequestAuthenticatorError`.

use serde::{Deserialize, Serialize};
use taceo_oprf::types::{OprfKeyId, api::OprfRequestAuthenticatorError};

/// Identifies the authentication module used for an OPRF request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthModules {
    /// Face-match authentication using zkPassport zero-knowledge proofs.
    FaceMatch,
}

impl core::fmt::Display for AuthModules {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("zkpassport")
    }
}

/// Authentication payload attached to an OPRF request.
///
/// Sent by the client as part of the face-match flow. The OPRF node
/// forwards the embedded proofs to the oracle for verification before
/// proceeding with the OPRF evaluation.
#[derive(Clone, Serialize, Deserialize)]
pub struct FaceMatchRequestAuth {
    /// The OPRF key to use for this request.
    pub oprf_key_id: OprfKeyId,
    /// zkPassport proofs that attest to the user's identity.
    pub proofs: Vec<ZKPassportProofResult>,
}

/// A single ZKPassport proof, matching the `ProofResult` type from `@zkpassport/utils`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ZKPassportProofResult {
    /// The serialized ZK proof string (base64 or hex, as produced by the prover).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
    /// Hash of the verification key used to generate the proof.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vkey_hash: Option<String>,
    /// Prover/circuit version string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Human-readable name identifying the proof type (e.g., `"older_than"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The public committed inputs for this proof.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub committed_inputs: Option<serde_json::Value>,
    /// Zero-based index of this proof within the batch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index: Option<u32>,
    /// Total number of proofs in the batch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<u32>,
}

/// Error kinds that can occur during OPRF request authentication.
///
/// Maps to numeric error codes in [`error_codes`] and converts to
/// [`OprfRequestAuthenticatorError`]
/// for returning over the WebSocket connection.
#[derive(Copy, Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuthErrorKind {
    /// The oracle service could not be reached (network error or timeout).
    #[error("oracle_not_reachable")]
    OracleNotReachable,
    /// The oracle rejected the provided zkPassport proofs.
    #[error("oracle_verification_failed")]
    OracleVerificationFailed,
    /// An unexpected internal error occurred.
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
