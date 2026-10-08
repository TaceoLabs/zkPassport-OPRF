//! Authentication types for the zkPassport OPRF service.
//!
//! This crate defines the types and error handling used to authenticate
//! OPRF requests via zkPassport zero-knowledge proofs for different authentication modules. It provides:
//!
//! * [`FaceMatchRequestAuth`] — the authentication payload sent by a client,
//!   containing an OPRF key ID and a list of zkPassport proofs.
//! * [`RegisterRequestAuth`] — the authentication payload for passport
//!   registration, which always uses the [`registration_oprf_key_id`].
//! * [`ZKPassportProofResult`] — a single zkPassport proof matching the
//!   `ProofResult` type from `@zkpassport/utils`.
//! * [`AuthModules`] — an enum of supported authentication modules
//!   (`FaceMatch` and `Register`).
//! * [`AuthErrorKind`] — authentication error variants with numeric
//!   [`error_codes`] and conversions to the upstream
//!   `OprfRequestAuthenticatorError`.

use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use ruint::aliases::U160;
use serde::{Deserialize, Serialize};
use taceo_oprf::types::{
    OprfKeyId,
    api::{CloseFrameMessage, OprfRequestAuthenticatorError},
    ark_babyjubjub,
};

/// Unique, salted identifier `I` of a passport.
///
/// Users obtain an identifier by registering at the OPRF nodes. A user needs to provide a zero-knowledge proof for ownership of passport `P` and the nodes compute:
///
/// `OPRF(P, OPRF_reg) = I`
///
/// where `OPRF_reg` is a global OPRF key. Following the registration process, a user can store a commitment to a secret at the OPRF nodes associated with `I` for fast authentication.
///
/// If a user loses `I`, they can trivially re-compute it at the nodes.
///
/// State-level actors that might also be able to compute a zero-knowledge proof of ownership `P`, are also able to compute `I` which in itself doesn't leak anything, as `I` is only used for identifying a user in the OPRF eco-system. The state-level actor must also know the secret-key associated with `I` to perform any actions.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    CanonicalSerialize,
    CanonicalDeserialize,
)]
pub struct SaltedIdentifier(
    #[serde(with = "ark_serde_compat::babyjubjub::affine")] ark_babyjubjub::EdwardsAffine,
);

/// The commitment to the secret.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    CanonicalSerialize,
    CanonicalDeserialize,
)]
pub struct AuthCommitment(#[serde(with = "ark_serde_compat::field")] ark_babyjubjub::Fq);

/// Request when sending a rotation request.
#[derive(Debug, Clone, Deserialize)]
pub struct CommitmentRotationRequest {
    /// The identifier for which to rotate the secret
    #[serde(rename = "I")]
    pub salted_identifier: SaltedIdentifier,
    /// The new commitment to persist in the database
    pub new_commitment: AuthCommitment,
}

/// Raw value of the global OPRF key used to derive user identifiers during registration.
///
/// See [`registration_oprf_key_id`].
// TODO: replace the placeholder with the final key id.
pub const REGISTRATION_OPRF_KEY_ID: U160 = U160::from_limbs([1, 0, 0]);

/// The global OPRF key used to derive user identifiers during registration.
///
/// The registration module always evaluates the OPRF under this key.
#[must_use]
pub fn registration_oprf_key_id() -> OprfKeyId {
    OprfKeyId::new(REGISTRATION_OPRF_KEY_ID)
}

/// Identifies the authentication module used for an OPRF request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthModules {
    /// Face-match authentication using zkPassport zero-knowledge proofs.
    FaceMatch,
    /// Passport registration, deriving the user identifier under the
    /// [`registration_oprf_key_id`].
    Register,
}

impl core::fmt::Display for AuthModules {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthModules::FaceMatch => f.write_str("face-match"),
            AuthModules::Register => f.write_str("register"),
        }
    }
}

/// Authentication payload attached to an OPRF request.
///
/// Sent by the client as part of the face-match flow. The OPRF node
/// forwards the embedded proofs to the oracle for verification before
/// proceeding with the OPRF evaluation.
#[derive(Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct FaceMatchRequestAuth {
    /// The OPRF key to use for this request.
    pub oprf_key_id: OprfKeyId,
    /// zkPassport proofs that attest to the user's identity.
    pub proofs: Vec<ZKPassportProofResult>,
}

impl FaceMatchRequestAuth {
    /// Creates a new `FaceMatchRequestAuth`.
    #[must_use]
    pub fn new(oprf_key_id: OprfKeyId, proofs: Vec<ZKPassportProofResult>) -> Self {
        Self {
            oprf_key_id,
            proofs,
        }
    }
}

/// Authentication payload attached to a registration OPRF request.
///
/// The client cannot choose the OPRF key: the OPRF node always uses the
/// [`registration_oprf_key_id`], and verifies the embedded proofs before
/// proceeding with the OPRF evaluation.
#[derive(Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RegisterRequestAuth {
    /// zkPassport proofs that attest to the user's passport.
    pub proofs: Vec<ZKPassportProofResult>,
}

impl RegisterRequestAuth {
    /// Creates a new `RegisterRequestAuth`.
    #[must_use]
    pub fn new(proofs: Vec<ZKPassportProofResult>) -> Self {
        Self { proofs }
    }
}

/// A single zkPassport proof, matching the `ProofResult` type from `@zkpassport/utils`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
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
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuthErrorKind {
    /// The oracle service could not be reached (network error or timeout).
    #[error("oracle_not_reachable")]
    OracleNotReachable,
    /// The oracle service responded with BAD REQUEST.
    #[error("oracle_bad_request")]
    OracleBadRequest(String),
    /// An unexpected internal error occurred.
    #[error("internal_server_error")]
    Internal,
}

/// Numeric close-frame error codes sent to the client when [`AuthErrorKind`] occurs.
pub mod error_codes {
    /// Error code for [`super::AuthErrorKind::OracleNotReachable`].
    pub const ORACLE_NOT_REACHABLE: u16 = 4500;
    /// Error code for [`super::AuthErrorKind::OracleBadRequest`].
    pub const ORACLE_BAD_REQUEST: u16 = 4501;
    /// Error code for [`super::AuthErrorKind::Internal`].
    pub const INTERNAL: u16 = 1011;
}

impl From<AuthErrorKind> for u16 {
    fn from(value: AuthErrorKind) -> Self {
        match value {
            AuthErrorKind::OracleNotReachable => error_codes::ORACLE_NOT_REACHABLE,
            AuthErrorKind::OracleBadRequest(_) => error_codes::ORACLE_BAD_REQUEST,
            AuthErrorKind::Internal => error_codes::INTERNAL,
        }
    }
}

impl From<AuthErrorKind> for OprfRequestAuthenticatorError {
    fn from(value: AuthErrorKind) -> Self {
        let message = match &value {
            AuthErrorKind::OracleNotReachable => {
                taceo_oprf::types::close_frame_message!("oracle not reachable - try again later")
            }
            AuthErrorKind::OracleBadRequest(reason) => {
                CloseFrameMessage::new_truncate(reason.to_owned())
            }
            AuthErrorKind::Internal => {
                taceo_oprf::types::close_frame_message!("internal")
            }
        };
        let code = u16::from(value);
        OprfRequestAuthenticatorError::with_message(code, message)
    }
}
