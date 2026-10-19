//! Authentication types for the zkPassport OPRF service.
//!
//! This crate defines the types and error handling used to authenticate
//! OPRF requests via zkPassport zero-knowledge proofs for different authentication modules. It provides:
//!
//! * [`FaceMatchRequestAuth`] — the authentication payload sent by a client,
//!   containing an OPRF key ID and a list of zkPassport proofs.
//! * [`RegisterRequestAuth`] — the authentication payload for passport
//!   registration, which always uses the [`registration_oprf_key_id`].
//! * [`NullifierRequestAuth`] — the authentication payload for nullifier
//!   derivation for a registered [`SaltedIdentifier`].
//! * [`ZKPassportProofResult`] — a single zkPassport proof matching the
//!   `ProofResult` type from `@zkpassport/utils`.
//! * [`AuthModules`] — an enum of supported authentication modules
//!   (`FaceMatch`, `Register` and `Nullifier`).
//! * [`RegistrationRequest`] — the request to register an identifier and
//!   commitment after the registration OPRF evaluation.
//! * [`AuthErrorKind`] — authentication error variants with numeric
//!   [`error_codes`] and conversions to the upstream
//!   `OprfRequestAuthenticatorError`.

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
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

impl From<ark_babyjubjub::EdwardsAffine> for SaltedIdentifier {
    fn from(value: ark_babyjubjub::EdwardsAffine) -> Self {
        Self(value)
    }
}

impl From<ark_babyjubjub::Fq> for AuthCommitment {
    fn from(value: ark_babyjubjub::Fq) -> Self {
        Self(value)
    }
}

impl SaltedIdentifier {
    /// Returns the wrapped `Affine` point.
    pub fn inner(self) -> ark_babyjubjub::EdwardsAffine {
        self.0
    }
}

impl AuthCommitment {
    /// Returns the wrapped field element.
    #[must_use]
    pub fn inner(self) -> ark_babyjubjub::Fq {
        self.0
    }
}

/// Request when sending a rotation request.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// Default nullifier authentication module proving knowledge of a secret in zk.
    Nullifier,
}

impl core::fmt::Display for AuthModules {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthModules::FaceMatch => f.write_str("face-match"),
            AuthModules::Register => f.write_str("register"),
            AuthModules::Nullifier => f.write_str("nullifier"),
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

/// Request when registering an identifier after the registration OPRF evaluation.
///
/// Sent by the client to every OPRF node after it derived its identifier with the
/// [`AuthModules::Register`] module. The node verifies the proofs, then stores
/// `I` → `commitment`. It rejects the request if `I` is already registered.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationRequest {
    /// The identifier to register
    #[serde(rename = "I")]
    pub salted_identifier: SaltedIdentifier,
    /// The commitment to persist in the database
    pub commitment: AuthCommitment,
    /// zkPassport proofs, including the client's OPRF proof that `I` is the output of the
    /// registration OPRF evaluation
    // TODO: the registration circuits do not exist yet.
    pub proofs: Vec<ZKPassportProofResult>,
}

/// Authentication payload attached to a nullifier OPRF request.
///
/// The client chooses the OPRF key, which must not be the
/// [`registration_oprf_key_id`] (rejected with
/// [`AuthErrorKind::RequestedOprfRegistrationKey`]). The OPRF node looks up the
/// commitment stored for `I` and verifies the embedded proofs before proceeding
/// with the OPRF evaluation.
#[derive(Clone, Serialize, Deserialize)]
pub struct NullifierRequestAuth {
    /// The requested `OprfKeyId`.
    pub oprf_key_id: OprfKeyId,
    /// The registered identifier `I` of the user.
    #[serde(rename = "I")]
    pub salted_identifier: SaltedIdentifier,
    /// Proofs of knowledge of the preimage of the commitment stored for `I`.
    pub proofs: Vec<ZKPassportProofResult>,
}

/// A single zkPassport proof, matching the `ProofResult` type from `@zkpassport/utils`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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
    /// Requested the OPRF registration key for nullifier creation.
    #[error("request_oprf_reg_key")]
    RequestedOprfRegistrationKey,
    /// Request for an unknown [`SaltedIdentifier`].
    #[error("unknown_identifier")]
    UnknownIdentifier,
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
    /// Error code for [`super::AuthErrorKind::RequestedOprfRegistrationKey`].
    pub const REQUESTED_OPRF_REGISTRATION_KEY: u16 = 4502;
    /// Error code for [`super::AuthErrorKind::UnknownIdentifier`].
    pub const UNKNOWN_IDENTIFIER: u16 = 4503;
    /// Error code for [`super::AuthErrorKind::Internal`].
    pub const INTERNAL: u16 = 1011;
}

impl From<AuthErrorKind> for u16 {
    fn from(value: AuthErrorKind) -> Self {
        match value {
            AuthErrorKind::OracleNotReachable => error_codes::ORACLE_NOT_REACHABLE,
            AuthErrorKind::OracleBadRequest(_) => error_codes::ORACLE_BAD_REQUEST,
            AuthErrorKind::RequestedOprfRegistrationKey => {
                error_codes::REQUESTED_OPRF_REGISTRATION_KEY
            }
            AuthErrorKind::UnknownIdentifier => error_codes::UNKNOWN_IDENTIFIER,
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
            AuthErrorKind::RequestedOprfRegistrationKey => {
                taceo_oprf::types::close_frame_message!("cannot request for registration OPRF key")
            }
            AuthErrorKind::UnknownIdentifier => {
                taceo_oprf::types::close_frame_message!("unknown identifier")
            }
            AuthErrorKind::Internal => {
                taceo_oprf::types::close_frame_message!("internal")
            }
        };
        let code = u16::from(value);
        OprfRequestAuthenticatorError::with_message(code, message)
    }
}

#[cfg(test)]
mod tests {
    use serde::{Serialize, de::DeserializeOwned};
    use serde_json::json;
    use taceo_oprf::types::api::CLOSE_FRAME_MAX_LENGTH;

    use super::*;

    /// Asserts that `value` serializes to `expected` and that `expected` deserializes back to it.
    ///
    /// Compares against fixed JSON, as a round trip alone passes after renaming a field.
    fn assert_wire_format<T: Serialize + DeserializeOwned>(
        value: &T,
        expected: &serde_json::Value,
    ) {
        assert_eq!(&serde_json::to_value(value).expect("serializes"), expected);
        let parsed: T = serde_json::from_value(expected.clone()).expect("deserializes");
        assert_eq!(&serde_json::to_value(parsed).expect("serializes"), expected);
    }

    fn identifier() -> SaltedIdentifier {
        SaltedIdentifier::from(ark_babyjubjub::EdwardsAffine::default())
    }

    fn commitment(n: u64) -> AuthCommitment {
        AuthCommitment::from(ark_babyjubjub::Fq::from(n))
    }

    fn proof() -> ZKPassportProofResult {
        ZKPassportProofResult {
            proof: Some("0xproof".to_owned()),
            vkey_hash: Some("0xvkey".to_owned()),
            version: Some("1.0.0".to_owned()),
            name: Some("outer_count_4".to_owned()),
            committed_inputs: Some(json!({ "key": "value" })),
            index: Some(0),
            total: Some(1),
        }
    }

    #[test]
    fn registration_request_wire_format() {
        let request = RegistrationRequest {
            salted_identifier: identifier(),
            commitment: commitment(42),
            proofs: vec![proof()],
        };
        let expected = json!({
            "I": ["0", "1"],
            "commitment": "42",
            "proofs": [{
                "proof": "0xproof",
                "vkeyHash": "0xvkey",
                "version": "1.0.0",
                "name": "outer_count_4",
                "committedInputs": { "key": "value" },
                "index": 0,
                "total": 1,
            }],
        });
        assert_wire_format(&request, &expected);
    }

    #[test]
    fn commitment_rotation_request_wire_format() {
        let request = CommitmentRotationRequest {
            salted_identifier: identifier(),
            new_commitment: commitment(43),
        };
        let expected = json!({
            "I": ["0", "1"],
            "new_commitment": "43",
        });
        assert_wire_format(&request, &expected);
    }

    #[test]
    fn register_request_auth_wire_format() {
        let auth = RegisterRequestAuth::new(vec![]);
        assert_wire_format(&auth, &json!({ "proofs": [] }));
    }

    #[test]
    fn nullifier_request_auth_wire_format() {
        let auth = NullifierRequestAuth {
            oprf_key_id: OprfKeyId::new(U160::from(7)),
            salted_identifier: identifier(),
            proofs: vec![],
        };
        let expected = json!({
            "oprf_key_id": "0x7",
            "I": ["0", "1"],
            "proofs": [],
        });
        assert_wire_format(&auth, &expected);
    }

    #[test]
    fn auth_error_close_frames() {
        // literal codes, as clients match on the numbers and not on the constants
        let cases = [
            (
                AuthErrorKind::OracleNotReachable,
                4500,
                "oracle not reachable - try again later",
            ),
            (
                AuthErrorKind::OracleBadRequest("invalid proof".to_owned()),
                4501,
                "invalid proof",
            ),
            (
                AuthErrorKind::RequestedOprfRegistrationKey,
                4502,
                "cannot request for registration OPRF key",
            ),
            (AuthErrorKind::UnknownIdentifier, 4503, "unknown identifier"),
            (AuthErrorKind::Internal, 1011, "internal"),
        ];
        for (kind, code, message) in cases {
            let err = OprfRequestAuthenticatorError::from(kind);
            assert_eq!(err.code(), code);
            assert_eq!(err.message(), message);
        }
    }

    #[test]
    fn oracle_bad_request_reason_is_truncated() {
        // multi-byte characters, so truncation must respect char boundaries
        let reason = "ä".repeat(100);
        let err =
            OprfRequestAuthenticatorError::from(AuthErrorKind::OracleBadRequest(reason.clone()));
        assert!(err.message().len() <= CLOSE_FRAME_MAX_LENGTH);
        let truncated = err.message().strip_suffix("...").expect("truncated");
        assert!(reason.starts_with(truncated));
    }

    #[test]
    fn salted_identifier_rejects_invalid_points() {
        // (1, 1) is not on the curve
        serde_json::from_value::<SaltedIdentifier>(json!(["1", "1"])).expect_err("rejected");
        // (0, -1) is on the curve but has order 2, so it is not in the prime-order subgroup
        let p_minus_one =
            "21888242871839275222246405745257275088548364400416034343698204186575808495616";
        serde_json::from_value::<SaltedIdentifier>(json!(["0", p_minus_one]))
            .expect_err("rejected");
        serde_json::from_value::<SaltedIdentifier>(json!(["0", "1"])).expect("accepted");
    }

    #[test]
    fn auth_commitment_rejects_non_canonical_values() {
        let p = "21888242871839275222246405745257275088548364400416034343698204186575808495617";
        serde_json::from_value::<AuthCommitment>(json!(p)).expect_err("rejected");
        // a signed parser would accept this as p - 1
        serde_json::from_value::<AuthCommitment>(json!("-1")).expect_err("rejected");
        serde_json::from_value::<AuthCommitment>(json!("42")).expect("accepted");
    }
}
