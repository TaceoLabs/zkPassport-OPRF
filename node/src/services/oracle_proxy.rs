//! Oracle interface for verifying zkPassport proofs.
//!
//! This module defines the [`OracleProxy`] trait, which is used by the authentication
//! modules and the HTTP API to verify proofs through the oracle.
//!
//! Current `OracleProxy` implementations:
//! - [`proof_verifier::ProofVerifierOracle`] (HTTP client for the proof-verifier)
//! - `test::TestOracleProxy` (tests only, sends no requests)

use std::sync::Arc;

use reqwest::StatusCode;
use taceo_oprf::types::{ark_babyjubjub, async_trait::async_trait};
use zkpassport_oprf_authentication::{
    AuthCommitment, AuthErrorKind, SaltedIdentifier, ZKPassportProofResult,
};

pub(crate) mod proof_verifier;
#[cfg(test)]
pub(crate) mod test;

type Result<T> = std::result::Result<T, OracleError>;

/// Dynamic trait object for the oracle proxy.
///
/// Must be `Send + Sync` to work with async contexts (e.g., Axum).
pub type OracleProxyService = Arc<dyn OracleProxy + Send + Sync>;

/// Errors returned by an [`OracleProxy`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OracleError {
    /// Cannot reach oracle
    #[error(transparent)]
    OracleNotReachable(#[from] reqwest::Error),
    /// Oracle returned with BAD REQUEST
    #[error("Bad Request: {0}")]
    BadRequest(String),
    /// Oracle returned a non-success HTTP status
    #[error("Unexpected status code: {status} with body: {body}")]
    UnexpectedStatusCode {
        /// The returned status code.
        status: StatusCode,
        /// The response body.
        body: String,
    },
    /// Serde
    #[error(transparent)]
    InvalidMessage(#[from] serde_json::Error),
    /// All permits for concurrent oracle requests are taken
    #[error("too many concurrent oracle requests")]
    Overloaded(#[from] tokio::sync::TryAcquireError),
    /// Oracle answered with REQUEST TIMEOUT
    #[error("oracle timeout")]
    OracleTimeout,
}

impl OracleError {
    pub(crate) fn log(&self) {
        if matches!(self, Self::BadRequest(_)) {
            tracing::warn!(err=?self, auth_error = true, "{self}");
        } else if matches!(self, Self::Overloaded(_)) {
            tracing::warn!(err=?self, "{self}");
        } else {
            tracing::error!(err=?self, "{self}");
        }
    }
}

impl From<OracleError> for AuthErrorKind {
    fn from(value: OracleError) -> Self {
        match value {
            OracleError::OracleNotReachable(_) => Self::OracleNotReachable,
            OracleError::BadRequest(reason) => Self::OracleBadRequest(reason),
            OracleError::OracleTimeout => Self::OracleTimeout,
            OracleError::Overloaded(_) => Self::Overloaded,
            OracleError::UnexpectedStatusCode { .. } | OracleError::InvalidMessage(_) => {
                Self::Internal
            }
        }
    }
}

/// Oracle that verifies the zero-knowledge proofs gating OPRF evaluations and other API calls.
///
/// Every method returns `Ok(())` iff the oracle accepted the proof.
///
/// # Notation
///
/// Shared by all proof statements on this type:
///
/// - `P`: the passport commitment, output by the base proof as `comm_out`. A Poseidon2
///   commitment over individually salted passport fields, among them `pn`.
/// - `pn`: the private nullifier committed in `P`, `pn = H(dg1, eContent, sod_sig)`. It is
///   deterministic per passport and never leaves a proof.
/// - `r`: a nonzero blinding factor chosen by the user.
/// - `B`: the blinded OPRF query, a blinding of `pn` under `r`.
/// - `k_id`: the global OPRF key used to derive identifiers.
/// - `k_c`: the nullifier OPRF key of a zkPassport customer.
/// - `I = OPRF(pn, k_id)`: the [`SaltedIdentifier`], a `BabyJubJub` point obtained by unblinding
///   the identify response. It is independent of the blinding factor.
/// - `pi`: the Chaum-Pedersen proof returned by the OPRF nodes, attesting to the correct
///   evaluation under `k_id`.
/// - `DS_COMMIT`: the ASCII string `zkpassport-oprf-v2-commit` interpreted as a
///   big-endian field element.
/// - `commit(pn, s) = Poseidon2_t3([DS_COMMIT, pn, s])[1]`: the commitment to a secret `s`, where
///   `Poseidon2_t3` is the BN254 Poseidon2 permutation of width 3. Including `pn` keeps the
///   commitments of different passports unlinkable even if a user reuses a secret.
/// - `x`, `x' = commit(pn, x)`: the user's secret and its commitment, the [`AuthCommitment`].
///   `x` MUST be sampled uniformly at random from the field, as `x'` is public and hides `x`
///   only by its entropy.
/// - `y`, `y' = commit(pn, y)`: the replacement secret and its commitment after a rotation,
///   subject to the same requirements as `x`.
///
/// # Proof Composition
///
/// Every proof verified by the oracle is composed of:
///
/// - **Base proof.** The zkPassport proof. It establishes that the user holds a valid
///   government-issued document and outputs the commitment `P` to it.
/// - **Stacked proofs.** Each additional statement is a separate proof that takes `P` as public
///   input and opens it privately. A stacked proof is meaningful only in conjunction with the
///   base proof that outputs the same `P`.
///
/// Every method MUST verify the base proof and all proofs stacked on top of it, and MUST check
/// that all of them carry the same `P`.
///
/// `P` is visible to the nodes and hides `pn` iff its salts are secret. A user MUST sample the
/// salts from a cryptographically secure source of randomness. As computing the base proof is
/// expensive, a user MAY cache `P` across requests. A cached `P` links the first registration
/// step to `I`, but otherwise reveals nothing beyond `I`, which is public in all later requests.
/// It reveals neither `pn` nor the holder's identity.
///
/// # Registration Proof
///
/// The registration proof is the zkPassport `oprf_registration` circuit. It takes `P`, `I`, the
/// public key of `k_id` and the commitment `x'` as public inputs and establishes:
///
/// - The user knows the opening of `P`, in particular its salts and `pn`.
/// - `pi` verifies against the public key of `k_id`, authenticating a blinded query/response
///   pair, and unblinding the response with `r` yields `I = OPRF(pn, k_id)`.
/// - The user knows `x` with `x' = commit(pn, x)`.
///
/// The oracle pins the public key of `k_id`, so a client cannot use a key of its own. A user
/// obtains the inputs for `I` (`r`, the response and `pi`) after the first registration step (see
/// `IdentifyAuthenticator`) and stacks the proof on the base proof in later requests.
///
/// The oracle routes are `POST /oprf/v2/{identify,register,query,rotate}`, one per method below.
/// Every one takes the three base proofs plus the proofs listed in its proof composition.
#[async_trait]
pub trait OracleProxy {
    /// Verifies that a user is eligible to obtain the [`SaltedIdentifier`] `I` for the passport
    /// committed in `P`. First step of the registration process.
    ///
    /// Consumed by `IdentifyAuthenticator`,
    /// which then evaluates the OPRF under `k_id`.
    ///
    /// # Proof Composition
    ///
    /// 1. The base proof.
    /// 2. The query proof (`oprf_auth`), see below.
    ///
    /// Oracle route: `identify`, with `blinded_query` `B`.
    ///
    /// # Proof Statement
    ///
    /// The query proof establishes:
    ///
    /// §1 - `B` is a blinding of `pn`
    ///
    /// The user opens `P` to `pn`, and `B` is a blinding of `pn` with a nonzero blinding factor
    /// `r`. Hence an OPRF evaluation can only be requested for a passport the
    /// user owns. This is the zkPassport `oprf-auth` circuit.
    ///
    /// # Notes
    ///
    /// The subsequent registration proof already rejects any `I` not computed from `pn`, so §1 is
    /// not required for soundness per se. It ensures the nodes never evaluate `k_id` on arbitrary
    /// inputs.
    ///
    /// No `nonce`, `challenge`, or `timestamp` is added. Replaying the proof with the same request
    /// only recomputes the blinded response, which the client unblinds to the same public `I`.
    /// Replay reveals nothing about `pn`. A user SHOULD sample a fresh blinding factor from a
    /// cryptographically secure source of randomness.
    async fn salted_identifier(
        &self,
        blinded_query: ark_babyjubjub::EdwardsAffine,
        proofs: &[ZKPassportProofResult],
    ) -> Result<()>;

    /// Verifies that the user may register the commitment `x'` for its identifier `I`. Second
    /// step of the registration process.
    ///
    /// # Proof Composition
    ///
    /// 1. The base proof.
    /// 2. The registration proof (`oprf_registration`) for `I` and `x'`.
    ///
    /// Oracle route: `register`, with `I` and `commitment` `x'`.
    ///
    /// # Notes
    ///
    /// The registration proof binds `x'` to `P` through the opening of `P` and the preimage of
    /// `x'`. Anyone who observes the request, including a malicious node, knows `P` but not its
    /// opening, and therefore cannot replace the registration proof with one for a different
    /// commitment `x̂'`.
    ///
    /// No `nonce`, `challenge`, or `timestamp` is added. Nodes MUST reject a registration if a
    /// commitment for `I` is already stored, so a replay is rejected.
    async fn registration_commitment(
        &self,
        salted_identifier: SaltedIdentifier,
        commitment: AuthCommitment,
        proofs: &[ZKPassportProofResult],
    ) -> Result<()>;

    /// Verifies that the user may request a salted nullifier, an opaque per-customer identifier
    /// that provides sybil resistance within the zkPassport ecosystem.
    ///
    /// Consumed by `NullifierAuthenticator`,
    /// which then evaluates the OPRF on `B` under `k_c`.
    ///
    /// # Proof Composition
    ///
    /// 1. The base proof.
    /// 2. The query proof (`oprf_auth`), as in [`Self::salted_identifier`].
    /// 3. The registration proof (`oprf_registration`) for `I` and `x'`, as in
    ///    [`Self::registration_commitment`].
    ///
    /// Oracle route: `query`, with `blinded_query` `B`, `I` and `commitment` `x'`, the commitment
    /// stored for `I`.
    ///
    /// # Notes
    ///
    /// The query proof is required for sybil resistance. Without it, a registered user could
    /// blind arbitrary inputs and obtain arbitrarily many nullifiers per customer. With it, each
    /// passport yields exactly one nullifier per customer.
    ///
    /// The proofs alone do not establish that `x'` is currently registered for `I`. Before
    /// authorizing the OPRF evaluation, nodes MUST look up `I`, reject unknown identifiers, and
    /// require `x'` to equal the commitment currently stored for `I`. This rejects both arbitrary
    /// commitments and commitments superseded by a rotation.
    ///
    /// Nodes MUST reject requests for `k_id`. The identifier key is used exclusively for
    /// computing identifiers.
    ///
    /// No `nonce`, `challenge`, or `timestamp` is needed. A replay is accepted only while `x'` is
    /// the commitment stored for `I`, and only makes the nodes recompute the same blinded
    /// response. The resulting nullifier is public and one-way, so nothing is gained.
    ///
    /// The base proof takes a `current_date` for PKI-chain verification. Nodes MAY additionally
    /// check that it lies within a reasonable window.
    async fn preimage_proof(
        &self,
        blinded_query: ark_babyjubjub::EdwardsAffine,
        salted_identifier: SaltedIdentifier,
        auth_commitment: AuthCommitment,
        proofs: &[ZKPassportProofResult],
    ) -> Result<()>;

    /// Verifies that the user may rotate the [`AuthCommitment`] stored for `I` from `x'` to `y'`.
    ///
    /// Rotation is the fallback for a lost secret or a front-run registration.
    ///
    /// # Proof Composition
    ///
    /// 1. The base proof.
    /// 2. The face-match proof (`facematch`), see below.
    /// 3. The registration proof (`oprf_registration`) for `I` and `y'`, as in
    ///    [`Self::registration_commitment`] with `y` in place of `x`.
    ///
    /// Oracle route: `rotate`, with `I` and `commitment` `y'`.
    ///
    /// # Proof Statement
    ///
    /// The face-match proof establishes:
    ///
    /// §1 - Face match against `P`
    ///
    /// The user performed a face match against the portrait whose DG2 hash is committed in `P`,
    /// as in the `v1` flow. A government cannot forge this proof, which makes rotation safe
    /// against front-running.
    ///
    /// # Notes
    ///
    /// Nodes MUST check that `I` is registered before updating the mapping.
    ///
    /// The registration proof binds `y'` to `P`. Without this binding, anyone observing the request
    /// could replace `y'` with their own commitment and take over `I`.
    ///
    /// Unlike [`Self::preimage_proof`], a `nonce` or `timestamp` may be desirable. Otherwise a
    /// replay could rotate the mapping back to a commitment whose secret the user has lost,
    /// locking them out. The commitment itself may serve as nonce: nodes could persist the history
    /// of commitments per `I` and reject any `y'` seen before, which also leaves an audit trail.
    async fn secret_rotation(
        &self,
        salted_identifier: SaltedIdentifier,
        new_commitment: AuthCommitment,
        proofs: &[ZKPassportProofResult],
    ) -> Result<()>;

    /// Verifies the proofs of a v1 face-match request.
    async fn v1_face_match(
        &self,
        blinded_query: ark_babyjubjub::EdwardsAffine,
        proofs: &[ZKPassportProofResult],
    ) -> Result<()>;
}
