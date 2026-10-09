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
use zkpassport_oprf_authentication::{AuthErrorKind, ZKPassportProofResult};

pub(crate) mod proof_verifier;
#[cfg(test)]
pub(crate) mod test;

type Result<T> = std::result::Result<T, OracleError>;

/// Dynamic trait object for the oracle proxy.
///
/// Must be `Send + Sync` to work with async contexts (e.g., Axum).
pub(crate) type OracleProxyService = Arc<dyn OracleProxy + Send + Sync>;

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

/// Trait that implementations of the oracle proxy must provide.
///
/// Every method returns `Ok(())` iff the oracle accepted the request.
#[async_trait]
#[expect(
    clippy::double_must_use,
    reason = "async_trait adds #[must_use] to the boxed futures"
)]
pub(crate) trait OracleProxy {
    /// First step in the registration process. Verifies that a prover is eligible to obtain a [`SaltedIdentifier`](zkpassport_oprf_authentication::SaltedIdentifier) for a passport `P`.
    ///
    /// Consumed by [`RegisterAuthenticator`](crate::auth_modules::register::RegisterAuthenticator), which then evaluates the OPRF under the global registration key `OPRF_reg`.
    ///
    /// # Notation
    ///
    /// Shared by all proof statements on this type:
    ///
    /// - `P`: the passport hash.
    /// - `OPRF_reg`: the global registration OPRF key.
    /// - `I = OPRF(P, OPRF_reg)`: the [`SaltedIdentifier`](zkpassport_oprf_authentication::SaltedIdentifier),
    ///   the stable `BabyJubJub` point obtained by unblinding the registration response. It is
    ///   independent of the blinding factor.
    /// - `x`, `x'`: the user's secret and its commitment, the [`AuthCommitment`](zkpassport_oprf_authentication::AuthCommitment).
    /// - `y`, `y'`: the replacement secret and commitment after a rotation.
    ///
    /// # Proof Statement
    ///
    /// The proof consists of the following statements:
    ///
    /// §1 - Ownership of passport `P`
    ///
    /// The ordinary zkPassport statement: the prover holds a valid government-issued document `P`.
    ///
    /// §2 - The OPRF request is a blinding of `P`
    ///
    /// Binds the blinded OPRF request to the passport in §1 using a nonzero blinding factor,
    /// so an OPRF evaluation can only be requested for a passport the prover owns.
    ///
    /// # Notes
    ///
    /// No `nonce`, `challenge`, or `timestamp` is added. Replaying the proof with the same request
    /// only recomputes the blinded response. The client unblinds it to recover the same public `I`;
    /// replay reveals nothing about `P`.
    async fn salted_identifier(&self) -> Result<()>;

    /// Second proof of the registration process. Attests that the public `I` was computed correctly for passport `P` and that the prover knows the secret behind the submitted commitment `x'`.
    ///
    /// Notation as in [`Self::salted_identifier`].
    ///
    /// # Proof Statement
    ///
    /// The proof consists of the following statements:
    ///
    /// §1 - Ownership of passport `P`
    ///
    /// The ordinary zkPassport statement: the prover holds a valid government-issued document `P`.
    ///
    /// §2 - Correct computation of `I`
    ///
    /// The public input `I` satisfies `I = OPRF(P, OPRF_reg)`. The enclosing ZK proof MUST establish
    /// all of the following:
    ///
    /// - The registration request is a blinding of the passport hash `P` from §1 using a nonzero
    ///   blinding factor known to the prover.
    /// - The Chaum-Pedersen discrete-logarithm-equality proof returned by the registration OPRF
    ///   verifies against the trusted public key for `OPRF_reg`, authenticating that blinded
    ///   request/response pair.
    /// - Unblinding that response with the same blinding factor yields the public input `I`.
    ///
    /// §3 - `I` and `P` have the same root passport
    ///
    /// §1 and §2 refer to the same `P`. Implied by the statements above, stated explicitly for clarity.
    ///
    /// §4 - Knowledge of the preimage of `x'`
    ///
    /// The prover knows `x` with `x' = commit(x)`. Binds the commitment to the proof, so a replayed proof cannot register a different commitment `x̂` under the prover's `I`.
    ///
    /// # Notes
    ///
    /// No `nonce`, `challenge`, or `timestamp` is added. Nodes MUST reject a registration if a commitment for `I` is already stored, so a replay is a no-op.
    async fn registration_commitment(&self) -> Result<()>;

    /// Verifies the query proof used to compute a salted nullifier. The salted nullifier is an opaque per-consumer identifier that provides sybil resistance within the zkPassport ecosystem.
    ///
    /// Consumed by the query authentication module, which then evaluates the OPRF under the consumer's nullifier key.
    ///
    /// Notation as in [`Self::salted_identifier`].
    ///
    /// # Proof Statement
    ///
    /// The proof consists of the following statements:
    ///
    /// §1 - Ownership of passport `P`
    ///
    /// The ordinary zkPassport statement: the prover holds a valid government-issued document with hash `P`.
    ///
    /// §2 - Correct computation of `I`
    ///
    /// The public input `I` satisfies `I = OPRF(P, OPRF_reg)` using the full derivation statement
    /// in §2 of [`Self::registration_commitment`], including registration request binding,
    /// Chaum-Pedersen verification against the trusted registration public key, and response unblinding.
    ///
    /// §3 - The OPRF request is a blinding of `P`
    ///
    /// Binds the blinded OPRF request to §1, so an OPRF evaluation can only be requested for a passport the prover owns.
    ///
    /// §4 - `I`, `P`, and the blinded OPRF request have the same root passport
    ///
    /// §1, §2, and §3 refer to the same `P`. Implied by the statements above, stated explicitly for clarity.
    ///
    /// §5 - Knowledge of the preimage of `x'`
    ///
    /// The prover knows `x` with `x' = commit(x)` for the public input `x'`.
    ///
    /// # Notes
    ///
    /// The proof alone does not establish that `x'` is currently registered for `I`. Before
    /// authorizing the OPRF evaluation, nodes MUST look up the proof's public input `I`, reject
    /// unknown identifiers, and require the proof's public input `x'` to equal the commitment
    /// currently stored for `I`. This rejects both arbitrary commitments and previous commitments
    /// superseded by rotation.
    ///
    /// Verifiers MUST enforce that the requested OPRF key is NOT `OPRF_reg`. The registration OPRF key MUST only be used for computing identifiers.
    ///
    /// No `nonce`, `challenge`, or `timestamp` is needed. A byte-for-byte replay is accepted only
    /// while `x'` still matches the currently stored commitment for `I`. It only makes the nodes
    /// recompute the same blinded response, from which the client can recover the same salted
    /// nullifier. The nullifier is public and one-way, so nothing is gained.
    ///
    /// The zkPassport circuit takes a `current_date` for PKI-chain verification. Nodes may additionally check that it lies within a reasonable window.
    #[expect(dead_code, reason = "is just a stub")]
    async fn preimage_proof(&self) -> Result<()>;

    /// Verifies the proof that rotates the [`AuthCommitment`](zkpassport_oprf_authentication::AuthCommitment) stored for a [`SaltedIdentifier`](zkpassport_oprf_authentication::SaltedIdentifier) from `x'` to a new commitment `y'`.
    ///
    /// Rotation is the fallback for a lost secret or a front-run registration. Notation as in [`Self::salted_identifier`].
    ///
    /// # Proof Statement
    ///
    /// The proof consists of the following statements:
    ///
    /// §1 - Ownership of passport `P`
    ///
    /// The ordinary zkPassport statement: the prover holds a valid government-issued document with hash `P`.
    ///
    /// §2 - Correct computation of `I`
    ///
    /// The public input `I` satisfies `I = OPRF(P, OPRF_reg)` using the full derivation statement
    /// in §2 of [`Self::registration_commitment`], including registration request binding,
    /// Chaum-Pedersen verification against the trusted registration public key, and response unblinding.
    ///
    /// §3 - `I` and `P` have the same root passport
    ///
    /// §1 and §2 refer to the same `P`. Implied by the statements above, stated explicitly for clarity.
    ///
    /// §4 - Face match against `P`
    ///
    /// The face-match proof from the `v1` flow, attesting that the user performed a face match against the picture on `P`. It must bind to the same `P` as `I`. A government cannot forge it, which is what makes rotation safe against front-running.
    ///
    /// §5 - Knowledge of the preimage of `y'`
    ///
    /// The prover knows `y` with `y' = commit(y)`. Binds the new commitment to the proof, so a replayed proof cannot rotate to a different commitment.
    ///
    /// # Notes
    ///
    /// Nodes MUST check that `I` is registered before updating the mapping.
    ///
    /// Unlike [`Self::preimage_proof`], a `nonce` or `timestamp` may be desirable. Otherwise a replay could rotate the mapping back to a commitment whose secret the user has lost, locking them out. The commitment itself may serve as nonce: nodes could persist the history of commitments per `I` and reject any `y'` seen before. This also leaves an audit trail of rotations.
    async fn secret_rotation(&self) -> Result<()>;

    /// Verifies the proofs of a v1 face-match request.
    async fn v1_face_match(
        &self,
        blinded_query: ark_babyjubjub::EdwardsAffine,
        proofs: &[ZKPassportProofResult],
    ) -> Result<()>;
}
