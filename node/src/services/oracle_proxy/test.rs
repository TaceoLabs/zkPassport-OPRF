use std::sync::{Arc, Mutex};

use taceo_oprf::types::{ark_babyjubjub, async_trait::async_trait};
use zkpassport_oprf_authentication::{AuthCommitment, ZKPassportProofResult};

use crate::services::oracle_proxy::{OracleError, OracleProxy, Result};

/// A call received by [`TestOracleProxy`], with the arguments relevant for assertions.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum OracleCall {
    SaltedIdentifier,
    PreimageProof(AuthCommitment),
    RegistrationCommitment,
    SecretRotation,
    V1FaceMatch {
        blinded_query: ark_babyjubjub::EdwardsAffine,
        proofs: Vec<ZKPassportProofResult>,
    },
}

/// [`OracleProxy`] that sends no requests and answers every check with a fixed outcome.
///
/// Records every call, see [`TestOracleProxy::calls`].
#[derive(Debug, Clone, Default)]
pub(crate) struct TestOracleProxy {
    /// If set, every check fails with [`OracleError::BadRequest`] with this reason.
    reject: Option<String>,
    /// If set, preimage proofs only verify against this commitment, see
    /// [`TestOracleProxy::knows_preimage_of`]. Shared between clones, so a test can change it
    /// for running nodes with [`TestOracleProxy::set_known_preimage`].
    preimage_of: Arc<Mutex<Option<AuthCommitment>>>,
    calls: Arc<Mutex<Vec<OracleCall>>>,
}

impl TestOracleProxy {
    /// Oracle that accepts every check.
    pub(crate) fn accept() -> Self {
        Self::default()
    }

    /// Oracle that rejects every check with [`OracleError::BadRequest`] with `reason`.
    pub(crate) fn reject(reason: impl Into<String>) -> Self {
        Self {
            reject: Some(reason.into()),
            ..Self::default()
        }
    }

    /// Oracle for a client that knows only the preimage of `commitment`: preimage proofs
    /// against any other commitment fail with [`OracleError::BadRequest`], every other check
    /// is accepted.
    pub(crate) fn knows_preimage_of(commitment: AuthCommitment) -> Self {
        Self {
            preimage_of: Arc::new(Mutex::new(Some(commitment))),
            ..Self::default()
        }
    }

    /// Makes subsequent preimage proofs verify only against `commitment`, e.g. to simulate a
    /// client that rotated to a new secret and no longer knows the old one.
    pub(crate) fn set_known_preimage(&self, commitment: AuthCommitment) {
        *self.preimage_of.lock().expect("not poisoned") = Some(commitment);
    }

    /// All calls received so far, in order.
    pub(crate) fn calls(&self) -> Vec<OracleCall> {
        self.calls.lock().expect("not poisoned").clone()
    }

    fn outcome(&self, call: OracleCall) -> Result<()> {
        self.calls.lock().expect("not poisoned").push(call);
        self.reject
            .clone()
            .map_or(Ok(()), |reason| Err(OracleError::BadRequest(reason)))
    }
}

#[async_trait]
impl OracleProxy for TestOracleProxy {
    async fn salted_identifier(&self) -> Result<()> {
        self.outcome(OracleCall::SaltedIdentifier)
    }

    async fn preimage_proof(&self, auth_commitment: &AuthCommitment) -> Result<()> {
        self.outcome(OracleCall::PreimageProof(*auth_commitment))?;
        match *self.preimage_of.lock().expect("not poisoned") {
            Some(known) if known != *auth_commitment => {
                Err(OracleError::BadRequest("unknown preimage".to_owned()))
            }
            _ => Ok(()),
        }
    }

    async fn registration_commitment(&self) -> Result<()> {
        self.outcome(OracleCall::RegistrationCommitment)
    }

    async fn secret_rotation(&self) -> Result<()> {
        self.outcome(OracleCall::SecretRotation)
    }

    async fn v1_face_match(
        &self,
        blinded_query: ark_babyjubjub::EdwardsAffine,
        proofs: &[ZKPassportProofResult],
    ) -> Result<()> {
        self.outcome(OracleCall::V1FaceMatch {
            blinded_query,
            proofs: proofs.to_vec(),
        })
    }
}
