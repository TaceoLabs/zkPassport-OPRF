use std::sync::{Arc, Mutex};

use taceo_oprf::types::{ark_babyjubjub, async_trait::async_trait};
use zkpassport_oprf_authentication::{AuthCommitment, SaltedIdentifier, ZKPassportProofResult};

use crate::services::oracle_proxy::{OracleError, OracleProxy, Result};

/// A call received by [`TestOracleProxy`], with the arguments relevant for assertions.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum OracleCall {
    SaltedIdentifier {
        blinded_query: ark_babyjubjub::EdwardsAffine,
        proofs: Vec<ZKPassportProofResult>,
    },
    PreimageProof {
        blinded_query: ark_babyjubjub::EdwardsAffine,
        salted_identifier: SaltedIdentifier,
        commitment: AuthCommitment,
        proofs: Vec<ZKPassportProofResult>,
    },
    RegistrationCommitment {
        salted_identifier: SaltedIdentifier,
        commitment: AuthCommitment,
        proofs: Vec<ZKPassportProofResult>,
    },
    SecretRotation {
        salted_identifier: SaltedIdentifier,
        new_commitment: AuthCommitment,
        proofs: Vec<ZKPassportProofResult>,
    },
    V1FaceMatch {
        blinded_query: ark_babyjubjub::EdwardsAffine,
        proofs: Vec<ZKPassportProofResult>,
    },
}

/// [`OracleProxy`] that sends no requests and answers every check with a fixed outcome.
///
/// Records every call, see [`TestOracleProxy::take_calls`].
#[derive(Debug, Clone, Default)]
pub(crate) struct TestOracleProxy {
    /// If set, every check fails with [`OracleError::BadRequest`] with this reason.
    reject: Option<String>,
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

    /// Returns the calls received since the last call to this method, in order.
    pub(crate) fn take_calls(&self) -> Vec<OracleCall> {
        std::mem::take(&mut *self.calls.lock().expect("not poisoned"))
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
    async fn salted_identifier(
        &self,
        blinded_query: ark_babyjubjub::EdwardsAffine,
        proofs: &[ZKPassportProofResult],
    ) -> Result<()> {
        self.outcome(OracleCall::SaltedIdentifier {
            blinded_query,
            proofs: proofs.to_vec(),
        })
    }

    async fn preimage_proof(
        &self,
        blinded_query: ark_babyjubjub::EdwardsAffine,
        salted_identifier: SaltedIdentifier,
        auth_commitment: AuthCommitment,
        proofs: &[ZKPassportProofResult],
    ) -> Result<()> {
        self.outcome(OracleCall::PreimageProof {
            blinded_query,
            salted_identifier,
            commitment: auth_commitment,
            proofs: proofs.to_vec(),
        })
    }

    async fn registration_commitment(
        &self,
        salted_identifier: SaltedIdentifier,
        commitment: AuthCommitment,
        proofs: &[ZKPassportProofResult],
    ) -> Result<()> {
        self.outcome(OracleCall::RegistrationCommitment {
            salted_identifier,
            commitment,
            proofs: proofs.to_vec(),
        })
    }

    async fn secret_rotation(
        &self,
        salted_identifier: SaltedIdentifier,
        new_commitment: AuthCommitment,
        proofs: &[ZKPassportProofResult],
    ) -> Result<()> {
        self.outcome(OracleCall::SecretRotation {
            salted_identifier,
            new_commitment,
            proofs: proofs.to_vec(),
        })
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
