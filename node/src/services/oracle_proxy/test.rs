use taceo_oprf::types::{ark_babyjubjub, async_trait::async_trait};
use zkpassport_oprf_authentication::{AuthCommitment, ZKPassportProofResult};

use crate::services::oracle_proxy::{OracleError, OracleProxy, Result};

/// [`OracleProxy`] that sends no requests and answers every check with a fixed outcome.
#[derive(Debug, Clone, Default)]
pub(crate) struct TestOracleProxy {
    /// If set, every check fails with [`OracleError::BadRequest`] with this reason.
    reject: Option<String>,
}

impl TestOracleProxy {
    /// Oracle that accepts every check.
    pub(crate) fn accept() -> Self {
        Self::default()
    }

    /// Oracle that rejects every check with `reason`.
    pub(crate) fn reject(reason: impl Into<String>) -> Self {
        Self {
            reject: Some(reason.into()),
        }
    }

    fn outcome(&self) -> Result<()> {
        self.reject
            .clone()
            .map_or(Ok(()), |reason| Err(OracleError::BadRequest(reason)))
    }
}

#[async_trait]
impl OracleProxy for TestOracleProxy {
    async fn salted_identifier(&self) -> Result<()> {
        self.outcome()
    }

    async fn preimage_proof(&self, _auth_commitment: &AuthCommitment) -> Result<()> {
        self.outcome()
    }

    async fn registration_commitment(&self) -> Result<()> {
        self.outcome()
    }

    async fn secret_rotation(&self) -> Result<()> {
        self.outcome()
    }

    async fn v1_face_match(
        &self,
        _blinded_query: ark_babyjubjub::EdwardsAffine,
        _proofs: &[ZKPassportProofResult],
    ) -> Result<()> {
        self.outcome()
    }
}
