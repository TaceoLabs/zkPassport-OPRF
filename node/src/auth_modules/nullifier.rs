use taceo_oprf::types::{
    OprfKeyId,
    api::{OprfRequest, OprfRequestAuthenticator, OprfRequestAuthenticatorError},
    async_trait::async_trait,
};
use tracing::instrument;
use zkpassport_oprf_authentication::{AuthErrorKind, NullifierRequestAuth};

use crate::{
    ZkPassportDb,
    services::{
        oracle_proxy::{OracleError, OracleProxy},
        postgres::DbError,
    },
};

pub(crate) struct NullifierAuthenticator {
    proxy: OracleProxy,
    db: ZkPassportDb,
}

#[derive(Debug, thiserror::Error)]
enum NullifierAuthenticatorError {
    #[error(transparent)]
    Oracle(#[from] OracleError),
    #[error("cannot request nullifier for registration OPRF-key")]
    RequestedOprfRegistrationKey,
    #[error(transparent)]
    Db(#[from] DbError),
}

impl NullifierAuthenticatorError {
    fn log(&self) {
        match self {
            NullifierAuthenticatorError::Oracle(oracle_error) => oracle_error.log(),
            NullifierAuthenticatorError::RequestedOprfRegistrationKey => {
                tracing::warn!(err=?self, auth_error = true, "{self}");
            }
            NullifierAuthenticatorError::Db(db_error) => db_error.log(),
        }
    }
}

impl From<NullifierAuthenticatorError> for AuthErrorKind {
    fn from(value: NullifierAuthenticatorError) -> Self {
        match value {
            NullifierAuthenticatorError::Oracle(oracle_error) => Self::from(oracle_error),
            NullifierAuthenticatorError::RequestedOprfRegistrationKey => {
                Self::RequestedOprfRegistrationKey
            }
            NullifierAuthenticatorError::Db(db_error) => Self::from(db_error),
        }
    }
}

impl NullifierAuthenticator {
    /// Initialize the authenticator.
    ///
    /// Stores the oracle proxy used for subsequent proof-verification requests.
    /// Oracle reachability is not checked here; a separate background task
    /// polls the oracle's health endpoint (see
    /// [`crate::services::health_check`]).
    pub(crate) fn init(proxy: OracleProxy, db: ZkPassportDb) -> Self {
        Self { proxy, db }
    }

    async fn authenticate_inner(
        &self,
        req: &NullifierRequestAuth,
    ) -> Result<OprfKeyId, NullifierAuthenticatorError> {
        if req.oprf_key_id == zkpassport_oprf_authentication::registration_oprf_key_id() {
            return Err(NullifierAuthenticatorError::RequestedOprfRegistrationKey);
        }
        let auth_commitment = self.db.fetch_commitment(req.salted_identifier).await?;
        self.proxy.preimage_proof(&auth_commitment).await?;
        Ok(req.oprf_key_id)
    }
}

#[async_trait]
impl OprfRequestAuthenticator for NullifierAuthenticator {
    type RequestAuth = NullifierRequestAuth;

    #[instrument(level = "info", skip_all)]
    async fn authenticate(
        &self,
        request: &OprfRequest<Self::RequestAuth>,
    ) -> Result<OprfKeyId, OprfRequestAuthenticatorError> {
        self.authenticate_inner(&request.auth)
            .await
            .inspect_err(NullifierAuthenticatorError::log)
            .map_err(|err| OprfRequestAuthenticatorError::from(AuthErrorKind::from(err)))
    }
}
