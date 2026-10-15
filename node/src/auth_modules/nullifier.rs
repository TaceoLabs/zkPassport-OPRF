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
        oracle_proxy::{OracleError, OracleProxyService},
        postgres::DbError,
    },
};

pub(crate) struct NullifierAuthenticator {
    proxy: OracleProxyService,
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
    pub(crate) fn init(proxy: OracleProxyService, db: ZkPassportDb) -> Self {
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ruint::aliases::U160;
    use taceo_oprf::{
        core::oprf::BlindingFactor,
        types::{
            OprfKeyId,
            api::{OprfRequest, OprfRequestAuthenticator as _},
            ark_babyjubjub,
        },
    };
    use uuid::Uuid;
    use zkpassport_oprf_authentication::{
        AuthCommitment, NullifierRequestAuth, SaltedIdentifier, error_codes,
        registration_oprf_key_id,
    };
    use zkpassport_oprf_test_utils::fixtures::FixtureData;

    use crate::{
        ZkPassportDb,
        auth_modules::nullifier::NullifierAuthenticator,
        services::oracle_proxy::test::{OracleCall, TestOracleProxy},
    };

    fn identifier(fixture: &FixtureData) -> SaltedIdentifier {
        let blinding_factor =
            BlindingFactor::from_scalar(fixture.beta).expect("Invalid blinding factor");
        let point =
            taceo_oprf::core::oprf::client::blind_query(fixture.private_nullifier, blinding_factor)
                .blinded_query();
        SaltedIdentifier::from(point)
    }

    fn commitment() -> AuthCommitment {
        AuthCommitment::from(ark_babyjubjub::Fq::from(42u64))
    }

    fn build_request(
        fixture: FixtureData,
        oprf_key_id: OprfKeyId,
        salted_identifier: SaltedIdentifier,
    ) -> OprfRequest<NullifierRequestAuth> {
        let blinding_factor =
            BlindingFactor::from_scalar(fixture.beta).expect("Invalid blinding factor");
        let blinded_query =
            taceo_oprf::core::oprf::client::blind_query(fixture.private_nullifier, blinding_factor);
        OprfRequest {
            request_id: Uuid::new_v4(),
            blinded_query: blinded_query.blinded_query(),
            auth: NullifierRequestAuth {
                oprf_key_id,
                salted_identifier,
                proofs: fixture.proofs,
            },
        }
    }

    #[tokio::test]
    async fn success_test() -> eyre::Result<()> {
        let (_pg, db) = ZkPassportDb::init_test().await?;
        let fixture = zkpassport_oprf_test_utils::fixtures::load_fixture_data();
        let id = identifier(&fixture);
        db.insert_registration(id, commitment()).await?;
        let request = build_request(fixture, OprfKeyId::new(U160::from(2)), id);
        let oracle = Arc::new(TestOracleProxy::accept());
        let auth_service = NullifierAuthenticator::init(oracle.clone(), db);
        let oprf_key = auth_service.authenticate(&request).await?;
        assert_eq!(oprf_key.into_inner(), 2);
        // the oracle verifies the preimage proof against the commitment stored for `I`
        assert_eq!(
            oracle.calls(),
            vec![OracleCall::PreimageProof(commitment())]
        );
        Ok(())
    }

    #[tokio::test]
    async fn registration_key_rejected_test() -> eyre::Result<()> {
        let (_pg, db) = ZkPassportDb::init_test().await?;
        let fixture = zkpassport_oprf_test_utils::fixtures::load_fixture_data();
        let id = identifier(&fixture);
        db.insert_registration(id, commitment()).await?;
        let request = build_request(fixture, registration_oprf_key_id(), id);
        let oracle = Arc::new(TestOracleProxy::accept());
        let auth_service = NullifierAuthenticator::init(oracle.clone(), db);
        let err = auth_service
            .authenticate(&request)
            .await
            .expect_err("Should fail");
        assert_eq!(err.code(), error_codes::REQUESTED_OPRF_REGISTRATION_KEY);
        assert_eq!(oracle.calls(), vec![]);
        Ok(())
    }

    #[tokio::test]
    async fn unknown_identifier_test() -> eyre::Result<()> {
        let (_pg, db) = ZkPassportDb::init_test().await?;
        let fixture = zkpassport_oprf_test_utils::fixtures::load_fixture_data();
        let id = identifier(&fixture);
        let request = build_request(fixture, OprfKeyId::new(U160::from(2)), id);
        let oracle = Arc::new(TestOracleProxy::accept());
        let auth_service = NullifierAuthenticator::init(oracle.clone(), db);
        let err = auth_service
            .authenticate(&request)
            .await
            .expect_err("Should fail");
        assert_eq!(err.code(), error_codes::UNKNOWN_IDENTIFIER);
        assert_eq!(oracle.calls(), vec![]);
        Ok(())
    }

    #[tokio::test]
    async fn db_error_test() -> eyre::Result<()> {
        let (_pg, db) = ZkPassportDb::init_test().await?;
        let fixture = zkpassport_oprf_test_utils::fixtures::load_fixture_data();
        let id = identifier(&fixture);
        db.insert_registration(id, commitment()).await?;
        db.close_test().await;
        let request = build_request(fixture, OprfKeyId::new(U160::from(2)), id);
        let oracle = Arc::new(TestOracleProxy::accept());
        let auth_service = NullifierAuthenticator::init(oracle.clone(), db);
        let err = auth_service
            .authenticate(&request)
            .await
            .expect_err("Should fail");
        // a DB failure must not be reported as an unknown identifier
        assert_eq!(err.code(), error_codes::INTERNAL);
        assert_eq!(err.message(), "internal");
        assert_eq!(oracle.calls(), vec![]);
        Ok(())
    }

    #[tokio::test]
    async fn oracle_rejects_test() -> eyre::Result<()> {
        let (_pg, db) = ZkPassportDb::init_test().await?;
        let fixture = zkpassport_oprf_test_utils::fixtures::load_fixture_data();
        let id = identifier(&fixture);
        db.insert_registration(id, commitment()).await?;
        let request = build_request(fixture, OprfKeyId::new(U160::from(2)), id);
        let auth_service =
            NullifierAuthenticator::init(Arc::new(TestOracleProxy::reject("invalid proof")), db);
        let err = auth_service
            .authenticate(&request)
            .await
            .expect_err("Should fail");
        assert_eq!(err.code(), error_codes::ORACLE_BAD_REQUEST);
        assert_eq!(err.message(), "invalid proof");
        Ok(())
    }
}
