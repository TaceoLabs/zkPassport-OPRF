use taceo_oprf::types::{
    OprfKeyId,
    api::{OprfRequest, OprfRequestAuthenticator, OprfRequestAuthenticatorError},
    async_trait::async_trait,
};
use tracing::instrument;
use zkpassport_oprf_authentication::{AuthErrorKind, NullifierRequestAuth};

use crate::{
    ZkPassportDb, metrics,
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
    #[error(transparent)]
    Db(#[from] DbError),
}

impl NullifierAuthenticatorError {
    fn log(&self) {
        match self {
            NullifierAuthenticatorError::Oracle(oracle_error) => oracle_error.log(),
            NullifierAuthenticatorError::Db(db_error) => db_error.log(),
        }
    }
}

impl From<NullifierAuthenticatorError> for AuthErrorKind {
    fn from(value: NullifierAuthenticatorError) -> Self {
        match value {
            NullifierAuthenticatorError::Oracle(oracle_error) => Self::from(oracle_error),
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
        request: &OprfRequest<NullifierRequestAuth>,
    ) -> Result<OprfKeyId, NullifierAuthenticatorError> {
        tracing::trace!("handling nullifier request");
        let OprfRequest {
            request_id: _,
            blinded_query,
            auth,
        } = request;
        let auth_commitment = self.db.fetch_commitment(auth.salted_identifier).await?;
        tracing::trace!("fetched stored commitment - verifying proofs with oracle");
        self.proxy
            .preimage_proof(
                *blinded_query,
                auth.salted_identifier,
                auth_commitment,
                &auth.proofs,
            )
            .await?;
        tracing::trace!("oracle accepted the nullifier proofs");
        Ok(OprfKeyId::from(auth.oprf_key_id))
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
        metrics::auth_module::inc_nullifier();
        self.authenticate_inner(request)
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
            api::{OprfRequest, OprfRequestAuthenticator as _},
            ark_babyjubjub,
        },
    };
    use uuid::Uuid;
    use zkpassport_oprf_authentication::{
        AuthCommitment, NonIdentifierOprfKeyId, NullifierRequestAuth, SaltedIdentifier, error_codes,
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
                oprf_key_id: customer_key_id(),
                salted_identifier,
                proofs: fixture.proofs,
            },
        }
    }

    fn customer_key_id() -> NonIdentifierOprfKeyId {
        NonIdentifierOprfKeyId::new(U160::from(2)).expect("not the identifier key")
    }

    #[tokio::test]
    async fn success_test() -> eyre::Result<()> {
        let (_pg, db) = ZkPassportDb::init_test().await?;
        let fixture = zkpassport_oprf_test_utils::fixtures::load_fixture_data();
        let id = identifier(&fixture);
        db.insert_registration(id, commitment()).await?;
        let request = build_request(fixture, id);
        let oracle = Arc::new(TestOracleProxy::accept());
        let auth_service = NullifierAuthenticator::init(oracle.clone(), db);
        let oprf_key = auth_service.authenticate(&request).await?;
        assert_eq!(oprf_key.into_inner(), 2);
        // the oracle verifies the preimage proof against the commitment stored for `I`
        assert_eq!(
            oracle.take_calls(),
            vec![OracleCall::PreimageProof {
                blinded_query: request.blinded_query,
                salted_identifier: id,
                commitment: commitment(),
                proofs: request.auth.proofs.clone(),
            }]
        );
        Ok(())
    }

    #[tokio::test]
    async fn unknown_identifier_test() -> eyre::Result<()> {
        let (_pg, db) = ZkPassportDb::init_test().await?;
        let fixture = zkpassport_oprf_test_utils::fixtures::load_fixture_data();
        let id = identifier(&fixture);
        let request = build_request(fixture, id);
        let oracle = Arc::new(TestOracleProxy::accept());
        let auth_service = NullifierAuthenticator::init(oracle.clone(), db);
        let err = auth_service
            .authenticate(&request)
            .await
            .expect_err("Should fail");
        assert_eq!(err.code(), error_codes::UNKNOWN_IDENTIFIER);
        assert_eq!(oracle.take_calls(), vec![]);
        Ok(())
    }

    #[tokio::test]
    async fn db_error_test() -> eyre::Result<()> {
        let (_pg, db) = ZkPassportDb::init_test().await?;
        let fixture = zkpassport_oprf_test_utils::fixtures::load_fixture_data();
        let id = identifier(&fixture);
        db.insert_registration(id, commitment()).await?;
        db.close_test().await;
        let request = build_request(fixture, id);
        let oracle = Arc::new(TestOracleProxy::accept());
        let auth_service = NullifierAuthenticator::init(oracle.clone(), db);
        let err = auth_service
            .authenticate(&request)
            .await
            .expect_err("Should fail");
        // a DB failure must not be reported as an unknown identifier
        assert_eq!(err.code(), error_codes::INTERNAL);
        assert_eq!(err.message(), "internal");
        assert_eq!(oracle.take_calls(), vec![]);
        Ok(())
    }

    #[tokio::test]
    async fn oracle_rejects_test() -> eyre::Result<()> {
        let (_pg, db) = ZkPassportDb::init_test().await?;
        let fixture = zkpassport_oprf_test_utils::fixtures::load_fixture_data();
        let id = identifier(&fixture);
        db.insert_registration(id, commitment()).await?;
        let request = build_request(fixture, id);
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
