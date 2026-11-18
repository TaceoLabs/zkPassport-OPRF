use taceo_oprf::types::{
    OprfKeyId,
    api::{OprfRequest, OprfRequestAuthenticator, OprfRequestAuthenticatorError},
    async_trait::async_trait,
};
use tracing::instrument;
use zkpassport_oprf_authentication::{
    AuthErrorKind, IdentifyRequestAuth, registration_oprf_key_id,
};

use crate::{
    metrics,
    services::oracle_proxy::{OracleError, OracleProxyService},
};

/// Authenticator for passport registration.
///
/// Always evaluates under the global [`registration_oprf_key_id`] (the client cannot
/// choose the key) and verifies the zkPassport proofs through the oracle. Implements
/// [`OprfRequestAuthenticator`] and is registered on the OPRF service builder for the
/// `/identify` authentication module.
pub struct IdentifyAuthenticator {
    proxy: OracleProxyService,
}

impl IdentifyAuthenticator {
    /// Initialize the authenticator.
    ///
    /// Stores the oracle proxy used for subsequent proof-verification requests.
    pub(crate) fn init(proxy: OracleProxyService) -> Self {
        Self { proxy }
    }
}

#[async_trait]
impl OprfRequestAuthenticator for IdentifyAuthenticator {
    type RequestAuth = IdentifyRequestAuth;

    #[instrument(level = "info", skip_all)]
    async fn authenticate(
        &self,
        request: &OprfRequest<Self::RequestAuth>,
    ) -> Result<OprfKeyId, OprfRequestAuthenticatorError> {
        metrics::auth_module::inc_identify();
        tracing::trace!("handling salted identifier request");
        self.proxy
            .salted_identifier(request.blinded_query, &request.auth.proofs)
            .await
            .inspect_err(OracleError::log)
            .map_err(|err| OprfRequestAuthenticatorError::from(AuthErrorKind::from(err)))?;
        tracing::trace!("oracle accepted the identify proofs");
        Ok(registration_oprf_key_id())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use taceo_oprf::{
        core::oprf::BlindingFactor,
        types::api::{OprfRequest, OprfRequestAuthenticator as _},
    };
    use uuid::Uuid;
    use zkpassport_oprf_authentication::{
        IdentifyRequestAuth, error_codes, registration_oprf_key_id,
    };
    use zkpassport_oprf_test_utils::fixtures::FixtureData;

    use crate::{
        auth_modules::identify::IdentifyAuthenticator,
        services::oracle_proxy::test::{OracleCall, TestOracleProxy},
    };

    fn build_request(fixture: FixtureData) -> OprfRequest<IdentifyRequestAuth> {
        let blinding_factor =
            BlindingFactor::from_scalar(fixture.beta).expect("Invalid blinding factor");
        let blinded_query =
            taceo_oprf::core::oprf::client::blind_query(fixture.private_nullifier, blinding_factor);
        OprfRequest {
            request_id: Uuid::new_v4(),
            blinded_query: blinded_query.blinded_query(),
            auth: IdentifyRequestAuth::new(fixture.proofs),
        }
    }

    #[tokio::test]
    async fn success_test() -> eyre::Result<()> {
        let fixture = zkpassport_oprf_test_utils::fixtures::load_fixture_data();
        let request = build_request(fixture);
        let oracle = Arc::new(TestOracleProxy::accept());
        let auth_service = IdentifyAuthenticator::init(oracle.clone());
        let oprf_key = auth_service.authenticate(&request).await?;
        assert_eq!(oprf_key, registration_oprf_key_id());
        assert_eq!(
            oracle.take_calls(),
            vec![OracleCall::SaltedIdentifier {
                blinded_query: request.blinded_query,
                proofs: request.auth.proofs.clone(),
            }]
        );
        Ok(())
    }

    #[tokio::test]
    async fn oracle_rejects_test() -> eyre::Result<()> {
        let fixture = zkpassport_oprf_test_utils::fixtures::load_fixture_data();
        let request = build_request(fixture);
        let auth_service =
            IdentifyAuthenticator::init(Arc::new(TestOracleProxy::reject("invalid proof")));
        let is_err = auth_service
            .authenticate(&request)
            .await
            .expect_err("Should fail");
        assert_eq!(is_err.code(), error_codes::ORACLE_BAD_REQUEST);
        assert_eq!(is_err.message(), "invalid proof");
        Ok(())
    }
}
