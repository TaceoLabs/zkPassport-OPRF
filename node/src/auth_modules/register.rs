use taceo_oprf::types::{
    OprfKeyId,
    api::{OprfRequest, OprfRequestAuthenticator, OprfRequestAuthenticatorError},
    async_trait::async_trait,
};
use tracing::instrument;
use zkpassport_oprf_authentication::{
    AuthErrorKind, RegisterRequestAuth, registration_oprf_key_id,
};

use crate::services::oracle_proxy::{OracleError, OracleProxyService};

/// Authenticator for passport registration.
///
/// Always evaluates under the global [`registration_oprf_key_id`] (the client cannot
/// choose the key) and verifies the zkPassport proofs through the oracle. Implements
/// [`OprfRequestAuthenticator`] and is registered on the OPRF service builder for the
/// `/register` authentication module.
pub struct RegisterAuthenticator {
    proxy: OracleProxyService,
}

impl RegisterAuthenticator {
    /// Initialize the authenticator.
    ///
    /// Stores the oracle proxy used for subsequent proof-verification requests.
    /// Oracle reachability is not checked here; a separate background task
    /// polls the oracle's health endpoint (see
    /// [`crate::services::health_check`]).
    pub(crate) fn init(proxy: OracleProxyService) -> Self {
        Self { proxy }
    }
}

#[async_trait]
impl OprfRequestAuthenticator for RegisterAuthenticator {
    type RequestAuth = RegisterRequestAuth;

    #[instrument(level = "info", skip_all)]
    async fn authenticate(
        &self,
        _request: &OprfRequest<Self::RequestAuth>,
    ) -> Result<OprfKeyId, OprfRequestAuthenticatorError> {
        // TODO: forward the `blinded_query` together with the proofs (like face-match
        // does) once `OracleProxy::salted_identifier` takes a request.
        self.proxy
            .salted_identifier()
            .await
            .inspect_err(OracleError::log)
            .map_err(|err| OprfRequestAuthenticatorError::from(AuthErrorKind::from(err)))?;
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
        RegisterRequestAuth, error_codes, registration_oprf_key_id,
    };
    use zkpassport_oprf_test_utils::fixtures::FixtureData;

    use crate::{
        auth_modules::register::RegisterAuthenticator,
        services::oracle_proxy::test::TestOracleProxy,
    };

    // TODO: once `OracleProxy::salted_identifier` sends requests to the proof-verifier, add
    // tests against `shared_proof_verifier()` like for face-match (invalid proofs, missing
    // proofs, blinded query mismatch, oracle unreachable).

    fn build_request(fixture: FixtureData) -> OprfRequest<RegisterRequestAuth> {
        let blinding_factor =
            BlindingFactor::from_scalar(fixture.beta).expect("Invalid blinding factor");
        let blinded_query =
            taceo_oprf::core::oprf::client::blind_query(fixture.private_nullifier, blinding_factor);
        OprfRequest {
            request_id: Uuid::new_v4(),
            blinded_query: blinded_query.blinded_query(),
            auth: RegisterRequestAuth::new(fixture.proofs),
        }
    }

    #[tokio::test]
    async fn success_test() -> eyre::Result<()> {
        let fixture = zkpassport_oprf_test_utils::fixtures::load_fixture_data();
        let request = build_request(fixture);
        let auth_service = RegisterAuthenticator::init(Arc::new(TestOracleProxy::accept()));
        let oprf_key = auth_service.authenticate(&request).await?;
        assert_eq!(oprf_key, registration_oprf_key_id());
        Ok(())
    }

    #[tokio::test]
    async fn oracle_rejects_test() -> eyre::Result<()> {
        let fixture = zkpassport_oprf_test_utils::fixtures::load_fixture_data();
        let request = build_request(fixture);
        let auth_service =
            RegisterAuthenticator::init(Arc::new(TestOracleProxy::reject("invalid proof")));
        let is_err = auth_service
            .authenticate(&request)
            .await
            .expect_err("Should fail");
        assert_eq!(is_err.code(), error_codes::ORACLE_BAD_REQUEST);
        assert_eq!(is_err.message(), "invalid proof");
        Ok(())
    }
}
