use taceo_oprf::types::{
    OprfKeyId,
    api::{OprfRequest, OprfRequestAuthenticator, OprfRequestAuthenticatorError},
    async_trait::async_trait,
};
use tracing::instrument;
use zkpassport_oprf_authentication::{
    AuthErrorKind, RegisterRequestAuth, registration_oprf_key_id,
};

use crate::services::oracle_proxy::{OracleError, OracleProxy};

/// Authenticator for passport registration.
///
/// Always evaluates under the global [`registration_oprf_key_id`] (the client cannot
/// choose the key) and verifies the zkPassport proofs through the oracle. Implements
/// [`OprfRequestAuthenticator`] and is registered on the OPRF service builder for the
/// `/register` authentication module.
pub struct RegisterAuthenticator {
    proxy: OracleProxy,
}

impl RegisterAuthenticator {
    /// Initialize the authenticator.
    ///
    /// Stores the oracle proxy used for subsequent proof-verification requests.
    /// Oracle reachability is not checked here; a separate background task
    /// polls the oracle's health endpoint (see
    /// [`crate::services::health_check`]).
    pub fn init(proxy: OracleProxy) -> Self {
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
        // does) once `OracleProxy::registration` takes a request.
        self.proxy
            .registration()
            .await
            .inspect_err(|err| {
                if matches!(err, OracleError::BadRequest(_)) {
                    tracing::warn!(?err, auth_error = true, "{err}");
                } else {
                    tracing::error!(?err, "{err}");
                }
            })
            .map_err(|err| OprfRequestAuthenticatorError::from(AuthErrorKind::from(err)))?;
        Ok(registration_oprf_key_id())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use taceo_oprf::{
        core::oprf::BlindingFactor,
        service::Environment,
        types::api::{OprfRequest, OprfRequestAuthenticator as _},
    };
    use uuid::Uuid;
    use zkpassport_oprf_authentication::{RegisterRequestAuth, registration_oprf_key_id};
    use zkpassport_oprf_test_utils::fixtures::FixtureData;

    use crate::{
        auth_modules::register::RegisterAuthenticator, config::RetryLayerConfig,
        services::oracle_proxy::OracleProxy,
    };

    // TODO: once `OracleProxy::registration` sends requests to the proof-verifier, run
    // `success_test` against `shared_proof_verifier()` and add tests through `authenticate`
    // like for face-match (invalid proofs, missing proofs, blinded query mismatch, oracle
    // unreachable).

    fn test_client() -> eyre::Result<reqwest::Client> {
        Ok(reqwest::ClientBuilder::new()
            .timeout(Duration::from_secs(10))
            .build()?)
    }

    // Unreachable oracle (nothing listens on port 1, so requests fail immediately).
    // `registration` is still a stub and sends no request.
    fn auth_service() -> eyre::Result<RegisterAuthenticator> {
        let proxy = OracleProxy::init(
            test_client()?,
            "http://127.0.0.1:1".parse()?,
            Environment::Dev,
            RetryLayerConfig::disabled(),
        )?;
        Ok(RegisterAuthenticator::init(proxy))
    }

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
        let auth_service = auth_service()?;
        let oprf_key = auth_service.authenticate(&request).await?;
        assert_eq!(oprf_key, registration_oprf_key_id());
        Ok(())
    }
}
