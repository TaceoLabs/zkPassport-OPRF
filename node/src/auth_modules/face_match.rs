use taceo_oprf::types::{
    OprfKeyId,
    api::{OprfRequest, OprfRequestAuthenticator, OprfRequestAuthenticatorError},
    async_trait::async_trait,
};
use tracing::instrument;
use zkpassport_oprf_authentication::{AuthErrorKind, FaceMatchRequestAuth};

use crate::services::oracle_proxy::{OracleError, OracleProxyService};

/// Authenticator that verifies zkPassport face-match proofs by forwarding them to an oracle.
///
/// Implements [`OprfRequestAuthenticator`] and is registered on the OPRF service builder
/// for the `/face-match` authentication module.
pub struct FaceMatchAuthenticator {
    proxy: OracleProxyService,
}

impl FaceMatchAuthenticator {
    /// Initialize the authenticator.
    ///
    /// Stores the oracle proxy used for subsequent proof-verification requests.
    pub(crate) fn init(proxy: OracleProxyService) -> Self {
        Self { proxy }
    }
}

#[async_trait]
impl OprfRequestAuthenticator for FaceMatchAuthenticator {
    type RequestAuth = FaceMatchRequestAuth;

    #[instrument(level = "info", skip_all)]
    async fn authenticate(
        &self,
        request: &OprfRequest<Self::RequestAuth>,
    ) -> Result<OprfKeyId, OprfRequestAuthenticatorError> {
        self.proxy
            .v1_face_match(request.blinded_query, &request.auth.proofs)
            .await
            .inspect_err(OracleError::log)
            .map_err(|err| OprfRequestAuthenticatorError::from(AuthErrorKind::from(err)))?;
        Ok(request.auth.oprf_key_id)
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use ruint::aliases::U160;
    use taceo_oprf::{
        core::oprf::BlindingFactor,
        service::Environment,
        types::{
            OprfKeyId,
            api::{OprfRequest, OprfRequestAuthenticator as _},
        },
    };
    use uuid::Uuid;
    use zkpassport_oprf_authentication::{FaceMatchRequestAuth, error_codes};
    use zkpassport_oprf_test_utils::fixtures::FixtureData;

    use crate::{
        auth_modules::face_match::FaceMatchAuthenticator,
        config::RetryLayerConfig,
        services::oracle_proxy::{
            proof_verifier::ProofVerifierOracle,
            test::{OracleCall, TestOracleProxy},
        },
    };

    fn build_request(fixture: FixtureData) -> OprfRequest<FaceMatchRequestAuth> {
        let blinding_factor =
            BlindingFactor::from_scalar(fixture.beta).expect("Invalid blinding factor");
        let blinded_query =
            taceo_oprf::core::oprf::client::blind_query(fixture.private_nullifier, blinding_factor);
        OprfRequest {
            request_id: Uuid::new_v4(),
            blinded_query: blinded_query.blinded_query(),
            auth: FaceMatchRequestAuth::new(OprfKeyId::new(U160::from(1)), fixture.proofs),
        }
    }

    #[tokio::test]
    async fn success_test() -> eyre::Result<()> {
        let fixture = zkpassport_oprf_test_utils::fixtures::load_fixture_data();
        let request = build_request(fixture);
        let oracle = Arc::new(TestOracleProxy::accept());
        let auth_service = FaceMatchAuthenticator::init(oracle.clone());
        let oprf_key = auth_service.authenticate(&request).await?;
        assert_eq!(oprf_key.into_inner(), 1);
        // the oracle verifies the proofs against the blinded query of this request
        assert_eq!(
            oracle.calls(),
            vec![OracleCall::V1FaceMatch {
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
            FaceMatchAuthenticator::init(Arc::new(TestOracleProxy::reject("invalid proof")));
        let is_err = auth_service
            .authenticate(&request)
            .await
            .expect_err("Should fail");
        assert_eq!(is_err.code(), error_codes::ORACLE_BAD_REQUEST);
        assert_eq!(is_err.message(), "invalid proof");
        Ok(())
    }

    #[tokio::test]
    async fn oracle_unreachable_test() -> eyre::Result<()> {
        // Port 1 on loopback is never open; any connection attempt immediately
        // returns ECONNREFUSED without waiting for a timeout.
        let client = reqwest::ClientBuilder::new()
            .timeout(Duration::from_secs(10))
            .build()?;
        let proxy = Arc::new(ProofVerifierOracle::init(
            client,
            "http://127.0.0.1:1".parse()?,
            Environment::Dev,
            RetryLayerConfig::disabled(),
        )?);
        let auth_service = FaceMatchAuthenticator::init(proxy);
        let fixture = zkpassport_oprf_test_utils::fixtures::load_fixture_data();
        let request = build_request(fixture);

        let is_err = auth_service
            .authenticate(&request)
            .await
            .expect_err("Should fail");
        assert_eq!(is_err.code(), error_codes::ORACLE_NOT_REACHABLE);
        assert_eq!(is_err.message(), "oracle not reachable - try again later");

        Ok(())
    }
}
