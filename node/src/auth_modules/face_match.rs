use taceo_oprf::types::{
    OprfKeyId,
    api::{OprfRequest, OprfRequestAuthenticator, OprfRequestAuthenticatorError},
    async_trait::async_trait,
};
use tracing::instrument;
use zkpassport_oprf_authentication::{
    AuthErrorKind, FaceMatchRequestAuth, registration_oprf_key_id,
};

use crate::{
    metrics,
    services::oracle_proxy::{OracleError, OracleProxyService},
};

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
        metrics::auth_module::inc_face_match();
        tracing::trace!("handling v1 face-match");
        if request.auth.oprf_key_id == registration_oprf_key_id() {
            tracing::warn!(
                auth_error = true,
                "cannot request face-match for registration OPRF-key"
            );
            return Err(AuthErrorKind::RequestedOprfRegistrationKey.into());
        }
        self.proxy
            .v1_face_match(request.blinded_query, &request.auth.proofs)
            .await
            .inspect_err(OracleError::log)
            .map_err(|err| OprfRequestAuthenticatorError::from(AuthErrorKind::from(err)))?;
        tracing::trace!("oracle accepted the face-match proofs");
        Ok(request.auth.oprf_key_id)
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
        },
    };
    use uuid::Uuid;
    use zkpassport_oprf_authentication::{
        FaceMatchRequestAuth, error_codes, registration_oprf_key_id,
    };
    use zkpassport_oprf_test_utils::fixtures::FixtureData;

    use crate::{
        auth_modules::face_match::FaceMatchAuthenticator,
        services::oracle_proxy::test::{OracleCall, TestOracleProxy},
    };

    fn build_request(
        fixture: FixtureData,
        oprf_key_id: OprfKeyId,
    ) -> OprfRequest<FaceMatchRequestAuth> {
        let blinding_factor =
            BlindingFactor::from_scalar(fixture.beta).expect("Invalid blinding factor");
        let blinded_query =
            taceo_oprf::core::oprf::client::blind_query(fixture.private_nullifier, blinding_factor);
        OprfRequest {
            request_id: Uuid::new_v4(),
            blinded_query: blinded_query.blinded_query(),
            auth: FaceMatchRequestAuth::new(oprf_key_id, fixture.proofs),
        }
    }

    fn customer_key_id() -> OprfKeyId {
        OprfKeyId::new(U160::from(2))
    }

    #[tokio::test]
    async fn success_test() -> eyre::Result<()> {
        let fixture = zkpassport_oprf_test_utils::fixtures::load_fixture_data();
        let request = build_request(fixture, customer_key_id());
        let oracle = Arc::new(TestOracleProxy::accept());
        let auth_service = FaceMatchAuthenticator::init(oracle.clone());
        let oprf_key = auth_service.authenticate(&request).await?;
        assert_eq!(oprf_key, customer_key_id());
        // the oracle verifies the proofs against the blinded query of this request
        assert_eq!(
            oracle.take_calls(),
            vec![OracleCall::V1FaceMatch {
                blinded_query: request.blinded_query,
                proofs: request.auth.proofs.clone(),
            }]
        );
        Ok(())
    }

    #[tokio::test]
    async fn registration_key_rejected_test() -> eyre::Result<()> {
        let fixture = zkpassport_oprf_test_utils::fixtures::load_fixture_data();
        let request = build_request(fixture, registration_oprf_key_id());
        let oracle = Arc::new(TestOracleProxy::accept());
        let auth_service = FaceMatchAuthenticator::init(oracle.clone());
        let is_err = auth_service
            .authenticate(&request)
            .await
            .expect_err("Should fail");
        assert_eq!(is_err.code(), error_codes::REQUESTED_OPRF_REGISTRATION_KEY);
        assert_eq!(oracle.take_calls(), vec![]);
        Ok(())
    }

    #[tokio::test]
    async fn oracle_rejects_test() -> eyre::Result<()> {
        let fixture = zkpassport_oprf_test_utils::fixtures::load_fixture_data();
        let request = build_request(fixture, customer_key_id());
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
}
