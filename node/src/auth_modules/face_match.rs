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
    /// Oracle reachability is not checked here; a separate background task
    /// polls the oracle's health endpoint (see
    /// [`crate::services::health_check`]).
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
            ark_babyjubjub,
        },
    };
    use uuid::Uuid;
    use zkpassport_oprf_authentication::{FaceMatchRequestAuth, error_codes};
    use zkpassport_oprf_test_utils::{
        containers::{SharedProofVerifier, shared_proof_verifier},
        fixtures::FixtureData,
    };

    use crate::{
        auth_modules::face_match::FaceMatchAuthenticator, config::RetryLayerConfig,
        services::oracle_proxy::proof_verifier::ProofVerifierOracle,
    };

    fn test_client() -> eyre::Result<reqwest::Client> {
        Ok(reqwest::ClientBuilder::new()
            .timeout(Duration::from_secs(10))
            .build()?)
    }

    async fn auth_service() -> eyre::Result<(FaceMatchAuthenticator, Arc<SharedProofVerifier>)> {
        let proof_verifier = shared_proof_verifier().await;
        let proxy = Arc::new(ProofVerifierOracle::init(
            test_client()?,
            proof_verifier.url.clone(),
            Environment::Dev,
            RetryLayerConfig::disabled(),
        )?);
        let service = FaceMatchAuthenticator::init(proxy);
        Ok((service, proof_verifier))
    }

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
        let (auth_service, _proof_verifier) = auth_service().await?;
        let oprf_key = auth_service.authenticate(&request).await?;
        assert_eq!(oprf_key.into_inner(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn invalid_proof_test() -> eyre::Result<()> {
        let mut fixture = zkpassport_oprf_test_utils::fixtures::load_fixture_data();
        fixture.proofs[0].proof = Some("invalid value".to_string());
        let request = build_request(fixture);

        let (auth_service, _proof_verifier) = auth_service().await?;
        let is_err = auth_service
            .authenticate(&request)
            .await
            .expect_err("Should fail");
        assert_eq!(is_err.code(), error_codes::ORACLE_BAD_REQUEST);
        assert_eq!(is_err.message(), "Cannot convert undefined to a BigInt");

        Ok(())
    }

    #[tokio::test]
    async fn swapped_base_proofs_test() -> eyre::Result<()> {
        let mut fixture = zkpassport_oprf_test_utils::fixtures::load_fixture_data();
        let dummy = fixture.proofs[0].proof.clone();
        fixture.proofs[0].proof = fixture.proofs[1].proof.clone();
        fixture.proofs[1].proof = dummy;
        let request = build_request(fixture);

        let (auth_service, _proof_verifier) = auth_service().await?;
        let is_err = auth_service
            .authenticate(&request)
            .await
            .expect_err("Should fail");
        assert_eq!(is_err.code(), error_codes::ORACLE_BAD_REQUEST);
        assert_eq!(
            is_err.message(),
            "Proof verification failed: {\"sig_check_dsc\":{\"certificate\":{\"expected\":\"A valid root from ZKPassport Registry\",\"received..."
        );

        Ok(())
    }

    #[tokio::test]
    async fn wrong_proof_count_test() -> eyre::Result<()> {
        let mut fixture = zkpassport_oprf_test_utils::fixtures::load_fixture_data();
        fixture.proofs.pop();
        let request = build_request(fixture);

        let (auth_service, _proof_verifier) = auth_service().await?;
        let is_err = auth_service
            .authenticate(&request)
            .await
            .expect_err("Should fail");
        assert_eq!(is_err.code(), error_codes::ORACLE_BAD_REQUEST);
        assert_eq!(
            is_err.message(),
            "Expected 5 subproofs (3 base + facematch + oprf_auth), got 4"
        );

        Ok(())
    }

    #[tokio::test]
    async fn missing_facematch_proof_test() -> eyre::Result<()> {
        let mut fixture = zkpassport_oprf_test_utils::fixtures::load_fixture_data();
        fixture.proofs[3].proof = None;
        let request = build_request(fixture);

        let (auth_service, _proof_verifier) = auth_service().await?;
        let is_err = auth_service
            .authenticate(&request)
            .await
            .expect_err("Should fail");
        assert_eq!(is_err.code(), error_codes::ORACLE_BAD_REQUEST);
        assert_eq!(is_err.message(), "Missing required facematch proof");

        Ok(())
    }

    #[tokio::test]
    async fn missing_oprf_auth_proof_test() -> eyre::Result<()> {
        let mut fixture = zkpassport_oprf_test_utils::fixtures::load_fixture_data();
        fixture.proofs[4].proof = None;
        let request = build_request(fixture);

        let (auth_service, _proof_verifier) = auth_service().await?;
        let is_err = auth_service
            .authenticate(&request)
            .await
            .expect_err("Should fail");
        assert_eq!(is_err.code(), error_codes::ORACLE_BAD_REQUEST);
        assert_eq!(is_err.message(), "Missing required oprf_auth proof");

        Ok(())
    }

    #[tokio::test]
    async fn blinded_identifier_mismatch_test() -> eyre::Result<()> {
        let fixture = zkpassport_oprf_test_utils::fixtures::load_fixture_data();

        // Blind with scalar 2 instead of the fixture's beta so the transmitted point
        // diverges from the one baked into the oprf_auth proof.
        let different_beta = ark_babyjubjub::Fr::from(2u64);
        let blinding_factor =
            BlindingFactor::from_scalar(different_beta).expect("Invalid blinding factor");
        let blinded_query =
            taceo_oprf::core::oprf::client::blind_query(fixture.private_nullifier, blinding_factor);
        let request = OprfRequest {
            request_id: Uuid::new_v4(),
            blinded_query: blinded_query.blinded_query(),
            auth: FaceMatchRequestAuth::new(OprfKeyId::new(U160::from(1)), fixture.proofs),
        };

        let (auth_service, _proof_verifier) = auth_service().await?;
        let is_err = auth_service
            .authenticate(&request)
            .await
            .expect_err("Should fail");
        assert_eq!(is_err.code(), error_codes::ORACLE_BAD_REQUEST);
        assert_eq!(
            is_err.message(),
            "blinded_unique_identifier does not match oprf_auth proof output"
        );

        Ok(())
    }

    #[tokio::test]
    async fn oracle_unreachable_test() -> eyre::Result<()> {
        // Port 1 on loopback is never open; any connection attempt immediately
        // returns ECONNREFUSED without waiting for a timeout.
        let proxy = Arc::new(ProofVerifierOracle::init(
            test_client()?,
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

    #[tokio::test]
    async fn oracle_empty_proofs() -> eyre::Result<()> {
        let fixture = zkpassport_oprf_test_utils::fixtures::load_fixture_data();
        let mut request = build_request(fixture);
        request.auth.proofs.clear();

        let (auth_service, _proof_verifier) = auth_service().await?;
        let is_err = auth_service
            .authenticate(&request)
            .await
            .expect_err("Should fail");
        assert_eq!(is_err.code(), error_codes::ORACLE_BAD_REQUEST);
        assert_eq!(
            is_err.message(),
            "Expected 5 subproofs (3 base + facematch + oprf_auth), got 0"
        );

        Ok(())
    }
}
