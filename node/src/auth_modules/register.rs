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

