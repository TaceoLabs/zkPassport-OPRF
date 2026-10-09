use axum::{
    Json, Router,
    extract::{FromRef, State},
    routing::post,
};
use tracing::instrument;
use zkpassport_oprf_authentication::{CommitmentRotationRequest, RegistrationRequest};

use crate::{ZkPassportDb, api::errors::ApiError, services::oracle_proxy::OracleProxy};

pub(crate) mod errors;

type ApiResult<T> = std::result::Result<T, ApiError>;

#[derive(Debug, Clone)]
pub(crate) struct AppState {
    proxy: OracleProxy,
    db: ZkPassportDb,
}

impl FromRef<AppState> for OracleProxy {
    fn from_ref(input: &AppState) -> Self {
        input.proxy.clone()
    }
}

impl FromRef<AppState> for ZkPassportDb {
    fn from_ref(input: &AppState) -> Self {
        input.db.clone()
    }
}

#[instrument(level = "info", skip_all)]
async fn rotation(
    State(proxy): State<OracleProxy>,
    State(db): State<ZkPassportDb>,
    Json(CommitmentRotationRequest {
        salted_identifier,
        new_commitment,
    }): Json<CommitmentRotationRequest>,
) -> ApiResult<()> {
    // TODO: unauthenticated until the oracle check and proofs are implemented
    proxy.secret_rotation().await?;
    tracing::trace!("proof verification for rotation succeeded - rotating secret now");
    db.rotate_commitment(salted_identifier, new_commitment)
        .await?;
    tracing::trace!("successfully rotated secret");
    Ok(())
}

#[instrument(level = "info", skip_all)]
async fn registration(
    State(proxy): State<OracleProxy>,
    State(db): State<ZkPassportDb>,
    Json(RegistrationRequest {
        salted_identifier,
        commitment,
        proofs: _,
    }): Json<RegistrationRequest>,
) -> ApiResult<()> {
    // TODO: unauthenticated until the oracle check and proofs are implemented. Verify both
    // the OPRF proof and the passport proof.
    proxy.registration_commitment().await?;
    tracing::trace!("proof verification for registration succeeded - storing identifier now");
    db.insert_registration(salted_identifier, commitment)
        .await?;
    tracing::trace!("successfully registered identifier");
    Ok(())
}

pub(crate) fn routes(proxy: OracleProxy, db: ZkPassportDb) -> Router {
    Router::new()
        .route("/registration", post(registration))
        .route("/rotation", post(rotation))
        .with_state(AppState { proxy, db })
}
