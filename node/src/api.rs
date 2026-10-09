use axum::{
    Json, Router,
    extract::{FromRef, State},
    routing::post,
};
use telemetry_batteries::{opentelemetry, tracing::middleware::TraceLayer};
use tracing::instrument;
use zkpassport_oprf_authentication::{CommitmentRotationRequest, RegistrationRequest};

use crate::{ZkPassportDb, api::errors::ApiError, services::oracle_proxy::OracleProxyService};

pub(crate) mod errors;

type ApiResult<T> = std::result::Result<T, ApiError>;

#[derive(Clone)]
pub(crate) struct AppState {
    proxy: OracleProxyService,
    db: ZkPassportDb,
}

impl FromRef<AppState> for OracleProxyService {
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
    State(proxy): State<OracleProxyService>,
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
    State(proxy): State<OracleProxyService>,
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

pub(crate) fn routes(proxy: OracleProxyService, db: ZkPassportDb) -> Router {
    Router::new()
        .route("/registration", post(registration))
        .route("/rotation", post(rotation))
        .layer(TraceLayer::new_for_axum().with_make_span(|req| {
            let headers = req.headers();
            tracing::info_span!(
                "HTTP request",
                http.request.method = %req.method(),
                http.route = tracing::field::Empty,
                network.protocol.version = ?req.version(),
                server.address = headers.get(axum::http::header::HOST).and_then(|v| v.to_str().ok()),
                user_agent.original = headers.get(axum::http::header::USER_AGENT).and_then(|v| v.to_str().ok()),
                http.response.status_code = tracing::field::Empty,
                http.status_code = tracing::field::Empty,
                url.path = req.uri().path(),
                url.query = req.uri().query(),
                url.scheme = req.uri().scheme_str(),
                otel.name = %req.method(),
                otel.kind = ?opentelemetry::trace::SpanKind::Server,
                otel.status_code = tracing::field::Empty,
                exception.message = tracing::field::Empty,
                "span.type" = "web",
            )
        }))
        .with_state(AppState { proxy, db })
}
