use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, FromRef, State},
    routing::post,
};
use reqwest::StatusCode;
use taceo_oprf::service::config::OprfNodeServiceConfig;
use telemetry_batteries::{opentelemetry, tracing::middleware::TraceLayer};
use tower_http::timeout::TimeoutLayer;
use tracing::instrument;
use zkpassport_oprf_authentication::{CommitmentRotationRequest, RegistrationRequest};

use crate::{
    ZkPassportDb, api::errors::ApiError, metrics, services::oracle_proxy::OracleProxyService,
};

pub(crate) mod errors;
#[cfg(test)]
mod tests;

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
        proofs,
    }): Json<CommitmentRotationRequest>,
) -> ApiResult<()> {
    tracing::trace!("handling rotation request");
    proxy
        .secret_rotation(salted_identifier, new_commitment, &proofs)
        .await?;
    tracing::trace!("proof verification for rotation succeeded - rotating secret now");
    db.rotate_commitment(salted_identifier, new_commitment)
        .await?;
    metrics::api::inc_rotations();
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
        proofs,
    }): Json<RegistrationRequest>,
) -> ApiResult<()> {
    tracing::trace!("handling registration request");
    proxy
        .registration_commitment(salted_identifier, commitment, &proofs)
        .await?;
    tracing::trace!("proof verification for registration succeeded - storing identifier now");
    db.insert_registration(salted_identifier, commitment)
        .await?;
    metrics::api::inc_registrations();
    tracing::trace!("successfully registered identifier");
    Ok(())
}

pub(crate) fn routes(
    config: &OprfNodeServiceConfig,
    proxy: OracleProxyService,
    db: ZkPassportDb,
) -> Router {
    Router::new()
        .route("/registration", post(registration))
        .route("/rotation", post(rotation))
        .layer(DefaultBodyLimit::max(config.ws_max_message_size))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::SERVICE_UNAVAILABLE,
            config.session_lifetime,
        ))
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
