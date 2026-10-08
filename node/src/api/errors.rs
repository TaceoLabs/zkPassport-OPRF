use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;

use crate::services::{oracle_proxy::OracleError, postgres::DbError};

/// Errors returned by the HTTP API, keyed by the response the client receives.
///
/// Variants exist only for outcomes the client must distinguish. Everything else is
/// [`ApiError::Internal`], which is logged here and answered with a generic 500.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ApiError {
    #[error("unknown identifier")]
    UnknownIdentifier,
    #[error("identifier already registered")]
    AlreadyRegistered,
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("oracle not reachable")]
    OracleUnavailable,
    #[error("internal error: {0:?}")]
    Internal(#[from] eyre::Report),
}

impl From<OracleError> for ApiError {
    fn from(err: OracleError) -> Self {
        match err {
            OracleError::BadRequest(reason) => Self::BadRequest(reason),
            OracleError::OracleNotReachable(_) => Self::OracleUnavailable,
            OracleError::UnexpectedStatusCode { .. } | OracleError::InvalidMessage(_) => {
                Self::Internal(eyre::Report::from(err))
            }
        }
    }
}

impl From<DbError> for ApiError {
    fn from(value: DbError) -> Self {
        match value {
            DbError::UnknownIdentifier => Self::UnknownIdentifier,
            DbError::AlreadyRegistered => Self::AlreadyRegistered,
            DbError::Internal(report) => Self::Internal(report),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            Self::BadRequest(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            Self::UnknownIdentifier => (StatusCode::NOT_FOUND, self.to_string()),
            Self::AlreadyRegistered => (StatusCode::CONFLICT, self.to_string()),
            Self::OracleUnavailable => (StatusCode::SERVICE_UNAVAILABLE, self.to_string()),
            Self::Internal(report) => {
                tracing::error!(err = ?report, "internal error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal server error".to_owned(),
                )
            }
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_codes() {
        let cases: [(ApiError, StatusCode); 3] = [
            (
                OracleError::BadRequest("bad".to_owned()).into(),
                StatusCode::BAD_REQUEST,
            ),
            (
                OracleError::UnexpectedStatusCode {
                    status: StatusCode::IM_A_TEAPOT,
                    body: String::new(),
                }
                .into(),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (
                eyre::eyre!("boom").into(),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
        ];
        for (err, expected) in cases {
            assert_eq!(err.into_response().status(), expected);
        }
        assert_eq!(
            ApiError::OracleUnavailable.into_response().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
}
