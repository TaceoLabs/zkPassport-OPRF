//! Configuration types and CLI/environment parsing for the OPRF node.

use std::time::Duration;

use backon::ExponentialBuilder;
use reqwest::Url;
use serde::Deserialize;
use taceo_oprf::service::{VersionReq, config::OprfNodeServiceConfig};

/// The configuration for the OPRF node.
///
/// It can be configured via environment variables or command line arguments using `clap`.
#[derive(Clone, Debug, Deserialize)]
#[non_exhaustive]
pub struct ZkPassportNodeConfig {
    /// The `URL` of the oracle health check endpoint.
    pub oracle_health_check_url: Url,

    /// The `URL` of the oracle verifying the face-match proofs.
    pub oracle_verifier_url: Url,

    /// The interval in which we do health checks.
    #[serde(default = "ZkPassportNodeConfig::default_oracle_health_check_interval")]
    #[serde(with = "humantime_serde")]
    pub oracle_health_check_interval: Duration,

    /// Request timeout when talking to the verifier oracle.
    #[serde(default = "ZkPassportNodeConfig::default_oracle_request_timeout")]
    #[serde(with = "humantime_serde")]
    pub oracle_request_timeout: Duration,

    /// The retry layer config for requests to the verifier oracle, used by
    /// both the face-match verify requests and the health-check task.
    #[serde(rename = "retry")]
    #[serde(default)]
    pub oracle_retry_layer: RetryLayerConfig,

    /// The OPRF service config
    #[serde(rename = "oprf")]
    pub node_config: OprfNodeServiceConfig,
}

/// Retry config for retry layers.
///
/// Used to build an [`backon::ExponentialBuilder`](https://docs.rs/backon/latest/backon/struct.ExponentialBuilder.html).
#[derive(Clone, Copy, Debug, Deserialize)]
#[non_exhaustive]
pub struct RetryLayerConfig {
    /// Min interval for retry layer when encountering retryable errors during requests to the verifier oracle.
    #[serde(
        default = "RetryLayerConfig::default_verifier_request_min_delay",
        with = "humantime_serde"
    )]
    pub verifier_request_min_delay: Duration,

    /// Max interval for retry layer when encountering retryable errors during requests to the verifier oracle.
    #[serde(
        default = "RetryLayerConfig::default_verifier_request_max_delay",
        with = "humantime_serde"
    )]
    pub verifier_request_max_delay: Duration,

    /// Max attempts for retry layer when encountering retryable errors during requests to the verifier oracle.
    #[serde(default = "RetryLayerConfig::default_verifier_request_max_attempts")]
    pub verifier_request_max_attempts: usize,
}

impl ZkPassportNodeConfig {
    fn default_oracle_health_check_interval() -> Duration {
        Duration::from_mins(5)
    }

    fn default_oracle_request_timeout() -> Duration {
        Duration::from_secs(25)
    }
}

impl Default for RetryLayerConfig {
    fn default() -> Self {
        Self::with_default_values()
    }
}

impl RetryLayerConfig {
    fn default_verifier_request_min_delay() -> Duration {
        Duration::from_millis(250)
    }

    fn default_verifier_request_max_delay() -> Duration {
        Duration::from_secs(2)
    }

    fn default_verifier_request_max_attempts() -> usize {
        5
    }

    #[allow(dead_code, reason = "used in test")]
    pub(crate) fn disabled() -> Self {
        RetryLayerConfig {
            verifier_request_max_attempts: 0,
            ..Default::default()
        }
    }

    pub(crate) fn with_default_values() -> Self {
        Self {
            verifier_request_min_delay: Self::default_verifier_request_min_delay(),
            verifier_request_max_delay: Self::default_verifier_request_max_delay(),
            verifier_request_max_attempts: Self::default_verifier_request_max_attempts(),
        }
    }

    pub(crate) fn exponential_backoff(self) -> ExponentialBuilder {
        ExponentialBuilder::new()
            .with_min_delay(self.verifier_request_min_delay)
            .with_max_delay(self.verifier_request_max_delay)
            .with_max_times(self.verifier_request_max_attempts)
            .with_jitter()
    }
}

impl ZkPassportNodeConfig {
    /// Initialize with default values for all optional fields
    #[must_use]
    pub fn with_default_values(
        environment: taceo_oprf::service::Environment,
        oracle_health_check_url: Url,
        oracle_verifier_url: Url,
        version_req: VersionReq,
    ) -> Self {
        Self {
            oracle_health_check_url,
            oracle_verifier_url,
            oracle_health_check_interval: Self::default_oracle_health_check_interval(),
            oracle_request_timeout: Self::default_oracle_request_timeout(),
            oracle_retry_layer: RetryLayerConfig::with_default_values(),
            node_config: OprfNodeServiceConfig::with_default_values(environment, version_req),
        }
    }
}
