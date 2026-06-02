//! Configuration types and CLI/environment parsing for the OPRF node.

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

    /// The OPRF service config
    #[serde(rename = "oprf")]
    pub node_config: OprfNodeServiceConfig,
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
            node_config: OprfNodeServiceConfig::with_default_values(environment, version_req),
        }
    }
}
