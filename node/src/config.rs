//! Configuration types and CLI/environment parsing for the OPRF node.

use alloy::primitives::Address;
use reqwest::Url;
use serde::Deserialize;
use taceo_nodes_common::web3::{self, HttpRpcProviderConfig};
use taceo_oprf::service::{VersionReq, config::OprfNodeServiceConfig};

/// The configuration for the OPRF node.
///
/// It can be configured via environment variables or command line arguments using `clap`.
#[derive(Clone, Debug, Deserialize)]
#[non_exhaustive]
pub struct ZkPassportNodeConfig {
    /// The `URL` of the oracle verifying the face-match proofs.
    pub oracle_url: Url,

    /// The OPRF service config
    #[serde(rename = "oprf")]
    pub node_config: OprfNodeServiceConfig,

    /// The blockchain RPC config
    #[serde(rename = "rpc")]
    pub rpc_provider_config: web3::HttpRpcProviderConfig,
}

impl ZkPassportNodeConfig {
    /// Initialize with default values for all optional fields
    #[must_use]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "We want to consume the contracts"
    )]
    pub fn with_default_values(
        environment: taceo_oprf::service::Environment,
        proof_oracle_url: Url,
        oprf_key_registry_contract: Address,
        ws_rpc_url: Url,
        version_req: VersionReq,
        rpc_provider_config: HttpRpcProviderConfig,
    ) -> Self {
        Self {
            oracle_url: proof_oracle_url,
            node_config: OprfNodeServiceConfig::with_default_values(
                environment,
                oprf_key_registry_contract,
                ws_rpc_url,
                version_req,
            ),
            rpc_provider_config,
        }
    }
}
