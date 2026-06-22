//! OPRF Node Binary for zkPassport.
//!
//! Main entry point for the zkPassport OPRF service node. Loads configuration
//! from environment variables using the `TACEO_OPRF_NODE__` prefix, initializes
//! the PostgreSQL secret manager, and starts the Axum server with graceful
//! shutdown support.

use std::{net::SocketAddr, process::ExitCode, sync::Arc};

use eyre::Context as _;
use serde::Deserialize;
use taceo_nodes_common::postgres::PostgresConfig;
use taceo_oprf::service::secret_manager::{SecretManager, postgres::PostgresSecretManager};
use taceo_zkpassport_oprf_node::config::ZkPassportNodeConfig;

#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

/// Top-level configuration for the OPRF node, loaded from `TACEO_OPRF_NODE__*` environment variables.
#[derive(Clone, Debug, Deserialize)]
struct FullZkPassportNodeConfig {
    /// The bind addr of the AXUM server
    #[serde(default = "default_bind_addr")]
    pub bind_addr: SocketAddr,
    /// The OPRF service config
    #[serde(rename = "service")]
    pub node_config: ZkPassportNodeConfig,
    /// The postgres config for the secret-manager
    #[serde(rename = "postgres")]
    pub postgres_config: PostgresConfig,
}

/// Load and deserialize the node configuration from environment variables.
///
/// Uses the `TACEO_OPRF_NODE__` prefix with `__` as separator.
///
/// # Errors
/// Returns an error if any required variable is missing or cannot be parsed.
fn load_zk_passport_config() -> Result<FullZkPassportNodeConfig, config::ConfigError> {
    let cfg = config::Config::builder()
        .add_source(config::Environment::with_prefix("TACEO_OPRF_NODE").separator("__"));
    let config = cfg.build()?.try_deserialize()?;
    // Unset all env vars with our prefix to prevent leakage to subprocesses.
    // Safety: this is called before any threads are spawned.
    let keys_to_remove: Vec<String> = std::env::vars()
        .filter_map(|(k, _)| k.starts_with("TACEO_OPRF_NODE").then_some(k))
        .collect();
    for key in keys_to_remove {
        // SAFETY: no other threads are running at this point in the startup sequence.
        unsafe {
            std::env::remove_var(&key);
        }
    }
    Ok(config)
}

/// Default bind address (`0.0.0.0:4321`) used when `TACEO_OPRF_NODE__BIND_ADDR` is not set.
fn default_bind_addr() -> SocketAddr {
    "0.0.0.0:4321".parse().expect("valid SocketAddr")
}

/// Core async runtime: loads config, starts services, runs the Axum server, and waits for shutdown.
///
/// # Errors
/// Returns an error if startup fails or if a spawned task returns an error during shutdown.
async fn run(config: FullZkPassportNodeConfig) -> eyre::Result<()> {
    tracing::info!("{}", taceo_nodes_common::version_info!());

    tracing::info!("starting oprf-node with config: {config:#?}");

    // Load the postgres secret manager.
    tracing::info!("connect to postgres secret-manager..");
    let secret_manager = Arc::new(
        PostgresSecretManager::init(&config.postgres_config)
            .await
            .context("while starting postgres secret-manager")?,
    );

    let (cancellation_token, _) =
        taceo_nodes_common::spawn_shutdown_task(taceo_nodes_common::default_shutdown_signal());

    // Clone the values we need afterwards
    let bind_addr = config.bind_addr;

    let node_information = secret_manager
        .load_node_information()
        .await
        .context("while loading node information")?;

    tracing::info!("loaded node-information: {node_information:#?}");

    tracing::info!("starting zkPassport service...");
    let oprf_service_router = taceo_zkpassport_oprf_node::start(
        config.node_config,
        secret_manager,
        node_information,
        cancellation_token.clone(),
    )
    .await?;

    tracing::info!("starting axum server on {bind_addr}",);
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    axum::serve(listener, oprf_service_router)
        .with_graceful_shutdown(async move { cancellation_token.cancelled().await })
        .await
        .context("while serving axum")?;

    tracing::info!("successfully finished graceful shutdown in time");
    Ok(())
}

fn main() -> ExitCode {
    // try loading config and unsetting vars before we do any potentially multithreaded work;
    let maybe_config = load_zk_passport_config();

    // we panic if we cannot setup tracing + TLS - if that fails we won't see anything anyways on tracing endpoint
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("can install");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Can build Tokio runtime");

    runtime.block_on(async {
        let _guard = telemetry_batteries::init();
        taceo_zkpassport_oprf_node::metrics::describe_metrics();

        // load the config
        let config = match maybe_config {
            Ok(config) => config,
            Err(err) => {
                tracing::error!(%err, "failed to load config");
                return ExitCode::FAILURE;
            }
        };

        match run(config).await {
            Ok(_) => {
                tracing::info!("good night");
                ExitCode::SUCCESS
            }
            Err(err) => {
                tracing::error!(?err, "oprf-node did shutdown: {err}");
                tracing::error!("good night anyways");
                ExitCode::FAILURE
            }
        }
    })
}
