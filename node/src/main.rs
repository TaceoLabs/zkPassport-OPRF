//! OPRF Node Binary for zkPassport.
//!
//! Main entry point for the zkPassport OPRF service node. Loads configuration
//! from environment variables using the `TACEO_OPRF_NODE__` prefix, initializes
//! the PostgreSQL secret manager, and starts the Axum server with graceful
//! shutdown support.

use std::{net::SocketAddr, process::ExitCode, sync::Arc, time::Duration};

use eyre::Context as _;
use serde::Deserialize;
use taceo_nodes_common::postgres::PostgresConfig;
use taceo_oprf::service::secret_manager::postgres::PostgresSecretManager;
use taceo_zkpassport_oprf_node::config::ZkPassportNodeConfig;

/// Top-level configuration for the OPRF node, loaded from `TACEO_OPRF_NODE__*` environment variables.
#[derive(Clone, Debug, Deserialize)]
struct FullZkPassportNodeConfig {
    /// The bind addr of the AXUM server
    #[serde(default = "default_bind_addr")]
    pub bind_addr: SocketAddr,
    /// Max wait time the service waits for its workers during shutdown.
    #[serde(default = "default_max_wait_shutdown")]
    #[serde(with = "humantime_serde")]
    pub max_wait_time_shutdown: Duration,
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
/// The `service.rpc.http_urls` key is parsed as a comma-separated list.
///
/// # Errors
/// Returns an error if any required variable is missing or cannot be parsed.
fn load_zk_passport_id_config() -> eyre::Result<FullZkPassportNodeConfig> {
    let cfg = config::Config::builder().add_source(
        config::Environment::with_prefix("TACEO_OPRF_NODE")
            .separator("__")
            .list_separator(",")
            .with_list_parse_key("service.rpc.http_urls")
            .try_parsing(true),
    );

    cfg.build()
        .context("while building from config")?
        .try_deserialize()
        .context("while parsing config")
}

/// Default bind address (`0.0.0.0:4321`) used when `TACEO_OPRF_NODE__BIND_ADDR` is not set.
fn default_bind_addr() -> SocketAddr {
    "0.0.0.0:4321".parse().expect("valid SocketAddr")
}

/// Default maximum time to wait for graceful shutdown (10 seconds).
const fn default_max_wait_shutdown() -> Duration {
    Duration::from_secs(10)
}

/// Core async runtime: loads config, starts services, runs the Axum server, and waits for shutdown.
///
/// # Errors
/// Returns an error if startup fails or if a spawned task returns an error during shutdown.
async fn run() -> eyre::Result<()> {
    taceo_oprf::service::metrics::describe_metrics();
    taceo_zkpassport_oprf_node::metrics::describe_metrics();

    tracing::info!("{}", taceo_nodes_common::version_info!());

    let config = load_zk_passport_id_config()?;
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
    let max_wait_time_shutdown = config.max_wait_time_shutdown;

    tracing::info!("starting zkPassport service...");
    let (oprf_service_router, oprf_node_tasks) = taceo_zkpassport_oprf_node::start(
        config.node_config,
        secret_manager,
        cancellation_token.clone(),
    )
    .await?;

    let server = tokio::spawn({
        let cancellation_token = cancellation_token.clone();
        async move {
            let _drop_guard = cancellation_token.clone().drop_guard();
            tracing::info!("starting axum server on {bind_addr}",);
            let listener = tokio::net::TcpListener::bind(bind_addr).await?;
            let axum_result = axum::serve(listener, oprf_service_router)
                .with_graceful_shutdown(async move { cancellation_token.cancelled().await })
                .await;
            tracing::info!("axum server shutdown");
            axum_result
        }
    });

    tracing::info!("waiting for shutdown...");
    cancellation_token.cancelled().await;

    tracing::info!("waiting for shutdown of services (max wait time {max_wait_time_shutdown:?})..");
    match tokio::time::timeout(max_wait_time_shutdown, async move {
        let (server, oprf_node_tasks) = tokio::join!(server, oprf_node_tasks);
        server??;
        oprf_node_tasks??;
        eyre::Ok(())
    })
    .await
    {
        Ok(Ok(_)) => {
            tracing::info!("successfully finished graceful shutdown in time");
            Ok(())
        }
        Ok(Err(err)) => Err(err),
        Err(_) => {
            eyre::bail!("could not finish shutdown in time");
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("can install");
    let tracing_config =
        taceo_nodes_observability::TracingConfig::try_from_env().expect("Can create TryingConfig");
    let _tracing_handle = taceo_nodes_observability::initialize_tracing(&tracing_config)
        .expect("Can get tracing handle");
    match run().await {
        Ok(_) => {
            tracing::info!("good night");
            ExitCode::SUCCESS
        }
        Err(err) => {
            tracing::error!("oprf-node did shutdown: {err:?}");
            tracing::error!("good night anyways");
            ExitCode::FAILURE
        }
    }
}
