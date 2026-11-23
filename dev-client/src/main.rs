//! Smoke and stress tests for deployed zkPassport OPRF nodes.
//!
//! Sends the fixtures of the `zkpassport-oprf-test-utils` crate to a set of OPRF nodes. The
//! fixtures only verify at nodes in the `dev` environment, whose proof-verifier requests use
//! `?devmode=true`. No command rotates the fixture, so all of them can be repeated.
//!
//! Run via:
//!
//! ```sh
//! just run-dev-client <command>
//! ```

use std::num::NonZeroUsize;

use clap::{Parser, Subcommand, ValueEnum};
use ruint::aliases::U160;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt as _, util::SubscriberInitExt as _};
use zkpassport_oprf_authentication::NonIdentifierOprfKeyId;
use zkpassport_oprf_test_utils::node_client::NodeClient;

mod commands;

#[derive(Parser, Debug)]
struct Cli {
    /// The URLs to all OPRF nodes
    #[clap(
        long,
        env = "OPRF_DEV_CLIENT_NODES",
        value_delimiter = ',',
        default_value = "http://127.0.0.1:10000,http://127.0.0.1:10001,http://127.0.0.1:10002"
    )]
    nodes: Vec<String>,

    /// The threshold of nodes that need to respond
    #[clap(long, env = "OPRF_DEV_CLIENT_THRESHOLD", default_value = "2")]
    threshold: NonZeroUsize,

    /// The OPRF key used for the nullifier and face-match requests
    #[clap(long, env = "OPRF_DEV_CLIENT_OPRF_KEY_ID", default_value = "2")]
    oprf_key_id: U160,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Runs the v2 flow without the rotation, or only the given steps in the given order. Can be
    /// repeated, but fails on nodes where the rotation of the fixture ran.
    Smoke {
        /// The steps to run. All steps if empty
        steps: Vec<SmokeStep>,
        /// For nodes outside the `dev` environment: checks that they are up and reject the
        /// fixture proofs, and writes nothing. Supports the steps `online` and `identify`
        #[clap(long)]
        prod: bool,
    },
    /// Sends requests concurrently to nodes in the `dev` environment. Nullifier requests need
    /// nodes where the fixture was not rotated.
    Stress {
        /// The kind of request to send
        request: StressRequest,
        /// Maximum number of requests in flight
        #[clap(long, default_value = "10")]
        concurrency: NonZeroUsize,
        /// Total number of requests
        #[clap(long, default_value = "100")]
        requests: NonZeroUsize,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum SmokeStep {
    /// Every node is healthy and the nodes agree on the public keys
    Online,
    Identify,
    /// Registers the fixture. Succeeds if it is already registered
    Register,
    /// Needs the fixture to be registered
    Query,
    FaceMatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum StressRequest {
    Identify,
    Nullifier,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    install_tracing("taceo=trace,warn");
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("can install");
    let cli = Cli::parse();
    tracing::info!("starting oprf-dev-client with config: {cli:#?}");

    let oprf_key_id = NonIdentifierOprfKeyId::new(cli.oprf_key_id)
        .ok_or_else(|| eyre::eyre!("--oprf-key-id cannot be the identifier OPRF key"))?;
    let client = NodeClient::new(cli.nodes, cli.threshold)?;
    match cli.command {
        Command::Smoke { steps, prod } => commands::smoke(&client, oprf_key_id, steps, prod).await,
        Command::Stress {
            request,
            concurrency,
            requests,
        } => commands::stress(client, request, oprf_key_id, concurrency, requests).await,
    }
}

fn install_tracing(env_filter: &str) {
    let fmt_layer = fmt::layer().compact();
    let filter_layer = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(env_filter))
        .unwrap();

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .init();
}
