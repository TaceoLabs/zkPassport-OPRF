//! The commands of the dev-client.

use std::{
    collections::BTreeMap,
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, Instant},
};

use eyre::Context as _;
use reqwest::StatusCode;
use taceo_oprf::{client::Error, types::OprfKeyId};
use tokio::{sync::Semaphore, task::JoinSet};
use zkpassport_oprf_authentication::{NonIdentifierOprfKeyId, error_codes, identifier_oprf_key_id};
use zkpassport_oprf_test_utils::{
    fixtures::load_v2_fixtures,
    node_client::{NodeClient, expect_rejected, expect_statuses},
};

use crate::StressRequest;

pub(crate) async fn smoke(
    client: &NodeClient,
    oprf_key_id: NonIdentifierOprfKeyId,
) -> eyre::Result<()> {
    let fixtures = load_v2_fixtures();

    tracing::info!("identify");
    client
        .identify(&fixtures.identify)
        .await
        .context("identify")?;

    tracing::info!("register");
    let statuses = client.register(&fixtures.register).await?;
    expect_statuses(&statuses, &[StatusCode::OK, StatusCode::CONFLICT]).context("register")?;

    tracing::info!("query");
    client
        .nullifier(oprf_key_id, &fixtures.query)
        .await
        .context("query")?;

    tracing::info!("face match");
    client.face_match(oprf_key_id).await.context("face match")?;
    Ok(())
}

pub(crate) async fn smoke_prod(
    client: &NodeClient,
    oprf_key_id: NonIdentifierOprfKeyId,
) -> eyre::Result<()> {
    tracing::info!("nodes are online");
    client
        .check_online(&[identifier_oprf_key_id(), OprfKeyId::from(oprf_key_id)])
        .await?;

    tracing::info!("identify with the fixture proofs is rejected by the verifier");
    let fixtures = load_v2_fixtures();
    let result = client.identify(&fixtures.identify).await;
    expect_rejected(result, error_codes::ORACLE_BAD_REQUEST).context("identify")
}

pub(crate) async fn stress(
    client: NodeClient,
    request: StressRequest,
    oprf_key_id: NonIdentifierOprfKeyId,
    concurrency: NonZeroUsize,
    requests: NonZeroUsize,
) -> eyre::Result<()> {
    let requests = requests.get();
    let client = Arc::new(client);
    let fixtures = Arc::new(load_v2_fixtures());
    if request == StressRequest::Nullifier {
        let statuses = client.register(&fixtures.register).await?;
        expect_statuses(&statuses, &[StatusCode::OK, StatusCode::CONFLICT]).context("register")?;
    }
    let in_flight = Arc::new(Semaphore::new(concurrency.get()));
    let mut tasks = JoinSet::new();

    let start = Instant::now();
    for _ in 0..requests {
        let permit = Arc::clone(&in_flight).acquire_owned().await?;
        let client = Arc::clone(&client);
        let fixtures = Arc::clone(&fixtures);
        tasks.spawn(async move {
            let _permit = permit;
            let request_start = Instant::now();
            let result = match request {
                StressRequest::Identify => client.identify(&fixtures.identify).await,
                StressRequest::Nullifier => client.nullifier(oprf_key_id, &fixtures.query).await,
            };
            (request_start.elapsed(), result)
        });
    }

    let mut latencies = Vec::with_capacity(requests);
    let mut errors = BTreeMap::<String, usize>::new();
    while let Some(joined) = tasks.join_next().await {
        match joined? {
            (latency, Ok(_)) => latencies.push(latency),
            (_, Err(err)) => *errors.entry(error_label(&err)).or_default() += 1,
        }
    }
    let elapsed = start.elapsed();

    latencies.sort_unstable();
    tracing::info!(
        succeeded = latencies.len(),
        failed = requests - latencies.len(),
        ?elapsed,
        requests_per_second = requests as f64 / elapsed.as_secs_f64(),
        p50 = ?percentile(&latencies, 50),
        p99 = ?percentile(&latencies, 99),
        "stress test finished"
    );
    eyre::ensure!(errors.is_empty(), "requests failed: {errors:?}");
    Ok(())
}

fn error_label(err: &Error) -> String {
    match err {
        Error::ThresholdServiceError(err) => format!("service error {}", err.error_code),
        err => err.to_string(),
    }
}

/// `sorted` must be ascending; returns zero if it is empty.
fn percentile(sorted: &[Duration], percent: usize) -> Duration {
    sorted
        .len()
        .checked_sub(1)
        .map_or(Duration::ZERO, |last| sorted[last * percent / 100])
}
