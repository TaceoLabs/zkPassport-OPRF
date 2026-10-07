use backon::Retryable as _;
use eyre::Context as _;
use sqlx::PgPool;
use taceo_nodes_common::postgres::{CreateSchema, PostgresConfig};
use tracing::instrument;

#[derive(Clone, Debug)]
pub struct ZkPassportDb {
    pool: PgPool,
    backoff: backon::ConstantBuilder,
}

impl ZkPassportDb {
    #[instrument(level = "debug", skip_all)]
    pub async fn init(config: &PostgresConfig) -> eyre::Result<Self> {
        tracing::debug!("init PgPool with schema: {}", config.schema);
        let pool = taceo_nodes_common::postgres::pg_pool_with_schema(config, CreateSchema::Yes)
            .await
            .context("while connecting to postgres DB")?;
        // We create the pool eagerly, so running migrations here should not hit pool-acquire retries.
        tracing::trace!("potentially running migrations..");
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .context("while running migrations")?;

        Ok(Self {
            pool,
            backoff: backon::ConstantBuilder::new()
                .with_delay(config.retry_delay)
                .with_max_times(config.max_retries.get()),
        })
    }

    pub(crate) async fn with_retry<F, Fut, T>(&self, op_name: &str, f: F) -> sqlx::Result<T>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = sqlx::Result<T>>,
    {
        f.retry(self.backoff)
            .sleep(tokio::time::sleep)
            .when(is_retryable_error)
            .notify(|err, duration| {
                tracing::warn!(%err, "Retrying {op_name} in db after {duration:?}");
            })
            .await
    }
}

fn is_retryable_error(e: &sqlx::Error) -> bool {
    match e {
        // structural / driver-level errors
        sqlx::Error::PoolTimedOut
        | sqlx::Error::Io(_)
        | sqlx::Error::Tls(_)
        | sqlx::Error::Protocol(_)
        | sqlx::Error::AnyDriverError(_)
        | sqlx::Error::WorkerCrashed
        | sqlx::Error::BeginFailed => true,

        // serialization_failure and deadlock detected for transactions
        sqlx::Error::Database(db_err) => {
            matches!(db_err.code().as_deref(), Some("40001" | "40P01"))
        }
        _ => false,
    }
}
