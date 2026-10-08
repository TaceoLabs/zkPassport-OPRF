use backon::Retryable as _;
use eyre::Context as _;
use sqlx::PgPool;
use taceo_nodes_common::postgres::{CreateSchema, PostgresConfig};
use tracing::instrument;
use zkpassport_oprf_authentication::{AuthCommitment, SaltedIdentifier};

#[derive(Debug, thiserror::Error)]
pub(crate) enum DbError {
    #[error("unknown identifier")]
    UnknownIdentifier,
    #[error("internal error: {0:?}")]
    Internal(#[from] eyre::Report),
}

/// The postgres DB connection that stores the user registration material.
///
/// Is another pool than the OPRF defined secret-manager, but can use the same DB connection with a different schema. This is necessary because the schema for this DB is managed by the nodes and they need write access to this schema in contrast to the DB schema that manages the OPRF keys.
#[derive(Clone, Debug)]
pub struct ZkPassportDb {
    pool: PgPool,
    backoff: backon::ConstantBuilder,
}

impl ZkPassportDb {
    /// Initializes the `ZkPassportDb`.
    ///
    /// Connects to the Postgres database using the provided configuration potentially running migrations.
    ///
    /// # Errors
    /// Returns an error if the connection to the database fails.
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

    /// Replaces the commitment stored for `identifier`.
    ///
    /// # Errors
    /// Returns [`DbError::UnknownIdentifier`] if no entry exists for `identifier`.
    pub(crate) async fn rotate_commitment(
        &self,
        identifier: SaltedIdentifier,
        commitment: AuthCommitment,
    ) -> Result<(), DbError> {
        let result = self
            .with_retry("rotate_commitment", || {
                sqlx::query(
                    "UPDATE passport_registrations SET commitment = $2 WHERE identifier = $1",
                )
                .bind(taceo_nodes_common::postgres::to_db_ark_serialize_uncompressed(&identifier).as_slice())
                .bind(taceo_nodes_common::postgres::to_db_ark_serialize_uncompressed(&commitment).as_slice())
                .execute(&self.pool)
            })
            .await
            .map_err(|e| DbError::Internal(eyre::Report::new(e)))?;
        if result.rows_affected() == 0 {
            return Err(DbError::UnknownIdentifier);
        }
        Ok(())
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
