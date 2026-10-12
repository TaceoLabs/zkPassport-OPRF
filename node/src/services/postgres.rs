use backon::Retryable as _;
use eyre::Context as _;
use sqlx::PgPool;
use taceo_nodes_common::postgres::{CreateSchema, PostgresConfig};
use tracing::instrument;
use zkpassport_oprf_authentication::{AuthCommitment, AuthErrorKind, SaltedIdentifier};

#[derive(Debug, thiserror::Error)]
pub(crate) enum DbError {
    #[error("unknown identifier")]
    UnknownIdentifier,
    #[error("identifier already registered")]
    AlreadyRegistered,
    #[error("commitment was previously used for this identifier")]
    CommitmentPreviouslyUsed,
    #[error(transparent)]
    Db(#[from] sqlx::Error),
    #[error("internal error: {0:?}")]
    Internal(#[from] eyre::Report),
}

impl DbError {
    pub(crate) fn log(&self) {
        match self {
            DbError::UnknownIdentifier
            | DbError::AlreadyRegistered
            | DbError::CommitmentPreviouslyUsed => {
                tracing::warn!(err=?self, auth_error = true, "{self}");
            }
            DbError::Db(err) => tracing::error!(err=?err, "DB error"),
            DbError::Internal(report) => tracing::error!(err=?report, "internal DB error"),
        }
    }
}

impl From<DbError> for AuthErrorKind {
    fn from(value: DbError) -> Self {
        match value {
            DbError::UnknownIdentifier => Self::UnknownIdentifier,
            DbError::AlreadyRegistered
            | DbError::CommitmentPreviouslyUsed
            | DbError::Db(_)
            | DbError::Internal(_) => Self::Internal,
        }
    }
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

    /// Registers `identifier` with `commitment`. Never overwrites an existing entry.
    ///
    /// Also records `commitment` as the first entry of the commitment history of `identifier`.
    /// Both inserts happen in a single statement, so of two concurrent registrations for the
    /// same `identifier` only one is stored, and a rejected registration writes nothing.
    ///
    /// Registering `identifier` with its current commitment is a no-op that succeeds, which
    /// makes retries after a lost reply and duplicate submissions safe.
    ///
    /// # Errors
    /// Returns [`DbError::AlreadyRegistered`] if `identifier` is already registered with
    /// another commitment.
    pub(crate) async fn insert_registration(
        &self,
        identifier: SaltedIdentifier,
        commitment: AuthCommitment,
    ) -> Result<(), DbError> {
        let identifier =
            taceo_nodes_common::postgres::to_db_ark_serialize_uncompressed(&identifier);
        let commitment =
            taceo_nodes_common::postgres::to_db_ark_serialize_uncompressed(&commitment);
        let register = || async {
            let inserted = sqlx::query(
                "WITH registration AS (
                    INSERT INTO passport_registrations (salted_identifier, commitment) VALUES ($1, $2)
                    ON CONFLICT (salted_identifier) DO NOTHING
                    RETURNING salted_identifier, commitment
                )
                INSERT INTO commitment_history (salted_identifier, commitment)
                SELECT salted_identifier, commitment FROM registration",
            )
            .bind(identifier.as_slice())
            .bind(commitment.as_slice())
            .execute(&self.pool)
            .await?;
            if inserted.rows_affected() > 0 {
                return Ok(());
            }
            // A separate statement, so it sees a registration committed concurrently with the
            // insert above.
            let current: Option<Vec<u8>> = sqlx::query_scalar(
                "SELECT commitment FROM passport_registrations WHERE salted_identifier = $1",
            )
            .bind(identifier.as_slice())
            .fetch_optional(&self.pool)
            .await?;
            let current = current
                .ok_or_else(|| eyre::eyre!("registration vanished after conflicting insert"))?;
            if current != commitment.as_slice() {
                return Err(DbError::AlreadyRegistered);
            }
            // a retry or duplicate submission of this registration - nothing to do
            tracing::debug!("identifier is already registered with this commitment");
            Ok(())
        };
        self.with_retry("insert_registration", register).await
    }

    /// Replaces the commitment stored for `identifier` and appends it to its commitment history.
    ///
    /// A commitment can be used at most once per `identifier`, which prevents a replayed
    /// rotation from restoring an earlier commitment. Rotating to the current commitment is a
    /// no-op that succeeds, which makes retries and duplicate submissions safe.
    ///
    /// Runs in a transaction that locks the registration of `identifier`, so concurrent
    /// rotations for the same `identifier` are serialized.
    ///
    /// # Errors
    /// Returns [`DbError::UnknownIdentifier`] if no entry exists for `identifier`, and
    /// [`DbError::CommitmentPreviouslyUsed`] if `commitment` was previously stored for `identifier`.
    pub(crate) async fn rotate_commitment(
        &self,
        identifier: SaltedIdentifier,
        commitment: AuthCommitment,
    ) -> Result<(), DbError> {
        let identifier =
            taceo_nodes_common::postgres::to_db_ark_serialize_uncompressed(&identifier);
        let commitment =
            taceo_nodes_common::postgres::to_db_ark_serialize_uncompressed(&commitment);
        let rotate_transaction = || async {
            let mut tx = self.pool.begin().await?;
            let current: Option<Vec<u8>> = sqlx::query_scalar(
                "SELECT commitment FROM passport_registrations WHERE salted_identifier = $1 FOR UPDATE",
            )
            .bind(identifier.as_slice())
            .fetch_optional(&mut *tx)
            .await?;
            let current = current.ok_or(DbError::UnknownIdentifier)?;
            if current == commitment.as_slice() {
                // a retry or duplicate submission of the latest rotation - nothing to do
                tracing::debug!("commitment is already current - nothing to rotate");
                return Ok(());
            }
            let inserted = sqlx::query(
                "INSERT INTO commitment_history (salted_identifier, commitment) VALUES ($1, $2) ON CONFLICT DO NOTHING",
            )
            .bind(identifier.as_slice())
            .bind(commitment.as_slice())
            .execute(&mut *tx)
            .await?;
            if inserted.rows_affected() == 0 {
                return Err(DbError::CommitmentPreviouslyUsed);
            }
            sqlx::query(
                "UPDATE passport_registrations SET commitment = $2 WHERE salted_identifier = $1",
            )
            .bind(identifier.as_slice())
            .bind(commitment.as_slice())
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            Ok(())
        };
        self.with_retry("rotate_commitment", rotate_transaction)
            .await
    }

    /// Fetches the commitment stored for `identifier`.
    ///
    /// # Errors
    /// Returns [`DbError::UnknownIdentifier`] if no entry exists for `identifier`.
    pub(crate) async fn fetch_commitment(
        &self,
        identifier: SaltedIdentifier,
    ) -> Result<AuthCommitment, DbError> {
        let id_bytes = taceo_nodes_common::postgres::to_db_ark_serialize_uncompressed(&identifier);
        self.with_retry("fetch_commitment", || async {
            sqlx::query_scalar(
                "SELECT commitment FROM passport_registrations WHERE salted_identifier = $1",
            )
            .bind(id_bytes.as_slice())
            .fetch_optional(&self.pool)
            .await?
            .map(taceo_nodes_common::postgres::from_db_ark_serialize_uncompressed)
            .transpose()
            .map_err(DbError::from)
        })
        .await
        .context("while fetching commitment")?
        .ok_or_else(|| DbError::UnknownIdentifier)
    }

    /// Runs `f`, retrying it on transient [`DbError::Db`] errors. Domain errors are never retried.
    pub(crate) async fn with_retry<F, Fut, T>(&self, op_name: &str, f: F) -> Result<T, DbError>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<T, DbError>>,
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
fn is_retryable_error(e: &DbError) -> bool {
    match e {
        DbError::Db(err) => match err {
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
        },
        _ => false,
    }
}

#[cfg(test)]
impl ZkPassportDb {
    /// Connects to the shared Postgres test container using a fresh schema.
    ///
    /// Keep the returned handle alive as long as the DB is used.
    pub(crate) async fn init_test() -> eyre::Result<(
        std::sync::Arc<taceo_nodes_common::test_utils::SharedPostgres>,
        Self,
    )> {
        let postgres = taceo_nodes_common::test_utils::shared_postgres_testcontainer().await?;
        let config = PostgresConfig::with_default_values(
            postgres.connection_string.clone().into(),
            taceo_nodes_common::test_utils::next_test_schema(),
        );
        let db = Self::init(&config).await?;
        Ok((postgres, db))
    }
}
