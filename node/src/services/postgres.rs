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
    #[error("internal error: {0:?}")]
    Internal(#[from] eyre::Report),
}

impl DbError {
    pub(crate) fn log(&self) {
        match self {
            DbError::UnknownIdentifier | DbError::AlreadyRegistered => {
                tracing::warn!(err=?self, auth_error = true, "{self}");
            }
            DbError::Internal(report) => tracing::error!(err=?report, "internal DB error"),
        }
    }
}

impl From<DbError> for AuthErrorKind {
    fn from(value: DbError) -> Self {
        match value {
            DbError::UnknownIdentifier => Self::UnknownIdentifier,
            DbError::AlreadyRegistered | DbError::Internal(_) => Self::Internal,
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
    /// The insert is atomic, so of two concurrent registrations for the same `identifier`
    /// only one is stored.
    ///
    /// Not retried: a retry after a lost reply would find the row it just inserted and
    /// reject the client's own registration.
    ///
    /// # Errors
    /// Returns [`DbError::AlreadyRegistered`] if `identifier` is already registered.
    pub(crate) async fn insert_registration(
        &self,
        identifier: SaltedIdentifier,
        commitment: AuthCommitment,
    ) -> Result<(), DbError> {
        let result = sqlx::query(
            "INSERT INTO passport_registrations (salted_identifier, commitment) VALUES ($1, $2) ON CONFLICT (salted_identifier) DO NOTHING",
        )
        .bind(taceo_nodes_common::postgres::to_db_ark_serialize_uncompressed(&identifier).as_slice())
        .bind(taceo_nodes_common::postgres::to_db_ark_serialize_uncompressed(&commitment).as_slice())
        .execute(&self.pool)
        .await
        .context("while inserting registration")?;
        if result.rows_affected() == 0 {
            return Err(DbError::AlreadyRegistered);
        }
        Ok(())
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
                    "UPDATE passport_registrations SET commitment = $2 WHERE salted_identifier = $1",
                )
                .bind(
                    taceo_nodes_common::postgres::to_db_ark_serialize_uncompressed(&identifier)
                        .as_slice(),
                )
                .bind(
                    taceo_nodes_common::postgres::to_db_ark_serialize_uncompressed(&commitment)
                        .as_slice(),
                )
                .execute(&self.pool)
            })
            .await
            .context("while rotating commitment")?;
        if result.rows_affected() == 0 {
            return Err(DbError::UnknownIdentifier);
        }
        Ok(())
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
        })
        .await
        .context("while fetching commitment")?
        .ok_or_else(|| DbError::UnknownIdentifier)
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
