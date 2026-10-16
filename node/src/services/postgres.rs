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
                "INSERT INTO commitment_history (salted_identifier, commitment) VALUES ($1, $2) ON CONFLICT (salted_identifier, commitment) DO NOTHING",
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
        .await?
        .ok_or(DbError::UnknownIdentifier)
    }

    /// Runs `f`, retrying it on transient [`DbError::Db`] errors. Domain errors are never retried.
    async fn with_retry<F, Fut, T>(&self, op_name: &str, f: F) -> Result<T, DbError>
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
mod tests {
    use taceo_nodes_common::postgres::PostgresConfig;
    use taceo_oprf::{core::oprf::BlindingFactor, types::ark_babyjubjub};
    use zkpassport_oprf_authentication::{AuthCommitment, SaltedIdentifier};

    use super::{DbError, ZkPassportDb, is_retryable_error};

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

        /// Closes the pool, so every later query fails with a non-retryable DB error.
        pub(crate) async fn close_test(&self) {
            self.pool.close().await;
        }
    }

    fn identifier(n: u64) -> SaltedIdentifier {
        let blinding_factor = BlindingFactor::from_scalar(ark_babyjubjub::Fr::from(7u64))
            .expect("Invalid blinding factor");
        let point = taceo_oprf::core::oprf::client::blind_query(
            ark_babyjubjub::Fq::from(n),
            blinding_factor,
        )
        .blinded_query();
        SaltedIdentifier::from(point)
    }

    fn commitment(n: u64) -> AuthCommitment {
        AuthCommitment::from(ark_babyjubjub::Fq::from(n))
    }

    /// All commitments in the history of `id`, sorted.
    async fn history(db: &ZkPassportDb, id: SaltedIdentifier) -> Vec<AuthCommitment> {
        let id = taceo_nodes_common::postgres::to_db_ark_serialize_uncompressed(&id);
        let rows: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT commitment FROM commitment_history WHERE salted_identifier = $1 ORDER BY commitment",
        )
        .bind(id.as_slice())
        .fetch_all(&db.pool)
        .await
        .expect("history query");
        rows.into_iter()
            .map(|b| {
                taceo_nodes_common::postgres::from_db_ark_serialize_uncompressed(b)
                    .expect("valid commitment")
            })
            .collect()
    }

    fn sorted(mut v: Vec<AuthCommitment>) -> Vec<AuthCommitment> {
        let key = |c: &AuthCommitment| {
            taceo_nodes_common::postgres::to_db_ark_serialize_uncompressed(c).to_vec()
        };
        v.sort_by_key(key);
        v
    }

    #[tokio::test]
    async fn register_and_fetch() -> eyre::Result<()> {
        let (_pg, db) = ZkPassportDb::init_test().await?;
        let (id, c1) = (identifier(1), commitment(1));
        db.insert_registration(id, c1).await?;
        assert_eq!(db.fetch_commitment(id).await?, c1);
        assert_eq!(history(&db, id).await, vec![c1]);
        Ok(())
    }

    #[tokio::test]
    async fn fetch_unknown() -> eyre::Result<()> {
        let (_pg, db) = ZkPassportDb::init_test().await?;
        let err = db
            .fetch_commitment(identifier(1))
            .await
            .expect_err("should fail");
        assert!(matches!(err, DbError::UnknownIdentifier));
        Ok(())
    }

    #[tokio::test]
    async fn register_same_commitment_is_idempotent() -> eyre::Result<()> {
        let (_pg, db) = ZkPassportDb::init_test().await?;
        let (id, c1) = (identifier(1), commitment(1));
        db.insert_registration(id, c1).await?;
        db.insert_registration(id, c1).await?;
        assert_eq!(history(&db, id).await, vec![c1]);
        Ok(())
    }

    #[tokio::test]
    async fn register_other_commitment_rejected() -> eyre::Result<()> {
        let (_pg, db) = ZkPassportDb::init_test().await?;
        let (id, c1) = (identifier(1), commitment(1));
        db.insert_registration(id, c1).await?;
        let err = db
            .insert_registration(id, commitment(2))
            .await
            .expect_err("should fail");
        assert!(matches!(err, DbError::AlreadyRegistered));
        assert_eq!(db.fetch_commitment(id).await?, c1);
        assert_eq!(history(&db, id).await, vec![c1]);
        Ok(())
    }

    #[tokio::test]
    async fn rotate_unknown() -> eyre::Result<()> {
        let (_pg, db) = ZkPassportDb::init_test().await?;
        let id = identifier(1);
        let err = db
            .rotate_commitment(id, commitment(1))
            .await
            .expect_err("should fail");
        assert!(matches!(err, DbError::UnknownIdentifier));
        assert_eq!(history(&db, id).await.len(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn rotate_updates_current_and_history() -> eyre::Result<()> {
        let (_pg, db) = ZkPassportDb::init_test().await?;
        let (id, c1, c2) = (identifier(1), commitment(1), commitment(2));
        db.insert_registration(id, c1).await?;
        db.rotate_commitment(id, c2).await?;
        assert_eq!(db.fetch_commitment(id).await?, c2);
        assert_eq!(history(&db, id).await, sorted(vec![c1, c2]));
        // rotating to the current commitment is a no-op
        db.rotate_commitment(id, c2).await?;
        assert_eq!(history(&db, id).await, sorted(vec![c1, c2]));
        Ok(())
    }

    #[tokio::test]
    async fn rotate_to_previous_commitment_rejected() -> eyre::Result<()> {
        let (_pg, db) = ZkPassportDb::init_test().await?;
        let (id, c1, c2) = (identifier(1), commitment(1), commitment(2));
        db.insert_registration(id, c1).await?;
        db.rotate_commitment(id, c2).await?;
        let err = db.rotate_commitment(id, c1).await.expect_err("should fail");
        assert!(matches!(err, DbError::CommitmentPreviouslyUsed));
        assert_eq!(db.fetch_commitment(id).await?, c2);
        Ok(())
    }

    #[tokio::test]
    async fn commitment_reuse_across_identifiers_allowed() -> eyre::Result<()> {
        let (_pg, db) = ZkPassportDb::init_test().await?;
        let (a, b, c1, c2) = (identifier(1), identifier(2), commitment(1), commitment(2));
        db.insert_registration(a, c1).await?;
        db.insert_registration(b, c1).await?;
        db.rotate_commitment(a, c2).await?;
        db.rotate_commitment(b, c2).await?;
        assert_eq!(db.fetch_commitment(a).await?, c2);
        assert_eq!(db.fetch_commitment(b).await?, c2);
        Ok(())
    }

    #[tokio::test]
    async fn concurrent_registrations_store_exactly_one() -> eyre::Result<()> {
        let (_pg, db) = ZkPassportDb::init_test().await?;
        let id = identifier(1);
        let handles: Vec<_> = (1..=8u64)
            .map(|n| {
                let db = db.clone();
                tokio::spawn(async move { db.insert_registration(id, commitment(n)).await })
            })
            .collect();
        let mut ok = 0;
        for h in handles {
            match h.await? {
                Ok(()) => ok += 1,
                Err(e) => assert!(matches!(e, DbError::AlreadyRegistered)),
            }
        }
        assert_eq!(ok, 1);
        let winner = db.fetch_commitment(id).await?;
        assert_eq!(history(&db, id).await, vec![winner]);
        Ok(())
    }

    #[tokio::test]
    async fn concurrent_rotations_are_serialized() -> eyre::Result<()> {
        let (_pg, db) = ZkPassportDb::init_test().await?;
        let id = identifier(1);
        db.insert_registration(id, commitment(0)).await?;
        let handles: Vec<_> = (1..=8u64)
            .map(|n| {
                let db = db.clone();
                tokio::spawn(async move { db.rotate_commitment(id, commitment(n)).await })
            })
            .collect();
        for h in handles {
            h.await??;
        }
        let all: Vec<_> = (0..=8u64).map(commitment).collect();
        assert_eq!(history(&db, id).await, sorted(all.clone()));
        assert!(all.contains(&db.fetch_commitment(id).await?));
        Ok(())
    }

    #[tokio::test]
    async fn concurrent_identical_registrations_all_succeed() -> eyre::Result<()> {
        let (_pg, db) = ZkPassportDb::init_test().await?;
        let (id, c1) = (identifier(1), commitment(1));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let db = db.clone();
                tokio::spawn(async move { db.insert_registration(id, c1).await })
            })
            .collect();
        for h in handles {
            h.await??;
        }
        assert_eq!(db.fetch_commitment(id).await?, c1);
        assert_eq!(history(&db, id).await, vec![c1]);
        Ok(())
    }

    #[tokio::test]
    async fn concurrent_identical_rotations_all_succeed() -> eyre::Result<()> {
        let (_pg, db) = ZkPassportDb::init_test().await?;
        let (id, c1, c2) = (identifier(1), commitment(1), commitment(2));
        db.insert_registration(id, c1).await?;
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let db = db.clone();
                tokio::spawn(async move { db.rotate_commitment(id, c2).await })
            })
            .collect();
        for h in handles {
            h.await??;
        }
        assert_eq!(db.fetch_commitment(id).await?, c2);
        assert_eq!(history(&db, id).await, sorted(vec![c1, c2]));
        Ok(())
    }

    #[tokio::test]
    async fn registration_replay_after_rotation_rejected() -> eyre::Result<()> {
        let (_pg, db) = ZkPassportDb::init_test().await?;
        let (id, c1, c2) = (identifier(1), commitment(1), commitment(2));
        db.insert_registration(id, c1).await?;
        db.rotate_commitment(id, c2).await?;
        let err = db
            .insert_registration(id, c1)
            .await
            .expect_err("should fail");
        assert!(matches!(err, DbError::AlreadyRegistered));
        assert_eq!(db.fetch_commitment(id).await?, c2);
        assert_eq!(history(&db, id).await, sorted(vec![c1, c2]));
        Ok(())
    }

    #[test]
    fn retryable_errors() {
        assert!(is_retryable_error(&DbError::Db(sqlx::Error::PoolTimedOut)));
        assert!(!is_retryable_error(&DbError::Db(sqlx::Error::RowNotFound)));
        assert!(!is_retryable_error(&DbError::UnknownIdentifier));
        assert!(!is_retryable_error(&DbError::AlreadyRegistered));
        assert!(!is_retryable_error(&DbError::CommitmentPreviouslyUsed));
    }
}
