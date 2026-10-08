use std::fmt::Write as _;

use ark_serialize::CanonicalSerialize as _;
use backon::{ExponentialBuilder, Retryable as _};
use reqwest::{StatusCode, Url};
use serde::ser::Error;
use serde::{Deserialize, Serialize, Serializer};
use taceo_oprf::{service::Environment, types::ark_babyjubjub};
use tracing::instrument;
use zkpassport_oprf_authentication::{AuthErrorKind, ZKPassportProofResult};

use crate::config::RetryLayerConfig;

type Result<T> = std::result::Result<T, OracleError>;

#[derive(Debug, thiserror::Error)]
pub(crate) enum OracleError {
    /// Cannot reach oracle
    #[error(transparent)]
    OracleNotReachable(#[from] reqwest::Error),
    /// Oracle returned with BAD REQUEST
    #[error("Bad Request: {0}")]
    BadRequest(String),
    /// Oracle returned a non-success HTTP status
    #[error("Unexpected status code: {status} with body: {body}")]
    UnexpectedStatusCode { status: StatusCode, body: String },
    /// Serde
    #[error(transparent)]
    InvalidMessage(#[from] serde_json::Error),
}

impl From<OracleError> for AuthErrorKind {
    fn from(value: OracleError) -> Self {
        match value {
            OracleError::OracleNotReachable(_) => Self::OracleNotReachable,
            OracleError::BadRequest(reason) => Self::OracleBadRequest(reason),
            OracleError::UnexpectedStatusCode { .. } | OracleError::InvalidMessage(_) => {
                Self::Internal
            }
        }
    }
}

/// Request body sent to the oracle's face-match verification endpoint.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct OracleFaceMatchRequest {
    #[serde(serialize_with = "serialize_point_to_hex")]
    /// The blinded unique identifier (`BabyJubJub` affine point), hex-encoded as `"0x<x><y>"`.
    blinded_unique_identifier: ark_babyjubjub::EdwardsAffine,
    /// The zkPassport proofs submitted by the client.
    proofs: Vec<ZKPassportProofResult>,
}

impl OracleFaceMatchRequest {
    pub(crate) fn new(
        blinded_unique_identifier: ark_babyjubjub::EdwardsAffine,
        proofs: Vec<ZKPassportProofResult>,
    ) -> Self {
        Self {
            blinded_unique_identifier,
            proofs,
        }
    }
}

/// Response body received from the oracle's verification endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct OracleFaceMatchResponse {
    /// Whether the oracle accepted the proofs.
    verified: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Optional error message returned when `verified` is `false`.
    error: Option<String>,
}

const FACE_MATCH_PATH: &str = "verify-oprf-auth";
const PASSPORT_PROOF_PATH: &str = "verify-passport-proof";

/// Full oracle endpoint URLs, derived once from the configured base URL.
#[derive(Debug, Clone)]
struct OracleEndpoints {
    /// `<base>/verify-oprf-auth`, used by v1 face-match authentication.
    face_match: Url,
    /// `<base>/verify-passport-proof`, used by v2 registration and preimage proofs.
    passport_proof: Url,
}

impl OracleEndpoints {
    /// Appends each endpoint path to `base_url`.
    ///
    /// In [`Environment::Dev`] every endpoint gets `?devmode=true`; other environments
    /// get no query. Any query on `base_url` is dropped.
    fn new(mut base_url: Url, environment: Environment) -> eyre::Result<Self> {
        // `Url::join` replaces the last path segment unless the base ends with '/'
        if !base_url.path().ends_with('/') {
            let path = format!("{}/", base_url.path());
            base_url.set_path(&path);
        }
        let endpoint = |path: &str| -> eyre::Result<Url> {
            let mut url = base_url.join(path)?;
            if environment.is_dev() {
                url.set_query(Some("devmode=true"));
            }
            Ok(url)
        };
        Ok(Self {
            face_match: endpoint(FACE_MATCH_PATH)?,
            passport_proof: endpoint(PASSPORT_PROOF_PATH)?,
        })
    }
}

/// HTTP client for all oracle endpoints, with shared retry policy.
#[derive(Debug, Clone)]
pub(crate) struct OracleProxy {
    client: reqwest::Client,
    endpoints: OracleEndpoints,
    backoff: ExponentialBuilder,
}

impl OracleProxy {
    pub(crate) fn init(
        client: reqwest::Client,
        base_url: Url,
        environment: Environment,
        retry_layer: RetryLayerConfig,
    ) -> eyre::Result<Self> {
        Ok(Self {
            client,
            endpoints: OracleEndpoints::new(base_url, environment)?,
            backoff: retry_layer.exponential_backoff(),
        })
    }

    /// First step in the registration process. Verifies that a prover is eligible to obtain a [`SaltedIdentifier`](zkpassport_oprf_authentication::SaltedIdentifier) for a passport `P`.
    ///
    /// Consumed by [`RegisterAuthenticator`](crate::auth_modules::register::RegisterAuthenticator), which then evaluates the OPRF under the global registration key `OPRF_reg`.
    ///
    /// # Notation
    ///
    /// Shared by all proof statements on this type:
    ///
    /// - `P`: the passport hash.
    /// - `OPRF_reg`: the global registration OPRF key.
    /// - `I = OPRF(P, OPRF_reg)`: the [`SaltedIdentifier`](zkpassport_oprf_authentication::SaltedIdentifier),
    ///   the stable `BabyJubJub` point obtained by unblinding the registration response. It is
    ///   independent of the blinding factor.
    /// - `x`, `x'`: the user's secret and its commitment, the [`AuthCommitment`](zkpassport_oprf_authentication::AuthCommitment).
    /// - `y`, `y'`: the replacement secret and commitment after a rotation.
    ///
    /// # Proof Statement
    ///
    /// The proof consists of the following statements:
    ///
    /// §1 - Ownership of passport `P`
    ///
    /// The ordinary zkPassport statement: the prover holds a valid government-issued document `P`.
    ///
    /// §2 - The OPRF request is a blinding of `P`
    ///
    /// Binds the blinded OPRF request to the passport in §1 using a nonzero blinding factor,
    /// so an OPRF evaluation can only be requested for a passport the prover owns.
    ///
    /// # Notes
    ///
    /// No `nonce`, `challenge`, or `timestamp` is added. Replaying the proof with the same request
    /// only recomputes the blinded response. The client unblinds it to recover the same public `I`;
    /// replay reveals nothing about `P`.
    #[instrument(level = "debug", skip_all)]
    pub(crate) async fn salted_identifier(&self) -> Result<()> {
        tracing::trace!(
            "sending verify request to oracle: {}",
            self.endpoints.passport_proof
        );
        Ok(())
    }

    /// Second proof of the registration process. Attests that the public `I` was computed correctly for passport `P` and that the prover knows the secret behind the submitted commitment `x'`.
    ///
    /// Notation as in [`Self::salted_identifier`].
    ///
    /// # Proof Statement
    ///
    /// The proof consists of the following statements:
    ///
    /// §1 - Ownership of passport `P`
    ///
    /// The ordinary zkPassport statement: the prover holds a valid government-issued document `P`.
    ///
    /// §2 - Correct computation of `I`
    ///
    /// The public input `I` satisfies `I = OPRF(P, OPRF_reg)`. The enclosing ZK proof MUST establish
    /// all of the following:
    ///
    /// - The registration request is a blinding of the passport hash `P` from §1 using a nonzero
    ///   blinding factor known to the prover.
    /// - The Chaum-Pedersen discrete-logarithm-equality proof returned by the registration OPRF
    ///   verifies against the trusted public key for `OPRF_reg`, authenticating that blinded
    ///   request/response pair.
    /// - Unblinding that response with the same blinding factor yields the public input `I`.
    ///
    /// §3 - `I` and `P` have the same root passport
    ///
    /// §1 and §2 refer to the same `P`. Implied by the statements above, stated explicitly for clarity.
    ///
    /// §4 - Knowledge of the preimage of `x'`
    ///
    /// The prover knows `x` with `x' = commit(x)`. Binds the commitment to the proof, so a replayed proof cannot register a different commitment `x̂` under the prover's `I`.
    ///
    /// # Notes
    ///
    /// No `nonce`, `challenge`, or `timestamp` is added. Nodes MUST reject a registration if a commitment for `I` is already stored, so a replay is a no-op.
    #[instrument(level = "debug", skip_all)]
    #[expect(dead_code, reason = "is just a stub")]
    pub(crate) async fn registration_commitment(&self) -> Result<()> {
        tracing::trace!(
            "sending verify request to oracle: {}",
            self.endpoints.passport_proof
        );
        Ok(())
    }

    /// Verifies the query proof used to compute a salted nullifier. The salted nullifier is an opaque per-consumer identifier that provides sybil resistance within the zkPassport ecosystem.
    ///
    /// Consumed by the query authentication module, which then evaluates the OPRF under the consumer's nullifier key.
    ///
    /// Notation as in [`Self::salted_identifier`].
    ///
    /// # Proof Statement
    ///
    /// The proof consists of the following statements:
    ///
    /// §1 - Ownership of passport `P`
    ///
    /// The ordinary zkPassport statement: the prover holds a valid government-issued document with hash `P`.
    ///
    /// §2 - Correct computation of `I`
    ///
    /// The public input `I` satisfies `I = OPRF(P, OPRF_reg)` using the full derivation statement
    /// in §2 of [`Self::registration_commitment`], including registration request binding,
    /// Chaum-Pedersen verification against the trusted registration public key, and response unblinding.
    ///
    /// §3 - The OPRF request is a blinding of `P`
    ///
    /// Binds the blinded OPRF request to §1, so an OPRF evaluation can only be requested for a passport the prover owns.
    ///
    /// §4 - `I`, `P`, and the blinded OPRF request have the same root passport
    ///
    /// §1, §2, and §3 refer to the same `P`. Implied by the statements above, stated explicitly for clarity.
    ///
    /// §5 - Knowledge of the preimage of `x'`
    ///
    /// The prover knows `x` with `x' = commit(x)` for the public input `x'`.
    ///
    /// # Notes
    ///
    /// The proof alone does not establish that `x'` is currently registered for `I`. Before
    /// authorizing the OPRF evaluation, nodes MUST look up the proof's public input `I`, reject
    /// unknown identifiers, and require the proof's public input `x'` to equal the commitment
    /// currently stored for `I`. This rejects both arbitrary commitments and previous commitments
    /// superseded by rotation.
    ///
    /// Verifiers MUST enforce that the requested OPRF key is NOT `OPRF_reg`. The registration OPRF key MUST only be used for computing identifiers.
    ///
    /// No `nonce`, `challenge`, or `timestamp` is needed. A byte-for-byte replay is accepted only
    /// while `x'` still matches the currently stored commitment for `I`. It only makes the nodes
    /// recompute the same blinded response, from which the client can recover the same salted
    /// nullifier. The nullifier is public and one-way, so nothing is gained.
    ///
    /// The zkPassport circuit takes a `current_date` for PKI-chain verification. Nodes may additionally check that it lies within a reasonable window.
    #[instrument(level = "debug", skip_all)]
    #[expect(dead_code, reason = "is just a stub")]
    pub(crate) async fn preimage_proof(&self) -> Result<()> {
        tracing::trace!(
            "sending verify request to oracle: {}",
            self.endpoints.passport_proof
        );
        Ok(())
    }

    /// Verifies the proof that rotates the [`AuthCommitment`](zkpassport_oprf_authentication::AuthCommitment) stored for a [`SaltedIdentifier`](zkpassport_oprf_authentication::SaltedIdentifier) from `x'` to a new commitment `y'`.
    ///
    /// Rotation is the fallback for a lost secret or a front-run registration. Notation as in [`Self::salted_identifier`].
    ///
    /// # Proof Statement
    ///
    /// The proof consists of the following statements:
    ///
    /// §1 - Ownership of passport `P`
    ///
    /// The ordinary zkPassport statement: the prover holds a valid government-issued document with hash `P`.
    ///
    /// §2 - Correct computation of `I`
    ///
    /// The public input `I` satisfies `I = OPRF(P, OPRF_reg)` using the full derivation statement
    /// in §2 of [`Self::registration_commitment`], including registration request binding,
    /// Chaum-Pedersen verification against the trusted registration public key, and response unblinding.
    ///
    /// §3 - `I` and `P` have the same root passport
    ///
    /// §1 and §2 refer to the same `P`. Implied by the statements above, stated explicitly for clarity.
    ///
    /// §4 - Face match against `P`
    ///
    /// The face-match proof from the `v1` flow, attesting that the user performed a face match against the picture on `P`. It must bind to the same `P` as `I`. A government cannot forge it, which is what makes rotation safe against front-running.
    ///
    /// §5 - Knowledge of the preimage of `y'`
    ///
    /// The prover knows `y` with `y' = commit(y)`. Binds the new commitment to the proof, so a replayed proof cannot rotate to a different commitment.
    ///
    /// # Notes
    ///
    /// Nodes MUST check that `I` is registered before updating the mapping.
    ///
    /// Unlike [`Self::preimage_proof`], a `nonce` or `timestamp` may be desirable. Otherwise a replay could rotate the mapping back to a commitment whose secret the user has lost, locking them out. The commitment itself may serve as nonce: nodes could persist the history of commitments per `I` and reject any `y'` seen before. This also leaves an audit trail of rotations.
    #[instrument(level = "debug", skip_all)]
    pub(crate) async fn identifier_registration(&self) -> Result<()> {
        tracing::trace!(
            "sending verify request to oracle: {}",
            self.endpoints.passport_proof
        );
        Ok(())
    }

    #[instrument(level = "debug", skip_all)]
    pub(crate) async fn secret_rotation(&self) -> Result<()> {
        tracing::trace!(
            "sending verify request to oracle: {}",
            self.endpoints.passport_proof
        );
        Ok(())
    }

    #[instrument(level = "debug", skip_all)]
    pub(crate) async fn v1_face_match(&self, request: &OracleFaceMatchRequest) -> Result<()> {
        tracing::trace!(
            "sending verify request to oracle: {}",
            self.endpoints.face_match
        );
        self.with_retry("face_match", || async {
            let response = self
                .client
                .post(self.endpoints.face_match.clone())
                .json(request)
                .send()
                .await?;
            let status = response.status();
            if status == StatusCode::OK {
                tracing::trace!("oracle verified proofs successfully");
                Ok(())
            } else if status == StatusCode::BAD_REQUEST {
                tracing::trace!("received BAD REQUEST from oracle");
                let body = response.text().await?;
                let error_msg = match serde_json::from_str::<OracleFaceMatchResponse>(&body) {
                    Ok(response) => response.error.unwrap_or_else(|| "unknown".to_owned()),
                    Err(err) => {
                        tracing::error!(%err,"could not parse oracle verify response: {err}");
                        "unknown".to_owned()
                    }
                };

                Err(OracleError::BadRequest(error_msg))
            } else {
                tracing::trace!("unknown status code: {status}");
                let body = response.text().await?;
                Err(OracleError::UnexpectedStatusCode { status, body })
            }
        })
        .await
    }

    pub(crate) async fn with_retry<F, Fut, T>(&self, op_name: &str, f: F) -> Result<T>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        f.retry(self.backoff)
            .sleep(tokio::time::sleep)
            .when(is_retryable_error)
            .notify(|err, duration| {
                tracing::warn!(%err, retry_in = ?duration, "retrying {op_name} request to oracle");
            })
            .await
    }
}

/// Serialize a `BabyJubJub` affine point to a `"0x<x><y>"` hex string.
///
/// Coordinates are serialized in big-endian byte order to match the circuit's
/// public output format. `ark-serialize` returns little-endian bytes, so both
/// coordinate byte vectors are reversed before encoding.
fn serialize_point_to_hex<S: Serializer>(
    point: &ark_babyjubjub::EdwardsAffine,
    ser: S,
) -> std::result::Result<S::Ok, S::Error> {
    // Serialize x and y coordinates in big-endian to match the circuit's public output format
    // `blinded_query` in circuit returns (x, y) as Field elements which are big-endian
    let mut x_bytes = Vec::new();
    point
        .x
        .serialize_compressed(&mut x_bytes)
        .map_err(S::Error::custom)?;

    x_bytes.reverse(); // ark serializes in little-endian, circuit outputs are big-endian

    let mut y_bytes = Vec::new();
    point
        .y
        .serialize_compressed(&mut y_bytes)
        .map_err(S::Error::custom)?;
    y_bytes.reverse();

    let mut hex_x = String::with_capacity(x_bytes.len() * 2);
    for b in &x_bytes {
        write!(&mut hex_x, "{b:02x}").expect("Write to a string should never panic");
    }

    let mut hex_y = String::with_capacity(y_bytes.len() * 2);
    for b in &y_bytes {
        write!(&mut hex_y, "{b:02x}").expect("Write to a string should never panic");
    }
    ser.serialize_str(&format!("0x{hex_x}{hex_y}"))
}

fn is_retryable_error(e: &OracleError) -> bool {
    // Transport-level failures: no usable response came back.
    //
    // HTTP status failures worth retrying:
    // * 408 REQUEST TIMEOUT
    // * 429 TOO MANY REQUESTS
    // * 502 BAD GATEWAY
    // * 503 SERVICE UNAVAILABLE
    // * 504 GATEWAY TIMEOUT
    //
    // we do not retry INTERNAL SERVER ERROR
    match e {
        OracleError::OracleNotReachable(error) => error.is_connect(),
        OracleError::UnexpectedStatusCode { status, .. } => matches!(
            *status,
            StatusCode::REQUEST_TIMEOUT
                | StatusCode::TOO_MANY_REQUESTS
                | StatusCode::BAD_GATEWAY
                | StatusCode::SERVICE_UNAVAILABLE
                | StatusCode::GATEWAY_TIMEOUT
        ),
        OracleError::BadRequest(_) | OracleError::InvalidMessage(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_from_base_url() -> eyre::Result<()> {
        for base in ["http://oracle:8080/api", "http://oracle:8080/api/"] {
            let endpoints = OracleEndpoints::new(base.parse()?, Environment::Dev)?;
            assert_eq!(
                endpoints.face_match.as_str(),
                "http://oracle:8080/api/verify-oprf-auth?devmode=true"
            );
        }
        for environment in [Environment::Test, Environment::Prod] {
            let endpoints = OracleEndpoints::new("http://oracle:8080".parse()?, environment)?;
            assert_eq!(
                endpoints.face_match.as_str(),
                "http://oracle:8080/verify-oprf-auth"
            );
        }
        Ok(())
    }
}
