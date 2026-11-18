use std::{
    collections::HashMap,
    fmt::Write as _,
    num::NonZeroU16,
    sync::{Arc, Mutex},
};

use ark_ec::{AffineRepr as _, CurveGroup as _};
use ark_ff::{BigInteger as _, PrimeField as _};
use axum::{
    Json, Router,
    extract::State,
    http::{StatusCode, Uri},
};
use ruint::aliases::U160;
use serde::Serialize;
use serde_json::json;
use taceo_nodes_common::{
    postgres::PostgresConfig,
    test_utils::{
        SharedPostgres, axum_test::TestServer, next_test_schema, shared_postgres_testcontainer,
        test_server,
    },
};
use taceo_oprf::{
    client::{Connector, Error, ServiceError, VerifiableOprfOutput},
    core::{ddlog_equality::shamir::DLogShareShamir, oprf::BlindingFactor},
    service::{
        Environment,
        config::OprfNodeServiceConfig,
        secret_manager::{SecretManager, SecretManagerError},
    },
    types::{
        OprfKeyId, ShareEpoch,
        ark_babyjubjub::{EdwardsAffine, Fq, Fr},
        async_trait::async_trait,
        crypto::{OprfKeyMaterial, OprfPublicKey, PartyId},
        service::NodeInformation,
    },
};
use taceo_zkpassport_oprf_node::{ProofVerifierOracle, ZkPassportDb, config::RetryLayerConfig};
use zkpassport_oprf_authentication::{
    AuthCommitment, AuthModules, CommitmentRotationRequest, FaceMatchRequestAuth,
    IdentifyRequestAuth, NullifierRequestAuth, RegistrationRequest, SaltedIdentifier,
    ZKPassportProofResult, registration_oprf_key_id,
};

/// The private nullifier `pn` of the test passport.
pub(crate) const PN: u64 = 1;

/// Max websocket message size of the node, large enough for the fixture proofs.
const WS_MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/// Blinding factor of every OPRF request; no assertion depends on its value.
const BETA: u64 = 3;

/// An OPRF node with the users DB and the HTTP oracle of the binary, and its keys in memory.
///
/// The node is its own threshold, so a single one serves complete OPRF evaluations.
pub(crate) struct TestNode {
    url: String,
    pub(crate) verifier: FakeVerifier,
    http: reqwest::Client,
    _server: TestServer,
    _verifier_server: Option<TestServer>,
    _pg: Arc<SharedPostgres>,
}

impl TestNode {
    /// Starts a node whose proof-verifier accepts every proof.
    pub(crate) async fn start() -> eyre::Result<Self> {
        let verifier = FakeVerifier::new();
        let (verifier_server, verifier_url) = test_server(verifier.router());
        Self::start_with_verifier(verifier, Some(verifier_server), &verifier_url).await
    }

    /// Starts a node whose proof-verifier is down.
    pub(crate) async fn start_with_verifier_down() -> eyre::Result<Self> {
        // Port 1 on loopback is never open, so connecting fails immediately.
        Self::start_with_verifier(FakeVerifier::new(), None, "http://127.0.0.1:1").await
    }

    async fn start_with_verifier(
        verifier: FakeVerifier,
        verifier_server: Option<TestServer>,
        verifier_url: &str,
    ) -> eyre::Result<Self> {
        let pg = shared_postgres_testcontainer().await?;
        let db = ZkPassportDb::init(&PostgresConfig::with_default_values(
            pg.connection_string.clone().into(),
            next_test_schema(),
        ))
        .await?;
        let node_information =
            NodeInformation::new(PartyId(0), "node-0".to_owned(), NonZeroU16::MIN);
        let secret_manager = InMemorySecretManager {
            node_information: node_information.clone(),
            keys: HashMap::from([
                (registration_oprf_key_id(), key_material(Fr::from(11u64))),
                (customer_key_id(), key_material(Fr::from(12u64))),
            ]),
        };

        let mut retry = RetryLayerConfig::default();
        retry.verifier_request_max_attempts = 0;
        let oracle = ProofVerifierOracle::init(
            reqwest::Client::new(),
            verifier_url.parse()?,
            Environment::Dev,
            retry,
        )?;

        let mut config = OprfNodeServiceConfig::with_default_values(
            Environment::Dev,
            taceo_oprf::client::VERSION.parse()?,
        );
        // the default is far below the size of real proofs
        config.ws_max_message_size = WS_MAX_MESSAGE_SIZE;
        let router = taceo_zkpassport_oprf_node::start(
            config,
            Arc::new(oracle),
            Arc::new(secret_manager),
            db,
            &node_information,
            "test".to_owned(),
        );
        let (server, url) = test_server(router);
        Ok(Self {
            url,
            verifier,
            http: reqwest::Client::new(),
            _server: server,
            _verifier_server: verifier_server,
            _pg: pg,
        })
    }

    async fn oprf<Auth: Clone + Serialize + 'static>(
        &self,
        module: AuthModules,
        query: u64,
        auth: Auth,
    ) -> Result<VerifiableOprfOutput, Error> {
        let uris = taceo_oprf::client::to_oprf_uri_many(std::slice::from_ref(&self.url), module)
            .expect("valid URIs");
        let blinding_factor =
            BlindingFactor::from_scalar(Fr::from(BETA)).expect("non-zero blinding factor");
        taceo_oprf::client::distributed_oprf(
            &uris,
            1,
            Fq::from(query),
            blinding_factor,
            Fq::from(0u64),
            auth,
            Connector::Plain,
        )
        .await
    }

    /// First registration step: evaluates `pn` under the registration key.
    pub(crate) async fn identify_oprf(&self, pn: u64) -> Result<VerifiableOprfOutput, Error> {
        self.oprf(
            AuthModules::Identify,
            pn,
            IdentifyRequestAuth::new(proofs()),
        )
        .await
    }

    /// Requests the nullifier of `pn` under `oprf_key_id`, authenticated with `I`.
    pub(crate) async fn nullifier_oprf(
        &self,
        pn: u64,
        oprf_key_id: OprfKeyId,
        salted_identifier: SaltedIdentifier,
    ) -> Result<VerifiableOprfOutput, Error> {
        let auth = NullifierRequestAuth {
            oprf_key_id,
            salted_identifier,
            proofs: proofs(),
        };
        self.oprf(AuthModules::Nullifier, pn, auth).await
    }

    /// Requests the evaluation of `query` under `oprf_key_id`, authenticated with face-match proofs.
    pub(crate) async fn face_match_oprf(
        &self,
        query: u64,
        oprf_key_id: OprfKeyId,
    ) -> Result<VerifiableOprfOutput, Error> {
        let auth = FaceMatchRequestAuth::new(oprf_key_id, proofs());
        self.oprf(AuthModules::FaceMatch, query, auth).await
    }

    async fn post(&self, path: &str, body: &impl Serialize) -> eyre::Result<StatusCode> {
        let response = self
            .http
            .post(format!("{}/api/{path}", self.url))
            .json(body)
            .send()
            .await?;
        Ok(response.status())
    }

    /// Second registration step: stores `I` -> `commitment`.
    pub(crate) async fn post_registration(
        &self,
        salted_identifier: SaltedIdentifier,
        commitment: AuthCommitment,
    ) -> eyre::Result<StatusCode> {
        let request = RegistrationRequest {
            salted_identifier,
            commitment,
            proofs: proofs(),
        };
        self.post("registration", &request).await
    }

    pub(crate) async fn post_rotation(
        &self,
        salted_identifier: SaltedIdentifier,
        new_commitment: AuthCommitment,
    ) -> eyre::Result<StatusCode> {
        let request = CommitmentRotationRequest {
            salted_identifier,
            new_commitment,
            proofs: proofs(),
        };
        self.post("rotation", &request).await
    }
}

/// [`SecretManager`] serving fixed key material from memory.
struct InMemorySecretManager {
    node_information: NodeInformation,
    keys: HashMap<OprfKeyId, OprfKeyMaterial>,
}

#[async_trait]
impl SecretManager for InMemorySecretManager {
    async fn load_node_information(&self) -> eyre::Result<NodeInformation> {
        Ok(self.node_information.clone())
    }

    async fn get_oprf_key_material(
        &self,
        oprf_key_id: OprfKeyId,
    ) -> Result<OprfKeyMaterial, SecretManagerError> {
        self.keys
            .get(&oprf_key_id)
            .cloned()
            .ok_or(SecretManagerError::UnknownOprfKeyId(oprf_key_id))
    }
}

/// With a threshold of one, the node's share is the secret itself.
fn key_material(secret: Fr) -> OprfKeyMaterial {
    let public_key = OprfPublicKey::new((EdwardsAffine::generator() * secret).into_affine());
    OprfKeyMaterial::new(
        DLogShareShamir::from(secret),
        public_key,
        ShareEpoch::default(),
    )
}

/// Stand-in for the zkPassport proof-verifier.
///
/// Answers every request with the configured response and records what it received.
#[derive(Clone)]
pub(crate) struct FakeVerifier {
    response: Arc<Mutex<(StatusCode, serde_json::Value)>>,
    requests: Arc<Mutex<Vec<(String, serde_json::Value)>>>,
}

impl FakeVerifier {
    fn new() -> Self {
        Self {
            response: Arc::new(Mutex::new((StatusCode::OK, json!({ "verified": true })))),
            requests: Arc::default(),
        }
    }

    fn router(&self) -> Router {
        Router::new()
            .fallback(
                |State(verifier): State<Self>, uri: Uri, Json(body): Json<serde_json::Value>| async move {
                    verifier
                        .requests
                        .lock()
                        .expect("not poisoned")
                        .push((uri.path().to_owned(), body));
                    let (status, body) = verifier.response.lock().expect("not poisoned").clone();
                    (status, Json(body))
                },
            )
            .with_state(self.clone())
    }

    /// Answers subsequent requests with `status` and `body`.
    pub(crate) fn respond(&self, status: StatusCode, body: serde_json::Value) {
        *self.response.lock().expect("not poisoned") = (status, body);
    }

    /// Accepts the proofs of subsequent requests.
    pub(crate) fn accept(&self) {
        self.respond(StatusCode::OK, json!({ "verified": true }));
    }

    /// Rejects the proofs of subsequent requests with `reason`.
    pub(crate) fn reject(&self, reason: &str) {
        self.respond(
            StatusCode::BAD_REQUEST,
            json!({ "verified": false, "error": reason }),
        );
    }

    /// Returns the path and body of the requests received since the last call, in order.
    pub(crate) fn take_requests(&self) -> Vec<(String, serde_json::Value)> {
        std::mem::take(&mut *self.requests.lock().expect("not poisoned"))
    }
}

/// OPRF key of a zkPassport customer, held by the node next to the registration key.
pub(crate) fn customer_key_id() -> OprfKeyId {
    OprfKeyId::new(U160::from(42))
}

pub(crate) fn commitment(n: u64) -> AuthCommitment {
    AuthCommitment::from(Fq::from(n))
}

/// The proofs every request carries.
pub(crate) fn proofs() -> Vec<ZKPassportProofResult> {
    zkpassport_oprf_test_utils::fixtures::load_fixture_data().proofs
}

/// The oracle's encoding of a point: `"0x<x><y>"`, both coordinates big-endian.
pub(crate) fn hex_point(point: EdwardsAffine) -> String {
    let mut hex = String::from("0x");
    for coordinate in [point.x, point.y] {
        for byte in coordinate.into_bigint().to_bytes_be() {
            write!(hex, "{byte:02x}").expect("writing to a string cannot fail");
        }
    }
    hex
}

/// Returns the error the node rejected the request with.
pub(crate) fn service_error(result: Result<VerifiableOprfOutput, Error>) -> ServiceError {
    match result {
        Err(Error::ThresholdServiceError(err)) => err,
        other => panic!("expected a service error, got {other:?}"),
    }
}
