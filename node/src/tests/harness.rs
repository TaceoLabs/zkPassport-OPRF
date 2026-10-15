use std::{collections::HashMap, num::NonZeroU16, sync::Arc};

use ark_ec::{AffineRepr as _, CurveGroup as _};
use ark_ff::Field as _;
use reqwest::StatusCode;
use ruint::aliases::U160;
use serde::Serialize;
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
use zkpassport_oprf_authentication::{
    AuthCommitment, AuthModules, CommitmentRotationRequest, FaceMatchRequestAuth,
    NullifierRequestAuth, RegisterRequestAuth, RegistrationRequest, SaltedIdentifier,
    registration_oprf_key_id,
};

use crate::{ZkPassportDb, services::oracle_proxy::test::TestOracleProxy};

pub(crate) const NUM_NODES: usize = 3;
pub(crate) const THRESHOLD: usize = 2;

/// The private nullifier `pn` of the test passport.
pub(crate) const PN: Fq = Fq::ONE;

/// Blinding factor of every OPRF request; no assertion depends on its value.
const BETA: u64 = 3;

/// OPRF key of a zkPassport customer, held by all nodes next to the registration key.
pub(crate) fn customer_key_id() -> OprfKeyId {
    OprfKeyId::new(U160::from(42))
}

pub(crate) fn commitment(n: u64) -> AuthCommitment {
    AuthCommitment::from(Fq::from(n))
}

/// Returns the error that threshold many nodes rejected the request with.
pub(crate) fn service_error(result: Result<VerifiableOprfOutput, Error>) -> ServiceError {
    match result {
        Err(Error::ThresholdServiceError(err)) => err,
        other => panic!("expected a service error, got {other:?}"),
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

/// Shamir-shares the OPRF secret `secret` with degree `THRESHOLD - 1`, one share per node.
///
/// Node `i` gets the evaluation at `i + 1`, matching the Lagrange coefficients the client
/// computes from the party ids.
fn share_key(secret: Fr) -> Vec<OprfKeyMaterial> {
    let poly: Vec<Fr> = std::iter::once(secret)
        .chain((1..THRESHOLD).map(|i| Fr::from(1000 + i as u64)))
        .collect();
    let public_key = OprfPublicKey::new((EdwardsAffine::generator() * secret).into_affine());
    (0..NUM_NODES)
        .map(|i| {
            let share = taceo_oprf::core::shamir::evaluate_poly(&poly, Fr::from(i as u64 + 1));
            OprfKeyMaterial::new(
                DLogShareShamir::from(share),
                public_key,
                ShareEpoch::default(),
            )
        })
        .collect()
}

/// Three in-process OPRF nodes holding shares of the registration and the customer key.
pub(crate) struct TestNodes {
    urls: Vec<String>,
    /// Shared by all nodes, so it records the calls of every node.
    pub(crate) oracle: TestOracleProxy,
    /// The database of each node, to check state the HTTP API does not expose.
    pub(crate) dbs: Vec<ZkPassportDb>,
    http: reqwest::Client,
    _pg: Arc<taceo_nodes_common::test_utils::SharedPostgres>,
}

impl TestNodes {
    pub(crate) async fn start(oracle: TestOracleProxy) -> eyre::Result<Self> {
        let keys = [
            (registration_oprf_key_id(), share_key(Fr::from(11u64))),
            (customer_key_id(), share_key(Fr::from(12u64))),
        ];
        let pg = taceo_nodes_common::test_utils::shared_postgres_testcontainer().await?;
        let mut urls = Vec::with_capacity(NUM_NODES);
        let mut dbs = Vec::with_capacity(NUM_NODES);
        for party_id in 0..NUM_NODES {
            // a fresh schema in the shared container
            let (_, db) = ZkPassportDb::init_test().await?;
            dbs.push(db.clone());
            let node_information = NodeInformation::new(
                PartyId(u16::try_from(party_id)?),
                format!("node-{party_id}"),
                NonZeroU16::new(u16::try_from(THRESHOLD)?).expect("non-zero"),
            );
            let secret_manager = Arc::new(InMemorySecretManager {
                node_information: node_information.clone(),
                keys: keys
                    .iter()
                    .map(|(id, shares)| (*id, shares[party_id].clone()))
                    .collect(),
            });
            let router = crate::router(
                OprfNodeServiceConfig::with_default_values(
                    Environment::Dev,
                    taceo_oprf::client::VERSION.parse()?,
                ),
                Arc::new(oracle.clone()),
                secret_manager,
                db,
                &node_information,
                "test".to_owned(),
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            urls.push(format!("http://{}", listener.local_addr()?));
            tokio::spawn(axum::serve(listener, router).into_future());
        }
        Ok(Self {
            urls,
            oracle,
            dbs,
            http: reqwest::Client::new(),
            _pg: pg,
        })
    }

    async fn oprf<Auth: Clone + Serialize + 'static>(
        &self,
        module: AuthModules,
        query: Fq,
        auth: Auth,
    ) -> Result<VerifiableOprfOutput, Error> {
        let uris = taceo_oprf::client::to_oprf_uri_many(&self.urls, module).expect("valid URIs");
        let blinding_factor =
            BlindingFactor::from_scalar(Fr::from(BETA)).expect("non-zero blinding factor");
        taceo_oprf::client::distributed_oprf(
            &uris,
            THRESHOLD,
            query,
            blinding_factor,
            Fq::from(0u64),
            auth,
            Connector::Plain,
        )
        .await
    }

    /// First registration step: evaluates `pn` under the registration key.
    pub(crate) async fn register_oprf(&self, pn: Fq) -> Result<VerifiableOprfOutput, Error> {
        self.oprf(AuthModules::Register, pn, RegisterRequestAuth::new(vec![]))
            .await
    }

    /// Runs the first registration step and returns the identifier `I`.
    pub(crate) async fn identifier(&self, pn: Fq) -> eyre::Result<SaltedIdentifier> {
        let output = self.register_oprf(pn).await?;
        Ok(SaltedIdentifier::from(output.unblinded_response))
    }

    /// Requests the nullifier of `pn` under `oprf_key_id`, authenticated with `I`.
    pub(crate) async fn nullifier_oprf(
        &self,
        pn: Fq,
        oprf_key_id: OprfKeyId,
        salted_identifier: SaltedIdentifier,
    ) -> Result<VerifiableOprfOutput, Error> {
        let auth = NullifierRequestAuth {
            oprf_key_id,
            salted_identifier,
            proofs: vec![],
        };
        self.oprf(AuthModules::Nullifier, pn, auth).await
    }

    /// Requests the evaluation of `query` under `oprf_key_id`, authenticated with face-match proofs.
    pub(crate) async fn face_match_oprf(
        &self,
        query: Fq,
        oprf_key_id: OprfKeyId,
    ) -> Result<VerifiableOprfOutput, Error> {
        let auth = FaceMatchRequestAuth::new(oprf_key_id, vec![]);
        self.oprf(AuthModules::FaceMatch, query, auth).await
    }

    async fn post(
        &self,
        node: usize,
        path: &str,
        body: &impl Serialize,
    ) -> eyre::Result<StatusCode> {
        let response = self
            .http
            .post(format!("{}/api/{path}", self.urls[node]))
            .json(body)
            .send()
            .await?;
        Ok(response.status())
    }

    /// Second registration step on `node`: stores `I` -> `commitment`.
    pub(crate) async fn post_registration(
        &self,
        node: usize,
        salted_identifier: SaltedIdentifier,
        commitment: AuthCommitment,
    ) -> eyre::Result<StatusCode> {
        let request = RegistrationRequest {
            salted_identifier,
            commitment,
            proofs: vec![],
        };
        self.post(node, "registration", &request).await
    }

    pub(crate) async fn post_rotation(
        &self,
        node: usize,
        salted_identifier: SaltedIdentifier,
        new_commitment: AuthCommitment,
    ) -> eyre::Result<StatusCode> {
        let request = CommitmentRotationRequest {
            salted_identifier,
            new_commitment,
        };
        self.post(node, "rotation", &request).await
    }

    /// Registers `I` -> `commitment` on every node.
    pub(crate) async fn register_all(
        &self,
        salted_identifier: SaltedIdentifier,
        commitment: AuthCommitment,
    ) -> eyre::Result<()> {
        for node in 0..NUM_NODES {
            let status = self
                .post_registration(node, salted_identifier, commitment)
                .await?;
            eyre::ensure!(status == StatusCode::OK, "node {node} answered {status}");
        }
        Ok(())
    }
}
