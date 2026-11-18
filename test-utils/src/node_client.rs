//! Requests to a set of OPRF nodes: OPRF evaluations over websocket and the HTTP API.

use std::{num::NonZeroUsize, sync::Arc};

use eyre::Context as _;
use reqwest::StatusCode;
use rustls::{ClientConfig, RootCertStore};
use serde::Serialize;
use taceo_oprf::{
    client::{Connector, Error, distributed_oprf_core, to_oprf_uri_many, verify_dlog_equality},
    core::oprf::{BlindedOprfRequest, BlindingFactor, client::blind_query},
    types::{OprfKeyId, api::OprfRequest, ark_babyjubjub::EdwardsAffine},
};
use uuid::Uuid;
use zkpassport_oprf_authentication::{
    AuthModules, CommitmentRotationRequest, FaceMatchRequestAuth, NullifierRequestAuth,
    RegisterRequestAuth, RegistrationRequest,
};

use crate::fixtures::{CommitmentFixture, IdentifyFixture, QueryFixture, load_fixture_data};

/// Client for a set of OPRF nodes.
pub struct NodeClient {
    nodes: Vec<String>,
    threshold: NonZeroUsize,
    connector: Connector,
    http: reqwest::Client,
}

impl NodeClient {
    /// Creates a client for `nodes`, which must be reachable over `http(s)` and in which
    /// `threshold` nodes need to respond.
    ///
    /// Needs the default rustls crypto provider to be installed.
    pub fn new(nodes: Vec<String>, threshold: NonZeroUsize) -> eyre::Result<Self> {
        to_oprf_uri_many(&nodes, AuthModules::Register).context("invalid node URL")?;
        eyre::ensure!(
            nodes.len() >= threshold.get(),
            "threshold must be between 1 and the number of nodes"
        );
        Ok(Self {
            nodes,
            threshold,
            connector: tls_connector(),
            http: reqwest::Client::new(),
        })
    }

    /// OPRF evaluation of the registration key for `fixture`.
    pub async fn identify(&self, fixture: &IdentifyFixture) -> Result<(), Error> {
        let auth = RegisterRequestAuth::new(fixture.proofs.clone());
        self.oprf(AuthModules::Register, fixture.blinded_query, auth)
            .await
    }

    /// OPRF evaluation of the key `oprf_key_id` for `fixture`.
    pub async fn nullifier(
        &self,
        oprf_key_id: OprfKeyId,
        fixture: &QueryFixture,
    ) -> Result<(), Error> {
        let auth = NullifierRequestAuth {
            oprf_key_id,
            salted_identifier: fixture.salted_identifier,
            proofs: fixture.proofs.clone(),
        };
        self.oprf(AuthModules::Nullifier, fixture.blinded_query, auth)
            .await
    }

    /// OPRF evaluation of the key `oprf_key_id` for the face-match fixture.
    pub async fn face_match(&self, oprf_key_id: OprfKeyId) -> eyre::Result<()> {
        let fixture = load_fixture_data();
        let blinding_factor =
            BlindingFactor::from_scalar(fixture.beta).context("invalid blinding factor")?;
        let blinded_query = blind_query(fixture.private_nullifier, blinding_factor);
        let auth = FaceMatchRequestAuth::new(oprf_key_id, fixture.proofs);
        self.oprf(AuthModules::FaceMatch, blinded_query.blinded_query(), auth)
            .await?;
        Ok(())
    }

    /// Posts the registration to every node and returns the status of each.
    pub async fn register(&self, fixture: &CommitmentFixture) -> eyre::Result<Vec<StatusCode>> {
        let request = RegistrationRequest {
            salted_identifier: fixture.salted_identifier,
            commitment: fixture.commitment,
            proofs: fixture.proofs.clone(),
        };
        self.post_to_all("registration", &request).await
    }

    /// Posts the rotation to every node and returns the status of each.
    pub async fn rotate(&self, fixture: &CommitmentFixture) -> eyre::Result<Vec<StatusCode>> {
        let request = CommitmentRotationRequest {
            salted_identifier: fixture.salted_identifier,
            new_commitment: fixture.commitment,
            proofs: fixture.proofs.clone(),
        };
        self.post_to_all("rotation", &request).await
    }

    /// Checks that every node is healthy and serves the public keys of `oprf_key_ids`.
    pub async fn check_online(&self, oprf_key_ids: &[OprfKeyId]) -> eyre::Result<()> {
        for node in &self.nodes {
            self.expect_ok(format!("{node}/health")).await?;
            for oprf_key_id in oprf_key_ids {
                self.expect_ok(format!("{node}/oprf_pub/{oprf_key_id}"))
                    .await?;
            }
        }
        Ok(())
    }

    async fn oprf<Auth: Clone + Serialize + 'static>(
        &self,
        module: AuthModules,
        blinded_query: EdwardsAffine,
        auth: Auth,
    ) -> Result<(), Error> {
        let uris = to_oprf_uri_many(&self.nodes, module).expect("validated in new");
        let request_id = Uuid::new_v4();
        let request = OprfRequest {
            request_id,
            blinded_query,
            auth,
        };
        let (oprf_public_key, _epoch, challenge, responses) =
            distributed_oprf_core(&uris, self.threshold.get(), request, self.connector.clone())
                .await?;
        verify_dlog_equality(
            request_id,
            oprf_public_key,
            &BlindedOprfRequest::new(blinded_query),
            &responses,
            challenge,
        )?;
        Ok(())
    }

    async fn post_to_all(
        &self,
        path: &str,
        body: &impl Serialize,
    ) -> eyre::Result<Vec<StatusCode>> {
        let mut statuses = Vec::with_capacity(self.nodes.len());
        for node in &self.nodes {
            let response = self
                .http
                .post(format!("{node}/api/{path}"))
                .json(body)
                .send()
                .await
                .with_context(|| format!("while posting to {node}"))?;
            statuses.push(response.status());
        }
        Ok(statuses)
    }

    async fn expect_ok(&self, url: String) -> eyre::Result<()> {
        let response = self
            .http
            .get(&url)
            .send()
            .await
            .with_context(|| format!("while requesting {url}"))?;
        eyre::ensure!(
            response.status() == StatusCode::OK,
            "{url} returned {}",
            response.status()
        );
        Ok(())
    }
}

fn tls_connector() -> Connector {
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    Connector::Rustls(Arc::new(config))
}

/// Checks that every status is one of `allowed`.
///
/// # Errors
/// Returns an error naming the statuses if one is not allowed.
pub fn expect_statuses(statuses: &[StatusCode], allowed: &[StatusCode]) -> eyre::Result<()> {
    eyre::ensure!(
        statuses.iter().all(|status| allowed.contains(status)),
        "got status codes {statuses:?}, expected {allowed:?}"
    );
    Ok(())
}

/// Checks that `result` is a rejection by the nodes with `error_code`.
///
/// # Errors
/// Returns an error if the request was accepted or failed with another error.
pub fn expect_rejected(result: Result<(), Error>, error_code: u16) -> eyre::Result<()> {
    match result {
        Err(Error::ThresholdServiceError(err)) if err.error_code == error_code => Ok(()),
        Err(err) => eyre::bail!("expected rejection with code {error_code}, got: {err}"),
        Ok(()) => eyre::bail!("expected rejection with code {error_code}, but it was accepted"),
    }
}
