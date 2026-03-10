use ark_ff::PrimeField as _;
use eyre::Context;
use rand::{CryptoRng, Rng};
use salted_nullifier_authentication::SaltedNullifierRequestAuth;
use taceo_oprf::{
    client::{Connector, VerifiableOprfOutput},
    core::oprf::BlindingFactor,
    types::OprfKeyId,
};

const UNSALTED_NULLIFIER_DS: &[u8] = b"TACEO Unsalted Nullifier Auth";

fn compute_encrypted_unsalted_nullifier(
    oprf_key_id: OprfKeyId,
) -> (SaltedNullifierRequestAuth, ark_babyjubjub::Fq) {
    let auth = SaltedNullifierRequestAuth { oprf_key_id };
    (auth, rand::random())
}

pub async fn salted_nullifier<R: Rng + CryptoRng>(
    services: &[String],
    threshold: usize,
    oprf_key_id: OprfKeyId,
    connector: Connector,
    rng: &mut R,
) -> eyre::Result<VerifiableOprfOutput> {
    let (oprf_request_auth, query_hash) = compute_encrypted_unsalted_nullifier(oprf_key_id);
    let blinding_factor = BlindingFactor::rand(rng);
    let ds = ark_babyjubjub::Fq::from_be_bytes_mod_order(UNSALTED_NULLIFIER_DS);

    let uris =
        taceo_oprf::client::to_oprf_uri_many(services, "face").context("while building URIs")?;

    let verifiable_oprf_output = taceo_oprf::client::distributed_oprf(
        &uris,
        threshold,
        query_hash,
        blinding_factor,
        ds,
        oprf_request_auth,
        connector,
    )
    .await
    .context("while computing distributed OPRF")?;

    // TODO
    // post processing of verifiable oprf-output
    // potentially won't happen in rust land, therefore maybe we don't really need anything here
    Ok(verifiable_oprf_output)
}
