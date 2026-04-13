use ark_ff::PrimeField as _;
use eyre::Context;
use salted_nullifier_authentication::{SaltedNullifierRequestAuth, ZKPassportProofResult};
use taceo_oprf::{
    client::{Connector, VerifiableOprfOutput},
    core::oprf::BlindingFactor,
    types::OprfKeyId,
};

const UNSALTED_NULLIFIER_DS: &[u8] = b"TACEO Unsalted Nullifier Auth";

pub async fn salted_nullifier(
    services: &[String],
    threshold: usize,
    oprf_key_id: OprfKeyId,
    proofs: Vec<ZKPassportProofResult>,
    private_nullifier: ark_babyjubjub::Fq,
    beta: ark_babyjubjub::Fr,
    connector: Connector,
) -> eyre::Result<VerifiableOprfOutput> {
    let auth = SaltedNullifierRequestAuth {
        oprf_key_id,
        proofs,
    };
    let blinding_factor = BlindingFactor::from_scalar(beta).expect("Invalid blinding factor");
    let ds = ark_babyjubjub::Fq::from_be_bytes_mod_order(UNSALTED_NULLIFIER_DS);

    let uris = taceo_oprf::client::to_oprf_uri_many(services, "zkpassport")
        .context("while building URIs")?;

    let verifiable_oprf_output = taceo_oprf::client::distributed_oprf(
        &uris,
        threshold,
        private_nullifier,
        blinding_factor,
        ds,
        auth,
        connector,
    )
    .await
    .context("while computing distributed OPRF")?;

    Ok(verifiable_oprf_output)
}
