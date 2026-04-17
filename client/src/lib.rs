#![deny(missing_docs)]
#![deny(clippy::all, clippy::pedantic)]
#![deny(
    clippy::allow_attributes_without_reason,
    clippy::assertions_on_result_states,
    clippy::dbg_macro,
    clippy::decimal_literal_representation,
    clippy::iter_over_hash_type,
    clippy::let_underscore_must_use,
    clippy::missing_assert_message,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::undocumented_unsafe_blocks,
    clippy::unnecessary_safety_comment,
    clippy::unwrap_used
)]
//! Client library for zkPassport's instance of TACEO:OPRF.
//!
//! This crate wraps the upstream [`taceo_oprf::client`] functionality and
//! provides [`face_match_oprf`], a single async entry-point that:
//!
//! 1. Builds the authentication payload from zkPassport proofs.
//! 2. Derives the blinding factor and domain separator.
//! 3. Calls the distributed OPRF protocol across the provided service URIs.
//!
//! The returned [`taceo_oprf::client::VerifiableOprfOutput`] can be
//! verified on-chain or inside a zero-knowledge proof.

use std::num::NonZeroUsize;

use ark_ff::PrimeField as _;
use eyre::Context;
use taceo_oprf::{
    client::{Connector, VerifiableOprfOutput},
    core::oprf::BlindingFactor,
    types::OprfKeyId,
};
use zkpassport_oprf_authentication::{AuthModules, FaceMatchRequestAuth, ZKPassportProofResult};

/// Domain separator used when hashing the private nullifier into a field element.
///
/// This value is mixed into the OPRF input to bind evaluations to the
/// zkPassport use-case, preventing cross-protocol attacks.
const ZKPASSPORT_OPRF_DS: &[u8] = b"TACEO zkPassport OPRF Auth";

/// Perform a distributed, verifiable OPRF evaluation with zkPassport face-match authentication.
///
/// Connects to the OPRF nodes at `services`, assembles the [`FaceMatchRequestAuth`] payload
/// from the provided `proofs`, and runs the threshold OPRF protocol.
///
/// # Parameters
/// - `services` — base URLs of the OPRF service nodes (must have at least `threshold` entries)
/// - `threshold` — minimum number of nodes required to reconstruct the output
/// - `oprf_key_id` — identifier of the OPRF key registered on-chain
/// - `proofs` — zkPassport proof results to include in the authentication payload
/// - `private_nullifier` — the client's private nullifier (`BabyJubJub` base field element)
/// - `beta` — pre-chosen blinding scalar (`BabyJubJub` scalar field element)
/// - `connector` — TLS / transport connector used for the WebSocket connection
///
/// # Errors
/// Returns an error if URI construction fails, the OPRF protocol fails, or
/// fewer than `threshold` nodes respond successfully.
pub async fn face_match_oprf(
    services: &[String],
    threshold: NonZeroUsize,
    oprf_key_id: OprfKeyId,
    proofs: Vec<ZKPassportProofResult>,
    private_nullifier: ark_babyjubjub::Fq,
    beta: ark_babyjubjub::Fr,
    connector: Connector,
) -> eyre::Result<VerifiableOprfOutput> {
    let auth = FaceMatchRequestAuth {
        oprf_key_id,
        proofs,
    };
    let blinding_factor = BlindingFactor::from_scalar(beta).context("Invalid blinding factor")?;
    let ds = ark_babyjubjub::Fq::from_be_bytes_mod_order(ZKPASSPORT_OPRF_DS);

    let uris = taceo_oprf::client::to_oprf_uri_many(services, AuthModules::FaceMatch)
        .context("while building URIs")?;

    let verifiable_oprf_output = taceo_oprf::client::distributed_oprf(
        &uris,
        threshold.get(),
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
