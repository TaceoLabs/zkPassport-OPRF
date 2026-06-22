//! Test fixture loading for zkPassport OPRF tests.
//!
//! Reads proofs, `privateNullifier`, and `beta` from the bundled
//! `fixtures/zkpassport-proofs.json` file.

use ark_ff::PrimeField;
use zkpassport_oprf_authentication::ZKPassportProofResult;

/// Fixture data loaded from `fixtures/zkpassport-proofs.json`.
pub struct FixtureData {
    pub proofs: Vec<ZKPassportProofResult>,
    pub private_nullifier: ark_babyjubjub::Fq,
    pub beta: ark_babyjubjub::Fr,
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    let hex = if !hex.len().is_multiple_of(2) {
        format!("0{hex}")
    } else {
        hex.to_string()
    };
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("Invalid hex"))
        .collect()
}

/// Load ZKPassport proofs, privateNullifier, and beta from the fixtures file.
pub fn load_fixture_data() -> FixtureData {
    let fixture_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/zkpassport-proofs.json"
    );
    let data = std::fs::read_to_string(fixture_path)
        .unwrap_or_else(|e| panic!("Failed to read fixture file {fixture_path}: {e}"));
    let value: serde_json::Value =
        serde_json::from_str(&data).expect("Failed to parse fixture JSON");

    let proofs: Vec<ZKPassportProofResult> =
        serde_json::from_value(value["proofs"].clone()).expect("Failed to parse proofs");

    let pn_hex = value["privateNullifier"]
        .as_str()
        .expect("Missing privateNullifier");
    let private_nullifier = ark_babyjubjub::Fq::from_be_bytes_mod_order(&hex_to_bytes(pn_hex));

    let beta_hex = value["beta"].as_str().expect("Missing beta");
    let beta = ark_babyjubjub::Fr::from_be_bytes_mod_order(&hex_to_bytes(beta_hex));

    FixtureData {
        proofs,
        private_nullifier,
        beta,
    }
}
