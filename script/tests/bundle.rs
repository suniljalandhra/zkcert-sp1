//! `verify_bundle`: every check except Groth16 runs on a mock bundle of a synthetic email; the
//! Groth16 checks need the real fixture (`contracts/src/fixtures/groth16-proof.json`, a proof of
//! a real allowlisted email made with `SP1_PROVER=network`, see README) and are `#[ignore]`d
//! until it exists: `cargo test --release -p zkcert-script --test bundle -- --ignored`.
//!
//! The DKIM key is not a bundle check any more: the guest only accepts its compiled key table
//! (tests/verify.rs), so accepting the vkey is accepting the table.

use alloy_primitives::hex;
use alloy_sol_types::SolType;
use rsa::{rand_core::OsRng, RsaPrivateKey};
use zkcert_lib::{
    canon,
    dkim::DkimTags,
    keys::PinnedKey,
    verify::{keccak, verify_with, GuestInput},
    PublicValues,
};
use zkcert_script::{
    bundle::{verify_bundle, Decoded, ProofBundle, SP1_VERSION},
    inputs::key_der,
    prover::{accepted_vkeys, pinned_vkey},
    synth,
};

const VKEY: &str = "0x00aa";

fn accepted() -> Vec<String> {
    vec![VKEY.into()]
}

/// A mock bundle of a synthetic Udemy email (statement run with a table trusting its key).
fn mock() -> ProofBundle {
    let key = RsaPrivateKey::new(&mut OsRng, 1024).unwrap();
    let raw = synth::sign(&synth::udemy(), &key);
    let (headers, body) = canon::split_message(&raw).unwrap();
    let (dkim, rest) = headers.split_last().unwrap();
    let tags = DkimTags::parse(&dkim.value).unwrap();
    let der = key_der(&synth::record(&key)).unwrap();
    let input = GuestInput {
        headers: canon::signed_headers(canon::Canon::Relaxed, rest, &tags.h, dkim),
        body: canon::body(canon::Canon::Relaxed, body),
        signature: base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &tags.b)
            .unwrap(),
        public_key_der: der.clone(),
        wallet: [0x12; 20],
        disclose: true,
    };
    let table = [PinnedKey {
        name: "test",
        platform: 2,
        key_hash: keccak(&[&der]),
        valid_from: 0,
        valid_to: u64::MAX,
    }];
    let pv = PublicValues::abi_encode(&verify_with(&input, &table).unwrap());
    ProofBundle::new("mock", VKEY.into(), &[], &pv).unwrap()
}

fn err(b: &ProofBundle) -> String {
    verify_bundle(b, &accepted(), true).unwrap_err().to_string()
}

#[test]
fn mock_bundle_passes_non_proof_checks() {
    assert_eq!(
        verify_bundle(&mock(), &accepted(), true)
            .unwrap()
            .courseName,
        "Tally With Tax"
    );
}

#[test]
fn unknown_version_is_rejected() {
    let mut b = mock();
    b.version = "zkcert-v0".into();
    assert!(err(&b).contains("unknown bundle version"));
}

#[test]
fn vkey_not_accepted_is_rejected() {
    let b = mock();
    let e = verify_bundle(&b, &["0x00bb".into()], true)
        .unwrap_err()
        .to_string();
    assert!(e.contains("different program"), "{e}");
    // No accepted versions at all: nothing verifies.
    assert!(verify_bundle(&b, &[], true).is_err());
}

#[test]
fn any_accepted_vkey_verifies() {
    // Key rotation: an older program version stays valid while it is listed.
    let b = mock();
    let both = vec!["0x00bb".to_string(), "0x00AA".to_string()];
    assert!(verify_bundle(&b, &both, true).is_ok());
}

#[test]
fn pinned_vkey_is_accepted() {
    assert!(accepted_vkeys().unwrap().contains(&pinned_vkey().unwrap()));
}

#[test]
fn edited_decoded_fields_are_rejected() {
    let mut b = mock();
    b.decoded.course_name = "Harvard MBA".into();
    assert!(err(&b).contains("do not match"));
}

#[test]
fn undecodable_public_values_are_rejected() {
    let mut b = mock();
    b.public_values = "0x1234".into();
    assert!(err(&b).contains("do not decode"));
}

#[test]
fn mock_requires_flag_and_unknown_systems_are_rejected() {
    let mut b = mock();
    let e = verify_bundle(&b, &accepted(), false)
        .unwrap_err()
        .to_string();
    assert!(e.contains("mock"), "{e}");
    b.proof_system = "plonk".into();
    assert!(err(&b).contains("unsupported proof system"));
}

#[test]
fn bundle_records_sdk_version() {
    let lock = include_str!("../../Cargo.lock");
    let sdk = lock
        .split("name = \"sp1-sdk\"\nversion = \"")
        .nth(1)
        .unwrap();
    assert!(
        sdk.starts_with(&format!("{SP1_VERSION}\"")),
        "SP1_VERSION is stale"
    );
}

// ---- Real Groth16 fixture (a proof of a real, allowlisted email) ----

fn fixture() -> ProofBundle {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../contracts/src/fixtures/groth16-proof.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).expect("fixture")).unwrap()
}

#[test]
#[ignore = "needs contracts/src/fixtures/groth16-proof.json"]
fn groth16_fixture_verifies_for_accepted_program() {
    let b = fixture();
    verify_bundle(&b, &accepted_vkeys().unwrap(), false).unwrap();
}

#[test]
#[ignore = "needs contracts/src/fixtures/groth16-proof.json"]
fn groth16_rejects_tampered_public_values() {
    let mut b = fixture();
    let mut pv = hex::decode(&b.public_values).unwrap();
    let last = pv.len() - 1;
    pv[last] ^= 1; // last byte of the wallet
    b.public_values = hex::encode_prefixed(&pv);
    b.decoded = Decoded::from(&PublicValues::abi_decode(&pv).unwrap());
    let e = verify_bundle(&b, &accepted_vkeys().unwrap(), false)
        .unwrap_err()
        .to_string();
    assert!(e.contains("Groth16 proof invalid"), "{e}");
}
