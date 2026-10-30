//! `verify_bundle`: every check except Groth16 runs on a mock bundle of a synthetic email; the
//! Groth16 checks need the real fixture (`contracts/src/fixtures/groth16-proof.json`, made with
//! `SP1_PROVER=network`, see README) and are `#[ignore]`d until it exists:
//! `cargo test --release -p zkcert-script --test bundle -- --ignored`.

use alloy_primitives::hex;
use alloy_sol_types::SolType;
use rsa::{rand_core::OsRng, RsaPrivateKey};
use zkcert_lib::{canon, dkim::DkimTags, verify::verify, PublicValues};
use zkcert_script::{
    bundle::{verify_bundle, Decoded, ProofBundle, SP1_VERSION},
    discover::key_info,
    inputs::key_der,
    keys::{self, KnownKey},
    synth,
};

const VKEY: &str = "0x00aa";

/// A mock bundle of a synthetic Udemy email, plus an allowlist holding its key for `platform`.
fn mock(platform: u8) -> (ProofBundle, Vec<KnownKey>) {
    let key = RsaPrivateKey::new(&mut OsRng, 1024).unwrap();
    let raw = synth::sign(&synth::udemy(), &key);
    let (headers, body) = canon::split_message(&raw).unwrap();
    let (dkim, rest) = headers.split_last().unwrap();
    let tags = DkimTags::parse(&dkim.value).unwrap();
    let record = synth::record(&key);
    let input = zkcert_lib::verify::GuestInput {
        headers: canon::signed_headers(canon::Canon::Relaxed, rest, &tags.h, dkim),
        body: canon::body(canon::Canon::Relaxed, body),
        signature: base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &tags.b)
            .unwrap(),
        public_key_der: key_der(&record).unwrap(),
        wallet: [0x12; 20],
        disclose: true,
    };
    let pv = PublicValues::abi_encode(&verify(&input).unwrap());
    let allow = vec![KnownKey {
        platform,
        name: synth::key_name(&synth::udemy()),
        key_hash: key_info(&record).unwrap().der_keccak,
        record,
    }];
    (
        ProofBundle::new("mock", VKEY.into(), &[], &pv).unwrap(),
        allow,
    )
}

fn err(b: &ProofBundle, keys: &[KnownKey]) -> String {
    verify_bundle(b, VKEY, keys, true).unwrap_err().to_string()
}

#[test]
fn mock_bundle_passes_non_proof_checks() {
    let (b, keys) = mock(2);
    assert_eq!(
        verify_bundle(&b, VKEY, &keys, true).unwrap().courseName,
        "Tally With Tax"
    );
}

#[test]
fn unknown_version_is_rejected() {
    let (mut b, keys) = mock(2);
    b.version = "zkcert-v0".into();
    assert!(err(&b, &keys).contains("unknown bundle version"));
}

#[test]
fn wrong_vkey_is_rejected() {
    let (b, keys) = mock(2);
    let e = verify_bundle(&b, "0x00bb", &keys, true)
        .unwrap_err()
        .to_string();
    assert!(e.contains("different program"), "{e}");
}

#[test]
fn key_not_on_allowlist_is_rejected() {
    let (b, _) = mock(2);
    assert!(err(&b, &keys::allowlist()).contains("not on the allowlist"));
}

#[test]
fn key_for_other_platform_is_rejected() {
    let (b, _) = mock(2);
    let (_, coursera_keys) = mock(1);
    // Even the right key hash is refused when it is allowlisted for the other platform.
    let (b2, mut keys) = (b, coursera_keys);
    keys[0].key_hash = hex::decode(&b2.decoded.dkim_key_hash)
        .unwrap()
        .as_slice()
        .try_into()
        .unwrap();
    assert!(err(&b2, &keys).contains("not on the allowlist"));
}

#[test]
fn edited_decoded_fields_are_rejected() {
    let (mut b, keys) = mock(2);
    b.decoded.course_name = "Harvard MBA".into();
    assert!(err(&b, &keys).contains("do not match"));
}

#[test]
fn undecodable_public_values_are_rejected() {
    let (mut b, keys) = mock(2);
    b.public_values = "0x1234".into();
    assert!(err(&b, &keys).contains("do not decode"));
}

#[test]
fn mock_requires_flag_and_unknown_systems_are_rejected() {
    let (mut b, keys) = mock(2);
    let e = verify_bundle(&b, VKEY, &keys, false)
        .unwrap_err()
        .to_string();
    assert!(e.contains("mock"), "{e}");
    b.proof_system = "plonk".into();
    assert!(err(&b, &keys).contains("unsupported proof system"));
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

// ---- Real Groth16 fixture ----

fn fixture() -> (ProofBundle, Vec<KnownKey>) {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../contracts/src/fixtures/groth16-proof.json"
    );
    let b: ProofBundle =
        serde_json::from_str(&std::fs::read_to_string(path).expect("fixture")).unwrap();
    let record = include_str!("../../fixtures/redacted/synthetic-udemy.key")
        .trim()
        .to_string();
    let keys = vec![KnownKey {
        platform: 2,
        name: "test._domainkey.e.udemymail.com".into(),
        key_hash: key_info(&record).unwrap().der_keccak,
        record,
    }];
    (b, keys)
}

#[test]
#[ignore = "needs contracts/src/fixtures/groth16-proof.json"]
fn groth16_fixture_verifies_for_pinned_program() {
    let (b, keys) = fixture();
    assert_eq!(b.vkey, zkcert_script::prover::pinned_vkey().unwrap());
    verify_bundle(&b, &b.vkey, &keys, false).unwrap();
}

#[test]
#[ignore = "needs contracts/src/fixtures/groth16-proof.json"]
fn groth16_rejects_tampered_public_values() {
    let (mut b, keys) = fixture();
    let mut pv = hex::decode(&b.public_values).unwrap();
    let last = pv.len() - 1;
    pv[last] ^= 1; // last byte of the wallet
    b.public_values = hex::encode_prefixed(&pv);
    b.decoded = Decoded::from(&PublicValues::abi_decode(&pv).unwrap());
    let e = verify_bundle(&b, &b.vkey.clone(), &keys, false)
        .unwrap_err()
        .to_string();
    assert!(e.contains("Groth16 proof invalid"), "{e}");
}
