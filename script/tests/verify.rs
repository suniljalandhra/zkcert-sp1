//! Positive and negative tests for the guest statement (`zkcert_lib::verify`), using synthetic
//! emails signed with a key generated at test time, plus the real fixtures when present
//! (they are git-ignored, so those tests skip on a fresh clone).
//!
//! Synthetic keys are not in the production key table, so most tests use [`verify`] below, which
//! runs the statement with a table trusting the input's key; the key-table tests use the real
//! table or explicit windows.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rsa::{pkcs8::EncodePublicKey, rand_core::OsRng, RsaPrivateKey};
use sp1_sdk::{
    blocking::{Prover, ProverClient},
    include_elf, Elf, SP1Stdin,
};
use zkcert_lib::{
    canon::{self, Canon},
    dkim::DkimTags,
    keys::{PinnedKey, KEYS},
    verify::{self as statement, keccak, verify_with, GuestInput, VerifyError, NULLIFIER_DOMAIN},
    PublicValues,
};
use zkcert_script::{
    inputs::prepare,
    keys,
    synth::{self, coursera, udemy, Mail, COURSERA_BODY},
};

const ELF: Elf = include_elf!("zkcert-program");

/// A table entry for `der` on `platform` with the window `[from, to)`.
fn pinned(der: &[u8], platform: u8, from: u64, to: u64) -> PinnedKey {
    PinnedKey {
        name: "test",
        platform,
        key_hash: keccak(&[der]),
        valid_from: from,
        valid_to: to,
    }
}

/// The statement with a table that trusts the input's key, unbounded, for both platforms.
fn verify(input: &GuestInput) -> Result<PublicValues, VerifyError> {
    let der = &input.public_key_der;
    verify_with(
        input,
        &[pinned(der, 1, 0, u64::MAX), pinned(der, 2, 0, u64::MAX)],
    )
}

/// Runs the real guest ELF; true if it ran and exited non-zero (then no valid proof can exist).
/// An executor error (ELF not loading, bad stdin) fails the test instead of counting as a rejection.
/// Callers also assert the host `verify` error, so the rejection reason is known.
fn guest_rejects(input: &GuestInput) -> bool {
    let mut stdin = SP1Stdin::new();
    stdin.write(input);
    let client = ProverClient::builder().mock().build();
    let (_, report) = client
        .execute(ELF, stdin)
        .run()
        .expect("executor error, not a guest rejection");
    report.exit_code != 0
}

fn key() -> RsaPrivateKey {
    RsaPrivateKey::new(&mut OsRng, 1024).unwrap()
}

fn der(k: &RsaPrivateKey) -> Vec<u8> {
    k.to_public_key()
        .to_public_key_der()
        .unwrap()
        .as_bytes()
        .to_vec()
}

/// Signs `m` and builds the guest input from the raw message the way the host does.
fn signed(m: &Mail, k: &RsaPrivateKey) -> (Vec<u8>, GuestInput) {
    let raw = synth::sign(m, k);
    let (headers, body) = canon::split_message(&raw).unwrap();
    let (dkim, rest) = headers.split_last().unwrap();
    let tags = DkimTags::parse(&dkim.value).unwrap();
    let input = GuestInput {
        headers: canon::signed_headers(Canon::Relaxed, rest, &tags.h, dkim),
        body: canon::body(Canon::Relaxed, body),
        signature: B64.decode(&tags.b).unwrap(),
        public_key_der: der(k),
        wallet: [0x11; 20],
        disclose: true,
    };
    (raw, input)
}

/// Rewrites the signed-header blob (checks that run before the RSA check see the edit).
fn edit_blob(input: &mut GuestInput, from: &str, to: &str) {
    let blob = String::from_utf8(input.headers.clone()).unwrap();
    assert!(blob.contains(from), "{from:?} not in blob");
    input.headers = blob.replacen(from, to, 1).into_bytes();
}

fn err(m: &Mail) -> VerifyError {
    verify(&signed(m, &key()).1).unwrap_err()
}

#[test]
fn valid_coursera() {
    let k = key();
    let (_, input) = signed(&coursera(), &k);
    let v = verify(&input).unwrap();
    assert_eq!(v.platform, 1);
    assert_eq!(v.courseName, "Machine Learning");
    // t=1598137023 (2020-08-22T22:57:03Z) rounded down to the day.
    assert_eq!(v.emailSignedAt, 1598054400);
    assert_eq!(v.courseHash.0, keccak(&[b"Machine Learning"]));
    assert_eq!(v.dkimKeyHash.0, keccak(&[&der(&k)]));
    assert_eq!(v.wallet.0 .0, [0x11; 20]);
    // The To address is lowercased before hashing, so case variants share one nullifier.
    let to = keccak(&[b"some.one@example.com"]);
    assert_eq!(
        v.nullifier.0,
        keccak(&[NULLIFIER_DOMAIN, &[1], &v.courseHash.0, &to])
    );
}

#[test]
fn valid_udemy() {
    let v = verify(&signed(&udemy(), &key()).1).unwrap();
    assert_eq!(
        (v.platform, v.courseName.as_str(), v.emailSignedAt),
        (2, "Tally With Tax", 0)
    );
}

#[test]
fn hidden_course_name() {
    let (_, mut input) = signed(&udemy(), &key());
    input.disclose = false;
    let v = verify(&input).unwrap();
    assert_eq!(v.courseName, "");
    assert_eq!(v.courseHash.0, keccak(&[b"Tally With Tax"]));
}

#[test]
fn edited_body_is_rejected() {
    let (_, mut input) = signed(&coursera(), &key());
    let body = String::from_utf8(input.body)
        .unwrap()
        .replace("Machine Learning", "Deep Learning");
    input.body = body.into_bytes();
    assert_eq!(verify(&input).unwrap_err(), VerifyError::BodyHash);
}

#[test]
fn edited_subject_is_rejected() {
    let (_, mut input) = signed(&udemy(), &key());
    let h = String::from_utf8(input.headers)
        .unwrap()
        .replace("Tally With Tax", "Harvard MBA");
    input.headers = h.into_bytes();
    assert_eq!(verify(&input).unwrap_err(), VerifyError::Signature);
}

#[test]
fn wrong_key_is_rejected() {
    let (_, mut input) = signed(&coursera(), &key());
    input.public_key_der = der(&key());
    assert_eq!(verify(&input).unwrap_err(), VerifyError::Signature);
}

#[test]
fn short_key_is_rejected() {
    let k = RsaPrivateKey::new(&mut OsRng, 512).unwrap();
    assert!(matches!(
        verify(&signed(&coursera(), &k).1).unwrap_err(),
        VerifyError::Key(_)
    ));
}

#[test]
fn l_tag_is_rejected() {
    let mut m = coursera();
    m.extra_tags = " l=10;";
    assert_eq!(err(&m), VerifyError::LengthTag);
    m.extra_tags = " l=0;";
    assert_eq!(err(&m), VerifyError::LengthTag);
}

#[test]
fn foreign_signing_domain_is_rejected() {
    for d in [
        "sendgrid.info",
        "evilcoursera.org",
        "coursera.org.evil.com",
        "udemymail.com.evil.io",
    ] {
        let mut m = coursera();
        m.d = d;
        assert!(matches!(err(&m), VerifyError::Unsupported(_)), "{d}");
    }
}

#[test]
fn from_of_other_platform_is_rejected() {
    let mut m = coursera();
    m.from = "Udemy <no-reply@e.udemymail.com>";
    assert_eq!(err(&m), VerifyError::FromDomain);
    m.from = "x@gmail.com";
    assert_eq!(err(&m), VerifyError::FromDomain);
}

#[test]
fn unsigned_required_headers_are_rejected() {
    for (h, missing) in [
        ("Content-Type:Subject:From", "to"),
        ("To:From", "subject"),
        ("To:Subject", "from"),
    ] {
        let mut m = coursera();
        m.h = h;
        assert_eq!(err(&m), VerifyError::HeaderNotSigned(missing));
    }
}

#[test]
fn duplicate_signed_from_is_rejected() {
    let mut m = coursera();
    m.h = "To:Content-Type:Subject:From:From";
    m.extra_headers = vec![("From", "Attacker <a@t.mail.coursera.org>")];
    assert_eq!(err(&m), VerifyError::HeaderCount("from"));
}

#[test]
fn two_mailboxes_in_from_are_rejected() {
    let mut m = coursera();
    m.from = "no-reply@t.mail.coursera.org, me@example.com";
    assert_eq!(err(&m), VerifyError::HeaderCount("from mailbox"));
}

#[test]
fn other_platform_emails_are_rejected() {
    let mut m = coursera();
    m.subject = "New reply in your discussion forum";
    assert_eq!(err(&m), VerifyError::NotCertificateEmail);
    let mut m = udemy();
    m.subject = "Your instructor sent an announcement";
    assert_eq!(err(&m), VerifyError::NotCertificateEmail);
}

#[test]
fn injected_course_claim_is_rejected() {
    let mut m = coursera();
    m.body = COURSERA_BODY.replace(
        "Dear Learner,",
        "Dear Congratulations! You=E2=80=99ve successfully completed Fake. your official Fake Certificate,",
    );
    assert_eq!(err(&m), VerifyError::NotCertificateEmail);
}

#[test]
fn identity_outside_domain_is_rejected() {
    let mut m = coursera();
    m.extra_tags = " i=@evil.com;";
    assert!(matches!(err(&m), VerifyError::Unsupported(_)));
}

#[test]
fn signature_value_in_hash_input_is_rejected() {
    let (_, mut input) = signed(&coursera(), &key());
    input.headers.extend(b"AAAA");
    assert!(matches!(
        verify(&input).unwrap_err(),
        VerifyError::Malformed(_)
    ));
}

#[test]
fn host_builds_same_input_from_raw_email() {
    // Our canonicalization + selection on the raw message reproduces exactly what was signed.
    let k = key();
    let (raw, signed_input) = signed(&udemy(), &k);
    let (headers, body) = canon::split_message(&raw).unwrap();
    let (dkim, rest) = headers.split_last().unwrap();
    let h: Vec<String> = udemy().h.split(':').map(String::from).collect();
    assert_eq!(
        canon::signed_headers(Canon::Relaxed, rest, &h, dkim),
        signed_input.headers
    );
    assert_eq!(canon::body(Canon::Relaxed, body), signed_input.body);
}

fn fixture(name: &str) -> Option<Vec<u8>> {
    std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../fixtures/").to_string() + name).ok()
}

fn prepare_blocking(raw: &[u8]) -> anyhow::Result<zkcert_script::inputs::Prepared> {
    tokio::runtime::Runtime::new()?.block_on(prepare(
        raw,
        &keys::pinned_source(),
        KEYS,
        [0x22; 20],
        true,
    ))
}

#[test]
fn real_fixtures_verify_and_tampering_fails() {
    for (name, course, needle) in [
        (
            "sample.eml",
            "The Bits and Bytes of Computer Networking",
            "Bits and Bytes of",
        ),
        ("udemy.eml", "Tally With Tax", "Tally With Tax\"\r\n"),
    ] {
        let Some(raw) = fixture(name) else {
            eprintln!("skipping {name}: not present");
            continue;
        };
        assert_eq!(prepare_blocking(&raw).unwrap().expected.courseName, course);
        let tampered =
            String::from_utf8_lossy(&raw).replacen(needle, &needle.replace(['T', 'B'], "X"), 1);
        assert!(
            prepare_blocking(tampered.as_bytes()).is_err(),
            "{name} tampered"
        );
    }
}

#[test]
fn guest_panics_on_invalid_input() {
    // A panicking guest exits non-zero; the SP1 verifiers (sp1-verifier and the on-chain
    // SP1VerifierGroth16) reject any proof whose exit code is not 0.
    let (_, mut input) = signed(&coursera(), &key());
    input.body.push(b'!');
    assert_eq!(verify(&input).unwrap_err(), VerifyError::BodyHash);
    assert!(guest_rejects(&input));
}

// ---- Key table (compiled into the guest) ----

#[test]
fn production_table_rejects_unknown_key() {
    // A correctly signed email whose key is not in lib/src/keys.rs: an attacker's own key.
    let (_, input) = signed(&udemy(), &key());
    assert_eq!(
        statement::verify(&input).unwrap_err(),
        VerifyError::UnknownKey
    );
}

#[test]
fn guest_rejects_unknown_key() {
    let (_, input) = signed(&udemy(), &key());
    assert!(verify(&input).is_ok(), "the email itself is valid");
    assert_eq!(
        statement::verify(&input).unwrap_err(),
        VerifyError::UnknownKey
    );
    assert!(guest_rejects(&input));
}

#[test]
fn key_for_other_platform_is_rejected() {
    // The key is pinned for Coursera only; a Udemy-domain email signed with it is refused.
    let k = key();
    let (_, input) = signed(&udemy(), &k);
    let table = [pinned(&der(&k), 1, 0, u64::MAX)];
    assert_eq!(
        verify_with(&input, &table).unwrap_err(),
        VerifyError::UnknownKey
    );
}

#[test]
fn signing_time_outside_key_window_is_rejected() {
    // synth::coursera() signs with t=1598137023.
    let t = 1_598_137_023;
    let k = key();
    let (_, input) = signed(&coursera(), &k);
    let d = der(&k);
    let check = |from, to| verify_with(&input, &[pinned(&d, 1, from, to)]);
    assert!(check(t, t + 1).is_ok(), "window is [from, to)");
    assert_eq!(check(t + 1, u64::MAX).unwrap_err(), VerifyError::KeyWindow);
    assert_eq!(check(0, t).unwrap_err(), VerifyError::KeyWindow);
}

#[test]
fn bounded_key_requires_signing_time() {
    // Udemy signatures have no t=; a key with a window cannot be checked, so it is refused.
    let k = key();
    let (_, input) = signed(&udemy(), &k);
    let table = [pinned(&der(&k), 2, 1, u64::MAX)];
    assert_eq!(
        verify_with(&input, &table).unwrap_err(),
        VerifyError::KeyWindow
    );
}

#[test]
fn guest_accepts_real_fixture_and_rejects_body_edit() {
    let Some(raw) = fixture("sample.eml") else {
        eprintln!("skipping: fixtures/sample.eml not present");
        return;
    };
    let input = prepare_blocking(&raw).unwrap().input;
    assert!(!guest_rejects(&input));
    let mut edited = input.clone();
    let i = edited.body.windows(4).position(|w| w == b"Bits").unwrap();
    edited.body[i + 1] = b'a';
    assert!(guest_rejects(&edited));
}

#[test]
fn last_field_must_be_dkim_signature() {
    let (_, mut input) = signed(&udemy(), &key());
    input.headers.extend(b"\r\nx-foo:bar");
    assert_eq!(
        verify(&input).unwrap_err(),
        VerifyError::Malformed("last header is not DKIM-Signature")
    );
}

#[test]
fn non_utf8_or_malformed_blob_is_rejected() {
    let (_, mut input) = signed(&udemy(), &key());
    input.headers.insert(0, 0xff);
    assert_eq!(
        verify(&input).unwrap_err(),
        VerifyError::Malformed("headers not UTF-8")
    );
    let (_, mut input) = signed(&udemy(), &key());
    input
        .headers
        .splice(0..0, b"no colon here\r\n".iter().copied());
    assert_eq!(
        verify(&input).unwrap_err(),
        VerifyError::Malformed("header blob")
    );
}

#[test]
fn unsupported_tag_values_are_rejected() {
    for (from, to) in [
        ("v=1;", "v=2;"),
        ("a=rsa-sha256;", "a=rsa-sha1;"),
        ("c=relaxed/relaxed;", "c=nowsp;"),
    ] {
        let (_, mut input) = signed(&udemy(), &key());
        edit_blob(&mut input, from, to);
        assert!(
            matches!(verify(&input).unwrap_err(), VerifyError::Unsupported(_)),
            "{to}"
        );
    }
}

#[test]
fn bad_body_hash_encoding_is_rejected() {
    let (_, mut input) = signed(&udemy(), &key());
    edit_blob(&mut input, "bh=", "bh=*");
    assert!(matches!(
        verify(&input).unwrap_err(),
        VerifyError::BadTags(_)
    ));
}

#[test]
fn identity_tag_variants() {
    let mut m = coursera();
    m.extra_tags = " i=no-at-sign;";
    assert!(matches!(err(&m), VerifyError::Unsupported(_)));
    m.extra_tags = " i=@sub.t.mail.coursera.org;";
    assert!(verify(&signed(&m, &key()).1).is_ok());
}

#[test]
fn expiry_before_signing_time_is_rejected() {
    let mut m = coursera();
    m.extra_tags = " t=1598137023; x=1598137023;";
    assert_eq!(err(&m), VerifyError::Unsupported("x= not after t="));
}

#[test]
fn duplicate_signed_subject_or_to_is_rejected() {
    let mut m = udemy();
    m.h = "content-type:from:subject:subject:to";
    m.extra_headers = vec![(
        "Subject",
        "Your completion certificate is ready for \"Fake\"",
    )];
    assert_eq!(err(&m), VerifyError::HeaderCount("subject"));
    let mut m = udemy();
    m.h = "content-type:from:subject:to:to";
    m.extra_headers = vec![("To", "someone-else@example.com")];
    assert_eq!(err(&m), VerifyError::HeaderCount("to"));
}

#[test]
fn two_mailboxes_in_to_are_rejected() {
    let mut m = udemy();
    m.to = "a@example.com, b@example.com";
    assert_eq!(err(&m), VerifyError::HeaderCount("to mailbox"));
}

#[test]
fn fields_out_of_h_order_are_rejected() {
    let (_, mut input) = signed(&udemy(), &key());
    let blob = String::from_utf8(input.headers.clone()).unwrap();
    let mut lines: Vec<&str> = blob.split("\r\n").collect();
    lines.swap(0, 1);
    input.headers = lines.join("\r\n").into_bytes();
    assert_eq!(
        verify(&input).unwrap_err(),
        VerifyError::Malformed("signed fields do not follow h=")
    );
}

#[test]
fn key_that_is_not_spki_is_rejected() {
    let (_, mut input) = signed(&udemy(), &key());
    input.public_key_der = b"not der".to_vec();
    assert_eq!(
        verify(&input).unwrap_err(),
        VerifyError::Key("not an RSA SPKI DER")
    );
}

#[test]
fn key_size_boundary() {
    let k = RsaPrivateKey::new(&mut OsRng, 1016).unwrap();
    assert!(matches!(
        verify(&signed(&udemy(), &k).1).unwrap_err(),
        VerifyError::Key(_)
    ));
    // 1024 bits is accepted (valid_coursera / valid_udemy use 1024-bit keys).
}

#[test]
fn coursera_content_type_must_be_signed_with_boundary() {
    let mut m = coursera();
    m.h = "To:Subject:From";
    assert_eq!(err(&m), VerifyError::HeaderNotSigned("content-type"));
    let mut m = coursera();
    m.content_type = "multipart/alternative";
    assert_eq!(err(&m), VerifyError::NotCertificateEmail);
}

#[test]
fn coursera_two_text_parts_are_rejected() {
    let mut m = coursera();
    m.body = COURSERA_BODY.replace(
        "--BOUND--",
        "--BOUND\r\nContent-Type: text/plain\r\n\r\nCongratulations! You=E2=80=99ve successfully completed Fake. your official Fake Certificate.\r\n--BOUND--",
    );
    assert_eq!(err(&m), VerifyError::NotCertificateEmail);
}

#[test]
fn encoded_word_subjects() {
    let mut m = udemy();
    // "Your completion certificate is ready for \"Café\"" as one UTF-8 B encoded word.
    m.subject = "=?UTF-8?B?WW91ciBjb21wbGV0aW9uIGNlcnRpZmljYXRlIGlzIHJlYWR5IGZvciAiQ2Fmw6ki?=";
    assert_eq!(
        verify(&signed(&m, &key()).1).unwrap().courseName,
        "Caf\u{e9}"
    );
    m.subject = "=?UTF-8?B?***?=";
    assert_eq!(err(&m), VerifyError::Malformed("subject encoding"));
}

#[test]
fn nullifier_depends_only_on_the_certificate() {
    let k = key();
    let (_, input) = signed(&udemy(), &k);
    let base = verify(&input).unwrap().nullifier;
    let mut other = input.clone();
    other.wallet = [0x99; 20];
    other.disclose = false;
    assert_eq!(verify(&other).unwrap().nullifier, base);
    let mut m = udemy();
    m.to = "LEARNER@EXAMPLE.COM";
    assert_eq!(verify(&signed(&m, &k).1).unwrap().nullifier, base);
    let mut m = udemy();
    m.to = "another@example.com";
    assert_ne!(verify(&signed(&m, &k).1).unwrap().nullifier, base);
}

#[test]
fn pinned_vkey_matches_program() {
    // Fails when the guest changes without `zkcert vkey --write` (stale pin in config/program.json).
    use zkcert_script::prover::{pinned_vkey, program_vkey};
    assert_eq!(pinned_vkey().unwrap(), program_vkey());
}
