//! Offline tests for DKIM discovery. Each test signs a synthetic Coursera-style email with a
//! throwaway RSA key generated at runtime and pins that key, so no DNS or personal data is used.

use std::sync::OnceLock;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use mail_auth::{
    crypto::{RsaKey, Sha256},
    dkim::DkimSigner,
    headers::HeaderWriter,
};
use rsa::{
    pkcs8::{EncodePrivateKey, EncodePublicKey},
    RsaPrivateKey,
};
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use zkcert_lib::dkim::DkimTags;
use zkcert_lib::platform::Platform;
use zkcert_script::discover::{analyze, guest_checks, key_info, pinned, HeaderFacts, Report};

const KEY_NAME: &str = "test._domainkey.t.mail.coursera.org";

const MESSAGE: &str = "From: \"Coursera\" <no-reply@t.mail.coursera.org>\r\n\
To: Learner <learner@example.com>\r\n\
Subject: Congratulations, Your Certificate is Ready!\r\n\
Date: Sat, 22 Aug 2020 22:57:03 +0000\r\n\
Message-ID: <test@t.mail.coursera.org>\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
\r\n\
Dear Learner,\r\n\
\r\n\
Congratulations! You\u{2019}ve successfully completed The Bits and Bytes of\r\n\
     Computer Networking. On behalf of Google and Coursera we are pleased\r\n\
     to issue your official The Bits and Bytes of Computer Networking\r\n\
     Certificate.\r\n";

struct Keys {
    pkcs8: Vec<u8>,
    record: String,
}

fn keys() -> &'static Keys {
    static KEYS: OnceLock<Keys> = OnceLock::new();
    KEYS.get_or_init(key_pair)
}

fn key_pair() -> Keys {
    let sk = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 1024).unwrap();
    let pkcs8 = sk.to_pkcs8_der().unwrap().as_bytes().to_vec();
    let spki = sk.to_public_key().to_public_key_der().unwrap();
    Keys {
        pkcs8,
        record: format!("v=DKIM1; k=rsa; p={}", B64.encode(spki.as_bytes())),
    }
}

const SIGNED_HEADERS: [&str; 5] = ["From", "To", "Subject", "Date", "Message-ID"];

fn sign_with(pkcs8: &[u8], domain: &str, message: &str, body_length: bool) -> String {
    sign_headers(pkcs8, domain, message, body_length, &SIGNED_HEADERS)
}

fn sign_headers(
    pkcs8: &[u8],
    domain: &str,
    message: &str,
    body_length: bool,
    headers: &[&str],
) -> String {
    let key = RsaKey::<Sha256>::from_key_der(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        pkcs8.to_vec(),
    )))
    .unwrap();
    let sig = DkimSigner::from_key(key)
        .domain(domain)
        .selector("test")
        .headers(headers.iter().copied())
        .body_length(body_length)
        .sign(message.as_bytes())
        .unwrap();
    format!("{}{message}", sig.to_header())
}

fn sign(message: &str) -> String {
    sign_with(&keys().pkcs8, "t.mail.coursera.org", message, false)
}

async fn run(eml: &str, key_name: &str, record: &str) -> Report {
    analyze(eml.as_bytes(), &pinned(&[(key_name, record)]))
        .await
        .unwrap()
}

fn check(report: &Report, name: &str) -> bool {
    report.signatures[0]
        .checks
        .iter()
        .find(|(n, _)| *n == name)
        .unwrap()
        .1
}

#[tokio::test]
async fn valid_email_is_selected_and_parsed() {
    let r = run(&sign(MESSAGE), KEY_NAME, &keys().record).await;
    assert_eq!(r.signatures.len(), 1);
    assert_eq!(r.signatures[0].host_verify, "pass");
    assert_eq!(r.signatures[0].key.as_ref().unwrap().bits, 1024);
    assert_eq!(r.selected, Some(0));
    assert_eq!(r.from_platform, Some(Platform::Coursera));
    assert_eq!(
        r.coursera.unwrap().course_name,
        "The Bits and Bytes of Computer Networking"
    );
}

#[tokio::test]
async fn edited_body_fails() {
    let eml = sign(MESSAGE).replace("Computer Networking. On", "Machine Learning. On");
    let r = run(&eml, KEY_NAME, &keys().record).await;
    assert_ne!(r.signatures[0].host_verify, "pass");
    assert_eq!(r.selected, None);
    assert!(r.coursera.is_none());
}

#[tokio::test]
async fn edited_subject_fails() {
    let eml = sign(MESSAGE).replace("Your Certificate is Ready", "Your Certificate is Ready!!");
    let r = run(&eml, KEY_NAME, &keys().record).await;
    assert_ne!(r.signatures[0].host_verify, "pass");
    assert_eq!(r.selected, None);
}

#[tokio::test]
async fn wrong_key_fails() {
    let other = key_pair();
    let r = run(&sign(MESSAGE), KEY_NAME, &other.record).await;
    assert_ne!(r.signatures[0].host_verify, "pass");
    assert_eq!(r.selected, None);
}

#[tokio::test]
async fn l_tag_is_rejected() {
    let eml = sign_with(&keys().pkcs8, "t.mail.coursera.org", MESSAGE, true);
    let r = run(&eml, KEY_NAME, &keys().record).await;
    // mail-auth (strict) refuses l= != 0 outright; our own check rejects any l=, including l=0.
    assert_eq!(r.signatures[0].host_verify, "rejected by mail-auth parser");
    assert!(!check(&r, "no l= tag"));
    assert_eq!(r.selected, None);
}

#[tokio::test]
async fn foreign_signing_domain_is_rejected() {
    let eml = sign_with(&keys().pkcs8, "sparkpostmail.com", MESSAGE, false);
    let r = run(&eml, "test._domainkey.sparkpostmail.com", &keys().record).await;
    assert_eq!(r.signatures[0].host_verify, "pass");
    assert!(!check(&r, "d= is a platform domain"));
    assert_eq!(r.selected, None);
}

#[tokio::test]
async fn from_domain_mismatch_is_rejected() {
    let msg = MESSAGE.replace("no-reply@t.mail.coursera.org", "no-reply@evilcoursera.org");
    let r = run(&sign(&msg), KEY_NAME, &keys().record).await;
    assert_eq!(r.signatures[0].host_verify, "pass");
    assert!(!check(&r, "From domain matches d= platform"));
    assert_eq!(r.selected, None);
}

#[tokio::test]
async fn unsigned_email_has_no_selection() {
    let r = run(MESSAGE, KEY_NAME, &keys().record).await;
    assert!(r.signatures.is_empty());
    assert_eq!(r.selected, None);
}

#[tokio::test]
async fn missing_pinned_key_never_falls_back_to_dns() {
    // Pin a different name. The selection must fail closed. (The no-DNS-fallback property itself
    // is enforced by PinnedTxt answering every miss; a live-DNS pass can't be built offline.)
    let r = run(
        &sign(MESSAGE),
        "other._domainkey.t.mail.coursera.org",
        &keys().record,
    )
    .await;
    assert_ne!(r.signatures[0].host_verify, "pass");
    assert!(r.signatures[0].key.is_err());
    assert_eq!(r.selected, None);
}

#[tokio::test]
async fn prepended_unsigned_from_is_rejected() {
    let eml = format!("From: Fake <x@t.mail.coursera.org>\r\n{}", sign(MESSAGE));
    let r = run(&eml, KEY_NAME, &keys().record).await;
    assert!(!check(&r, "exactly one From header with one mailbox"));
    assert_eq!(r.selected, None);
}

#[tokio::test]
async fn from_with_two_mailboxes_is_rejected() {
    let msg = MESSAGE.replace(
        "From: \"Coursera\" <no-reply@t.mail.coursera.org>",
        "From: \"Coursera\" <no-reply@t.mail.coursera.org>, attacker@example.com",
    );
    let r = run(&sign(&msg), KEY_NAME, &keys().record).await;
    assert_eq!(r.signatures[0].host_verify, "pass");
    assert!(!check(&r, "exactly one From header with one mailbox"));
    assert_eq!(r.selected, None);
}

#[tokio::test]
async fn prepended_unsigned_subject_is_rejected() {
    let eml = format!("Subject: Your Certificate is Ready\r\n{}", sign(MESSAGE));
    let r = run(&eml, KEY_NAME, &keys().record).await;
    assert!(!check(&r, "exactly one Subject header"));
    assert_eq!(r.selected, None);
}

#[tokio::test]
async fn subject_not_signed_is_rejected() {
    let eml = sign_headers(
        &keys().pkcs8,
        "t.mail.coursera.org",
        MESSAGE,
        false,
        &["From", "To", "Date"],
    );
    let r = run(&eml, KEY_NAME, &keys().record).await;
    assert_eq!(r.signatures[0].host_verify, "pass");
    assert!(!check(&r, "h= signs subject"));
    assert_eq!(r.selected, None);
}

#[tokio::test]
async fn from_not_signed_is_rejected() {
    // RFC 6376 requires From in h=; mail-auth's signer and verifier enforce it too.
    let eml = sign_headers(
        &keys().pkcs8,
        "t.mail.coursera.org",
        MESSAGE,
        false,
        &["Subject", "To", "Date"],
    );
    let r = run(&eml, KEY_NAME, &keys().record).await;
    assert!(!check(&r, "h= signs from"));
    assert_eq!(r.selected, None);
}

fn good_facts() -> HeaderFacts {
    HeaderFacts {
        from_platform: Some(Platform::Coursera),
        from_headers: 1,
        from_mailboxes: 1,
        subject_headers: 1,
    }
}

fn good_tags() -> DkimTags {
    DkimTags::parse(
        "v=1; a=rsa-sha256; d=t.mail.coursera.org; s=x; h=from:subject; bh=AA==; b=AA==",
    )
    .unwrap()
}

fn failed(tags: &DkimTags) -> Vec<&'static str> {
    guest_checks(tags, good_facts())
        .into_iter()
        .filter(|(_, ok)| !ok)
        .map(|(n, _)| n)
        .collect()
}

#[test]
fn checks_pass_for_good_tags() {
    assert!(failed(&good_tags()).is_empty());
}

#[test]
fn wrong_algorithm_is_rejected() {
    let mut t = good_tags();
    t.a = "rsa-sha1".into();
    assert_eq!(failed(&t), ["a=rsa-sha256"]);
}

#[test]
fn wrong_version_is_rejected() {
    let mut t = good_tags();
    t.v = "2".into();
    assert_eq!(failed(&t), ["v=1"]);
}

#[test]
fn udemy_lookalike_signing_domain_is_rejected() {
    let mut t = good_tags();
    t.d = "udemymail.com.evil.io".into();
    assert!(failed(&t).contains(&"d= is a platform domain"));
}

#[test]
fn key_record_rejections() {
    let p = keys().record.split("p=").nth(1).unwrap();
    assert!(key_info(&keys().record).is_ok());
    assert!(key_info("v=DKIM1; k=rsa; p=")
        .unwrap_err()
        .to_string()
        .contains("revoked"));
    assert!(key_info(&format!("v=DKIM1; k=ed25519; p={p}")).is_err());
    assert!(key_info(&format!("v=DKIM1; t=y; k=rsa; p={p}"))
        .unwrap_err()
        .to_string()
        .contains("testing"));
    assert!(key_info("v=DKIM1; k=rsa; p=not-base64!").is_err());
}
