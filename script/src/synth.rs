//! Synthetic completion emails signed with a throwaway key (RFC 6376 relaxed/relaxed). Used by
//! tests and to make the committed contract fixture, so no real email is ever committed.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rsa::{pkcs8::EncodePublicKey, Pkcs1v15Sign, RsaPrivateKey};
use sha2::{Digest, Sha256};
use zkcert_lib::canon::{self, Canon};

pub const SELECTOR: &str = "test";

pub struct Mail {
    pub d: &'static str,
    pub from: &'static str,
    pub to: &'static str,
    pub subject: &'static str,
    pub h: &'static str,
    pub content_type: &'static str,
    pub extra_tags: &'static str,
    pub extra_headers: Vec<(&'static str, &'static str)>,
    pub body: String,
}

/// Signs `m` and returns the raw .eml bytes.
pub fn sign(m: &Mail, key: &RsaPrivateKey) -> Vec<u8> {
    let mut head = String::new();
    for (n, v) in &m.extra_headers {
        head += &format!("{n}: {v}\r\n");
    }
    head += &format!(
        "From: {}\r\nTo: {}\r\nSubject: {}\r\nContent-Type: {}\r\n",
        m.from, m.to, m.subject, m.content_type
    );
    let bh = B64.encode(Sha256::digest(canon::body(
        Canon::Relaxed,
        m.body.as_bytes(),
    )));
    let unsigned = format!(
        "v=1; a=rsa-sha256; c=relaxed/relaxed; d={}; s={SELECTOR};{} h={}; bh={}; b=",
        m.d, m.extra_tags, m.h, bh
    );
    let raw_unsigned = format!("{head}DKIM-Signature: {unsigned}\r\n\r\n{}", m.body);
    let (headers, _) = canon::split_message(raw_unsigned.as_bytes()).expect("well-formed");
    let (dkim, rest) = headers.split_last().expect("has DKIM header");
    let h: Vec<String> = m.h.split(':').map(|s| s.to_ascii_lowercase()).collect();
    let blob = canon::signed_headers(Canon::Relaxed, rest, &h, dkim);
    let sig = key
        .sign(Pkcs1v15Sign::new::<Sha256>(), &Sha256::digest(&blob))
        .expect("sign");
    format!(
        "{head}DKIM-Signature: {unsigned}{}\r\n\r\n{}",
        B64.encode(&sig),
        m.body
    )
    .into_bytes()
}

/// The DKIM TXT record publishing `key`'s public half.
pub fn record(key: &RsaPrivateKey) -> String {
    let der = key.to_public_key().to_public_key_der().expect("der");
    format!("v=DKIM1; k=rsa; p={}", B64.encode(der.as_bytes()))
}

pub fn key_name(m: &Mail) -> String {
    format!("{SELECTOR}._domainkey.{}", m.d)
}

pub const COURSERA_BODY: &str = "--BOUND\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nDear Learner,\r\n\r\nCongratulations! You=E2=80=99ve successfully completed Machine Lea=\r\nrning. On behalf of Coursera we are pleased to issue your official Machine Learning Certificate.\r\n--BOUND\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n<p>html</p>\r\n--BOUND--\r\n";

pub fn coursera() -> Mail {
    Mail {
        d: "t.mail.coursera.org",
        from: "Coursera <no-reply@t.mail.coursera.org>",
        to: "Some.One@Example.com",
        subject: "Congratulations, Your Certificate is Ready!",
        h: "To:Content-Type:Subject:From",
        content_type: "multipart/alternative; boundary=\"BOUND\"",
        extra_tags: " t=1598137023;",
        extra_headers: vec![],
        body: COURSERA_BODY.into(),
    }
}

pub fn udemy() -> Mail {
    Mail {
        d: "e.udemymail.com",
        from: "Udemy <no-reply@e.udemymail.com>",
        to: "learner@example.com",
        subject: "Your completion certificate is ready for \"Tally With Tax\"",
        h: "content-type:from:subject:to",
        content_type: "text/html; charset=utf-8",
        extra_tags: "",
        extra_headers: vec![],
        body: "<html>Hi Learner, congratulations</html>\r\n".into(),
    }
}
