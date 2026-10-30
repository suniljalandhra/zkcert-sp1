//! Phase 1 discovery: inspect every DKIM-Signature in a .eml, fetch (or pin) each public key,
//! verify on the host with `mail-auth`, and show the body fields the guest will parse.
//!
//! Nothing here is trusted by the proof; it exists to learn the real email formats and to
//! check our own tag parsing against an established DKIM implementation.

use std::{borrow::Borrow, collections::HashMap, hash::Hash, time::Instant};

use alloy_primitives::{keccak256, B256};
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use mail_auth::{
    dkim::record::DomainKey,
    dns::{DnsCache, NoCache, ResolverCache, TxtRecord, TxtRecordParser},
    AuthenticatedMessage, DkimResult, DnsError, Error as AuthError, MessageAuthenticator,
};
use mail_parser::MessageParser;
use rsa::{pkcs8::DecodePublicKey, traits::PublicKeyParts, RsaPublicKey};
use zkcert_lib::{
    dkim::{parse_tag_list, DkimTags, TagError},
    platform::{coursera, Platform},
};

/// Where public keys come from. DNS is untrusted; pinned records make runs reproducible and
/// let tests run offline.
pub enum KeySource {
    Dns,
    /// `<selector>._domainkey.<domain>` (no trailing dot, lowercase) -> TXT record value.
    Pinned(HashMap<String, String>),
}

#[derive(Debug)]
pub struct KeyInfo {
    pub record: String,
    pub bits: usize,
    /// keccak256 of the SubjectPublicKeyInfo DER: the `dkimKeyHash` public value.
    pub der_keccak: B256,
}

#[derive(Debug)]
pub struct SignatureReport {
    pub raw_value: String,
    pub tags: Result<DkimTags, TagError>,
    pub key_name: Option<String>,
    pub key: Result<KeyInfo, String>,
    /// mail-auth's verdict ("pass", or the failure reason).
    pub host_verify: String,
    /// The checks the guest will enforce, evaluated on the host: (name, passed).
    pub checks: Vec<(&'static str, bool)>,
}

impl SignatureReport {
    pub fn platform(&self) -> Option<Platform> {
        self.tags
            .as_ref()
            .ok()
            .and_then(|t| Platform::from_domain(&t.d))
    }

    /// Usable only if mail-auth passed it against the key we report, and every check holds.
    pub fn usable(&self) -> bool {
        self.host_verify == "pass" && self.key.is_ok() && self.checks.iter().all(|(_, ok)| *ok)
    }
}

/// Header facts the guest's checks depend on.
#[derive(Debug, Clone, Copy)]
pub struct HeaderFacts {
    pub from_platform: Option<Platform>,
    /// Number of From header fields (RFC 5322 §3.6: exactly one).
    pub from_headers: usize,
    /// Number of mailboxes in the From field (more than one would need a Sender header).
    pub from_mailboxes: usize,
    /// Number of Subject header fields (RFC 5322 §3.6: at most one).
    pub subject_headers: usize,
}

#[derive(Debug)]
pub struct Report {
    pub from_address: String,
    pub from_platform: Option<Platform>,
    pub subject: String,
    pub date: String,
    pub signatures: Vec<SignatureReport>,
    pub coursera: Option<coursera::Fields>,
    /// Index into `signatures` of the one zkCert would use.
    pub selected: Option<usize>,
}

pub fn key_name(tags: &DkimTags) -> String {
    format!("{}._domainkey.{}", tags.s, tags.d).to_ascii_lowercase()
}

/// Parses a DKIM key record (RFC 6376 §3.6.1) into key facts.
pub fn key_info(record: &str) -> Result<KeyInfo> {
    let tags = parse_tag_list(record).map_err(|e| anyhow!("key record: {e}"))?;
    let get = |k: &str| tags.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
    if let Some(k) = get("k") {
        anyhow::ensure!(k.eq_ignore_ascii_case("rsa"), "key type k={k} is not rsa");
    }
    // t=y: the domain is testing DKIM and verifiers must not rely on it (§3.6.1).
    if let Some(flags) = get("t") {
        anyhow::ensure!(
            !flags.split(':').any(|f| f.trim() == "y"),
            "key is in testing mode (t=y)"
        );
    }
    let p: String = get("p")
        .context("key record has no p=")?
        .split_whitespace()
        .collect();
    anyhow::ensure!(!p.is_empty(), "key revoked (empty p=)");
    let der = B64.decode(&p).context("p= is not base64")?;
    let key = RsaPublicKey::from_public_key_der(&der).context("p= is not an RSA SPKI key")?;
    Ok(KeyInfo {
        record: record.to_string(),
        bits: key.n().bits(),
        der_keccak: keccak256(&der),
    })
}

/// A mail-auth DNS cache pre-filled with the keys we resolved, so mail-auth verifies against
/// exactly the key we report. Every miss answers "not found", so mail-auth never falls back to
/// querying DNS itself.
struct PinnedTxt(HashMap<Box<str>, TxtRecord>);

impl ResolverCache<Box<str>, TxtRecord> for PinnedTxt {
    fn get<Q>(&self, name: &Q) -> Option<TxtRecord>
    where
        Box<str>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        Some(
            self.0
                .get(name)
                .cloned()
                .unwrap_or(TxtRecord::Error(AuthError::Dns(
                    DnsError::InvalidRecordType,
                ))),
        )
    }

    fn remove<Q>(&self, _: &Q) -> Option<TxtRecord>
    where
        Box<str>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        None
    }

    fn insert(&self, _: Box<str>, _: TxtRecord, _: Instant) {}
}

impl DnsCache for PinnedTxt {
    type Txt = Self;
    type Mx = NoCache;
    type Ipv4 = NoCache;
    type Ipv6 = NoCache;
    type Ptr = NoCache;

    fn txt(&self) -> Option<&Self> {
        Some(self)
    }
    fn mx(&self) -> Option<&NoCache> {
        None
    }
    fn ipv4(&self) -> Option<&NoCache> {
        None
    }
    fn ipv6(&self) -> Option<&NoCache> {
        None
    }
    fn ptr(&self) -> Option<&NoCache> {
        None
    }
}

/// The guest's acceptance rules (docs/ARCHITECTURE.md §3), evaluated on the host.
pub fn guest_checks(tags: &DkimTags, facts: HeaderFacts) -> Vec<(&'static str, bool)> {
    let sig_platform = Platform::from_domain(&tags.d);
    vec![
        ("v=1", tags.v == "1"),
        ("a=rsa-sha256", tags.a.eq_ignore_ascii_case("rsa-sha256")),
        ("d= is a platform domain", sig_platform.is_some()),
        ("h= signs from", tags.signs_header("from")),
        ("h= signs subject", tags.signs_header("subject")),
        ("no l= tag", tags.l.is_none()),
        (
            "From domain matches d= platform",
            sig_platform.is_some() && sig_platform == facts.from_platform,
        ),
        // DKIM signs the bottom-most instance of a header, so an extra unsigned From/Subject
        // could be shown to users instead of the signed one. Require exactly one of each.
        (
            "exactly one From header with one mailbox",
            facts.from_headers == 1 && facts.from_mailboxes == 1,
        ),
        ("exactly one Subject header", facts.subject_headers == 1),
    ]
}

pub async fn analyze(raw: &[u8], keys: &KeySource) -> Result<Report> {
    let parsed = MessageParser::default()
        .parse(raw)
        .context("not a parseable email")?;
    let from_mailboxes = parsed.from().map(|a| a.iter().count()).unwrap_or(0);
    let from_address = parsed
        .from()
        .and_then(|a| a.first())
        .and_then(|a| a.address())
        .unwrap_or_default()
        .to_string();
    let from_platform = from_address
        .rsplit_once('@')
        .and_then(|(_, d)| Platform::from_domain(d));
    let subject = parsed.subject().unwrap_or_default().to_string();
    let date = parsed.date().map(|d| d.to_rfc3339()).unwrap_or_default();
    let body_text = parsed
        .body_text(0)
        .map(|t| t.into_owned())
        .unwrap_or_default();

    let auth_msg = AuthenticatedMessage::parse(raw).context("mail-auth could not parse email")?;
    let count = |n: &[u8]| {
        auth_msg
            .headers()
            .iter()
            .filter(|(h, _)| h.eq_ignore_ascii_case(n))
            .count()
    };
    let facts = HeaderFacts {
        from_platform,
        from_headers: count(b"From"),
        from_mailboxes,
        subject_headers: count(b"Subject"),
    };
    let raw_sigs: Vec<String> = auth_msg
        .headers()
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case(b"DKIM-Signature"))
        .map(|(_, value)| String::from_utf8_lossy(value).into_owned())
        .collect();

    let resolver = match keys {
        KeySource::Dns => Some(MessageAuthenticator::new_system_conf()?),
        KeySource::Pinned(_) => None,
    };

    let mut signatures = Vec::new();
    let mut cache = HashMap::new();
    for raw_value in raw_sigs {
        let tags = DkimTags::parse(&raw_value);
        let name = tags.as_ref().ok().map(key_name);
        let record: Result<String, String> = match (&name, keys, &resolver) {
            (None, ..) => Err("signature tags invalid".into()),
            (Some(n), KeySource::Pinned(map), _) => map
                .get(n)
                .cloned()
                .ok_or_else(|| format!("no pinned key for {n}")),
            (Some(n), KeySource::Dns, Some(r)) => r
                .txt_raw_lookup(format!("{n}."))
                .await
                .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
                .map_err(|e| format!("DNS lookup failed: {e}")),
            (Some(_), KeySource::Dns, None) => unreachable!(),
        };
        if let (Some(n), Ok(rec)) = (&name, &record) {
            if let Ok(dk) = DomainKey::parse(rec.as_bytes()) {
                cache.insert(format!("{n}.").into_boxed_str(), TxtRecord::from(dk));
            }
        }
        let checks = tags
            .as_ref()
            .map(|t| guest_checks(t, facts))
            .unwrap_or_default();
        let host_verify = if tags.is_ok() {
            // Overwritten below if mail-auth verified this header. In strict mode it refuses to
            // parse some signatures at all (e.g. l= != 0), which then yield no output.
            "rejected by mail-auth parser"
        } else {
            "not evaluated (invalid tags)"
        };
        signatures.push(SignatureReport {
            raw_value,
            key: record.and_then(|r| key_info(&r).map_err(|e| e.to_string())),
            key_name: name,
            tags,
            host_verify: host_verify.into(),
            checks,
        });
    }

    // mail-auth's own verification, against the keys resolved above only.
    let cache = PinnedTxt(cache);
    let verifier = MessageAuthenticator::new_system_conf()?;
    let outputs = verifier
        .verify_dkim(mail_auth::dns::Parameters::new(&auth_msg).with_cache(&cache))
        .await;
    for out in &outputs {
        let Some(sig) = out.signature() else { continue };
        let verdict = match out.result() {
            DkimResult::Pass => "pass".to_string(),
            other => format!("{other:?}"),
        };
        if let Some(rep) = signatures.iter_mut().find(|r| {
            r.tags.as_ref().is_ok_and(|t| {
                t.d.eq_ignore_ascii_case(&sig.d)
                    && t.s.eq_ignore_ascii_case(&sig.s)
                    && B64.decode(&t.b).is_ok_and(|b| b == sig.b)
            })
        }) {
            rep.host_verify = verdict;
        }
    }

    let selected = signatures.iter().position(|s| s.usable());
    let coursera = match selected.and_then(|i| signatures[i].platform()) {
        Some(Platform::Coursera) => coursera::parse(&body_text),
        _ => None,
    };

    Ok(Report {
        from_address,
        from_platform,
        subject,
        date,
        signatures,
        coursera,
        selected,
    })
}

pub fn pinned(entries: &[(&str, &str)]) -> KeySource {
    KeySource::Pinned(
        entries
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
    )
}
