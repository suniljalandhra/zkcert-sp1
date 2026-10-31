//! Builds the guest input from a raw .eml: pick the platform signature, canonicalize, and check the
//! result with the same `verify` the guest runs.

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use zkcert_lib::{
    canon::{self, RawHeader},
    dkim::{parse_tag_list, DkimTags},
    keys::PinnedKey,
    verify::{verify_with, GuestInput},
    PublicValues,
};

use crate::discover::{analyze, KeySource};

/// Converts bare LF line endings to CRLF (some mail clients save .eml files that way).
pub fn normalize_crlf(raw: &[u8]) -> Vec<u8> {
    if raw.windows(2).any(|w| w == b"\r\n") {
        return raw.to_vec();
    }
    let mut out = Vec::with_capacity(raw.len() + raw.len() / 32);
    for &b in raw {
        if b == b'\n' {
            out.push(b'\r');
        }
        out.push(b);
    }
    out
}

/// The SPKI DER inside a DKIM key record's p= tag.
pub fn key_der(record: &str) -> Result<Vec<u8>> {
    let tags = parse_tag_list(record).map_err(|e| anyhow!("key record: {e}"))?;
    let p: String = tags
        .iter()
        .find(|(n, _)| n == "p")
        .context("key record has no p=")?
        .1
        .split_whitespace()
        .collect();
    B64.decode(p).context("p= is not base64")
}

pub struct Prepared {
    pub input: GuestInput,
    /// What the guest will commit, computed on the host.
    pub expected: PublicValues,
}

/// The guest input plus the values the guest will commit.
pub async fn prepare(
    raw: &[u8],
    keys: &KeySource,
    table: &[PinnedKey],
    wallet: [u8; 20],
    disclose: bool,
) -> Result<Prepared> {
    let input = guest_input(raw, keys, wallet, disclose).await?;
    let expected =
        verify_with(&input, table).map_err(|e| anyhow!("guest check would fail: {e}"))?;
    Ok(Prepared { input, expected })
}

/// The guest input for the platform signature, without running the guest's checks.
pub async fn guest_input(
    raw: &[u8],
    keys: &KeySource,
    wallet: [u8; 20],
    disclose: bool,
) -> Result<GuestInput> {
    let raw = normalize_crlf(raw);
    let report = analyze(&raw, keys).await?;
    let sig = report
        .selected
        .map(|i| &report.signatures[i])
        .ok_or_else(|| anyhow!("{}", rejection(&report)))?;
    let tags = sig.tags.as_ref().map_err(|e| anyhow!("{e}"))?;
    let key = sig.key.as_ref().map_err(|e| anyhow!("{e}"))?;
    let (header_c, body_c) = canon::parse_c(&tags.c).context("unsupported c=")?;

    let (headers, body) = canon::split_message(&raw).context("cannot split headers and body")?;
    let dkim = find_dkim(&headers, tags)?;
    // The signature being verified is never one of its own signed headers (§3.7).
    let others: Vec<RawHeader> = headers
        .iter()
        .filter(|h| !std::ptr::eq(*h, dkim))
        .cloned()
        .collect();
    Ok(GuestInput {
        headers: canon::signed_headers(header_c, &others, &tags.h, dkim),
        body: canon::body(body_c, body),
        signature: B64.decode(&tags.b).context("b= is not base64")?,
        public_key_der: key_der(&key.record)?,
        wallet,
        disclose,
    })
}

fn find_dkim<'a>(headers: &'a [RawHeader], want: &DkimTags) -> Result<&'a RawHeader> {
    let mut matches = headers.iter().filter(|h| {
        h.name.trim().eq_ignore_ascii_case("dkim-signature")
            && DkimTags::parse(&h.value).is_ok_and(|t| t == *want)
    });
    match (matches.next(), matches.next()) {
        (Some(h), None) => Ok(h),
        (None, _) => bail!("selected DKIM-Signature not found"),
        _ => bail!("selected DKIM-Signature appears twice"),
    }
}

/// Why no signature was usable, in words a user can act on (no email content is included).
pub fn rejection(report: &crate::discover::Report) -> String {
    let Some(sig) = report.signatures.iter().find(|s| s.platform().is_some()) else {
        return if report.signatures.is_empty() {
            "the email has no DKIM signature".into()
        } else {
            "not signed by Coursera or Udemy (unsupported sender, or a forwarded email)".into()
        };
    };
    if let Some((check, _)) = sig.checks.iter().find(|(_, ok)| !ok) {
        return format!("Coursera/Udemy signature rejected: {check} failed");
    }
    if let Err(e) = &sig.key {
        if e.starts_with("no pinned key") {
            return "the signing key is not one zkCert accepts (no record in config/dkim-keys.json)".into();
        }
        return format!("signing key not accepted: {e}");
    }
    let detail = match sig.host_verify.as_str() {
        v if v.contains("BodyHash") || v.contains("FailedBodyHash") => "the body was modified",
        v if v.contains("Signature") || v.contains("FailedVerification") => {
            "the headers were modified"
        }
        v => v,
    };
    format!("DKIM signature invalid: {detail}")
}
