//! The whole proof statement.

use std::fmt;

use alloy_sol_types::private::{Address, FixedBytes};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rsa::{pkcs8::DecodePublicKey, traits::PublicKeyParts, Pkcs1v15Sign, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher, Keccak};

use crate::{
    dkim::DkimTags,
    keys::{PinnedKey, KEYS},
    mime,
    platform::{coursera, normalize_ws, udemy, Platform},
    PublicValues,
};

/// Domain separator for nullifiers, so they never collide with another protocol's hashes.
pub const NULLIFIER_DOMAIN: &[u8] = b"zkcert-v1";

const DAY: u64 = 86_400;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuestInput {
    /// RFC 6376 §3.7 header hash input: canonical signed headers, then the DKIM-Signature header
    /// with an empty `b=` and no trailing CRLF.
    pub headers: Vec<u8>,
    /// Canonical body (§3.4.3 / §3.4.4).
    pub body: Vec<u8>,
    /// The decoded `b=` value.
    pub signature: Vec<u8>,
    /// The key from `p=`: DER SubjectPublicKeyInfo.
    pub public_key_der: Vec<u8>,
    /// The wallet the proof is bound to.
    pub wallet: [u8; 20],
    /// Reveal the course name in the public values (the hash is always public).
    pub disclose: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    Malformed(&'static str),
    BadTags(String),
    Unsupported(&'static str),
    LengthTag,
    HeaderNotSigned(&'static str),
    HeaderCount(&'static str),
    BodyHash,
    Key(&'static str),
    /// The key is not in the pinned table for the signing domain's platform.
    UnknownKey,
    /// The signed `t=` is outside the key's validity window (or absent for a bounded key).
    KeyWindow,
    Signature,
    FromDomain,
    NotCertificateEmail,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::Malformed(w) => write!(f, "malformed input: {w}"),
            VerifyError::BadTags(e) => write!(f, "invalid DKIM-Signature: {e}"),
            VerifyError::Unsupported(w) => write!(f, "unsupported: {w}"),
            VerifyError::LengthTag => write!(f, "l= tag present (body could be extended)"),
            VerifyError::HeaderNotSigned(h) => write!(f, "h= does not sign {h}"),
            VerifyError::HeaderCount(h) => write!(f, "expected exactly one signed {h} header"),
            VerifyError::BodyHash => write!(f, "body hash does not match bh= (body edited)"),
            VerifyError::Key(w) => write!(f, "public key: {w}"),
            VerifyError::UnknownKey => write!(f, "DKIM key is not on the zkCert key table"),
            VerifyError::KeyWindow => {
                write!(f, "signing time t= is outside the key's validity window")
            }
            VerifyError::Signature => {
                write!(f, "RSA signature invalid (headers edited or wrong key)")
            }
            VerifyError::FromDomain => {
                write!(f, "From domain does not belong to the signing platform")
            }
            VerifyError::NotCertificateEmail => write!(f, "not a recognised certificate email"),
        }
    }
}

impl std::error::Error for VerifyError {}

pub fn keccak(parts: &[&[u8]]) -> [u8; 32] {
    let mut k = Keccak::v256();
    for p in parts {
        k.update(p);
    }
    let mut out = [0u8; 32];
    k.finalize(&mut out);
    out
}

/// The address inside a From/To value: `Name <a@b>` or bare `a@b`. Exactly one mailbox.
pub fn single_address(value: &str) -> Option<String> {
    let addr = match (value.find('<'), value.rfind('>')) {
        (Some(l), Some(r)) if l < r && value.matches('<').count() == 1 => &value[l + 1..r],
        (None, None) => value,
        _ => return None,
    };
    let addr = addr.trim();
    let (local, domain) = addr.split_once('@')?;
    let ok = !local.is_empty()
        && !domain.is_empty()
        && !domain.contains('@')
        && !addr.contains([',', ' ', '\t', '<', '>', ';']);
    ok.then(|| addr.to_string())
}

/// `keccak("zkcert-v1", platform, courseHash, keccak(lowercase To))`.
pub fn nullifier(platform: u8, course_hash: &[u8; 32], to_addr: &str) -> [u8; 32] {
    keccak(&[
        NULLIFIER_DOMAIN,
        &[platform],
        course_hash,
        &keccak(&[to_addr.to_ascii_lowercase().as_bytes()]),
    ])
}

/// The proof statement with the production key table.
pub fn verify(input: &GuestInput) -> Result<PublicValues, VerifyError> {
    verify_with(input, KEYS)
}

/// The proof statement against `keys`. Only tests pass anything but [`KEYS`]; the guest cannot.
pub fn verify_with(input: &GuestInput, keys: &[PinnedKey]) -> Result<PublicValues, VerifyError> {
    // 1. The DKIM-Signature header is the last field of the hash input (§3.7).
    let blob = std::str::from_utf8(&input.headers)
        .map_err(|_| VerifyError::Malformed("headers not UTF-8"))?;
    let fields = mime::header_fields(blob).ok_or(VerifyError::Malformed("header blob"))?;
    let (last, signed) = fields
        .split_last()
        .ok_or(VerifyError::Malformed("no headers"))?;
    if last.0 != "dkim-signature" {
        return Err(VerifyError::Malformed("last header is not DKIM-Signature"));
    }
    let tags = DkimTags::parse(&last.1).map_err(|e| VerifyError::BadTags(e.to_string()))?;
    if !tags.b.is_empty() {
        return Err(VerifyError::Malformed("b= not emptied in hash input"));
    }

    // 2. Tag policy.
    if tags.v != "1" {
        return Err(VerifyError::Unsupported("v= must be 1"));
    }
    if !tags.a.eq_ignore_ascii_case("rsa-sha256") {
        return Err(VerifyError::Unsupported("a= must be rsa-sha256"));
    }
    if crate::canon::parse_c(&tags.c).is_none() {
        return Err(VerifyError::Unsupported("c= canonicalization"));
    }
    if tags.l.is_some() {
        return Err(VerifyError::LengthTag);
    }
    if let (Some(t), Some(x)) = (tags.t, tags.x) {
        // §3.5: x= must be greater than t=.
        if x <= t {
            return Err(VerifyError::Unsupported("x= not after t="));
        }
    }
    let platform = Platform::from_domain(&tags.d)
        .ok_or(VerifyError::Unsupported("d= is not a supported platform"))?;
    if let Some(i) = &tags.i {
        // §3.5: i= must be d= or a subdomain of it.
        let idom = i
            .rsplit_once('@')
            .map_or("", |(_, d)| d)
            .to_ascii_lowercase();
        let d = tags.d.to_ascii_lowercase();
        if !(idom == d || idom.ends_with(&format!(".{d}"))) {
            return Err(VerifyError::Unsupported("i= outside d="));
        }
    }
    for h in ["from", "subject", "to"] {
        if !tags.signs_header(h) {
            return Err(VerifyError::HeaderNotSigned(h));
        }
    }
    // Defence in depth: the blob's fields must appear in h= order (§5.4.2).
    let mut h = tags.h.iter();
    for (name, _) in signed {
        if !h.any(|x| x == name) {
            return Err(VerifyError::Malformed("signed fields do not follow h="));
        }
    }
    let one = |name: &'static str| -> Result<&str, VerifyError> {
        let mut it = signed.iter().filter(|(n, _)| n == name);
        match (it.next(), it.next()) {
            (Some((_, v)), None) => Ok(v.as_str()),
            _ => Err(VerifyError::HeaderCount(name)),
        }
    };
    let from = one("from")?;
    let subject = one("subject")?;
    let to = one("to")?;

    // 3. Body hash.
    let bh = B64
        .decode(&tags.bh)
        .map_err(|_| VerifyError::BadTags("bh= not base64".into()))?;
    if Sha256::digest(&input.body)[..] != bh[..] {
        return Err(VerifyError::BodyHash);
    }

    // 4. The key is pinned for this platform, and the signing time is inside its window.
    let key_hash = keccak(&[&input.public_key_der]);
    let pinned = keys
        .iter()
        .find(|k| k.key_hash == key_hash && k.platform == platform as u8)
        .ok_or(VerifyError::UnknownKey)?;
    if !pinned.accepts_time(tags.t) {
        return Err(VerifyError::KeyWindow);
    }

    // 5. RSA PKCS#1 v1.5 over SHA-256 of the header hash input.
    let key = RsaPublicKey::from_public_key_der(&input.public_key_der)
        .map_err(|_| VerifyError::Key("not an RSA SPKI DER"))?;
    if key.n().bits() < 1024 {
        return Err(VerifyError::Key("shorter than 1024 bits (RFC 8301)"));
    }
    let digest = Sha256::digest(&input.headers);
    key.verify(Pkcs1v15Sign::new::<Sha256>(), &digest, &input.signature)
        .map_err(|_| VerifyError::Signature)?;

    // 6. The signed From belongs to the same platform as d=.
    let from_addr = single_address(from).ok_or(VerifyError::HeaderCount("from mailbox"))?;
    let from_domain = from_addr.rsplit_once('@').map_or("", |(_, d)| d);
    if Platform::from_domain(from_domain) != Some(platform) {
        return Err(VerifyError::FromDomain);
    }

    // 7. Platform parser.
    let subject = mime::decode_words(subject).ok_or(VerifyError::Malformed("subject encoding"))?;
    let course = match platform {
        Platform::Coursera => {
            // Cheap rejection before MIME parsing: the subject must be a known template's.
            let subject = normalize_ws(&subject);
            if !coursera::TEMPLATES.iter().any(|t| t.subject == subject) {
                return Err(VerifyError::NotCertificateEmail);
            }
            let ctype =
                one("content-type").map_err(|_| VerifyError::HeaderNotSigned("content-type"))?;
            let boundary =
                mime::param(ctype, "boundary").ok_or(VerifyError::NotCertificateEmail)?;
            let text = mime::text_plain_part(&input.body, &boundary)
                .ok_or(VerifyError::NotCertificateEmail)?;
            coursera::parse(coursera::TEMPLATES, &subject, &text)
                .ok_or(VerifyError::NotCertificateEmail)?
                .course_name
        }
        Platform::Udemy => {
            udemy::parse_subject(&subject).ok_or(VerifyError::NotCertificateEmail)?
        }
    };

    // 8. Public values.
    let to_addr = single_address(to).ok_or(VerifyError::HeaderCount("to mailbox"))?;
    let course_hash = keccak(&[course.as_bytes()]);
    let nullifier = nullifier(platform as u8, &course_hash, &to_addr);
    Ok(PublicValues {
        platform: platform as u8,
        courseHash: FixedBytes(course_hash),
        courseName: if input.disclose {
            course
        } else {
            String::new()
        },
        // When the platform signed the email, not when the course was finished.
        emailSignedAt: tags.t.map_or(0, |t| t - t % DAY),
        dkimKeyHash: FixedBytes(key_hash),
        nullifier: FixedBytes(nullifier),
        wallet: Address::from(input.wallet),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nullifier_test_vector() {
        // Fixed across program versions; changing it would let a certificate be claimed again.
        let n = nullifier(1, &keccak(&[b"Machine Learning"]), "Some.One@Example.com");
        assert_eq!(
            n,
            nullifier(1, &keccak(&[b"Machine Learning"]), "some.one@example.com")
        );
        assert_eq!(
            n.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "5be87e49d5740a1cce2f4e77ff9c8ab1d0a62f17cec40952591a955f87336b6b"
        );
    }

    #[test]
    fn addresses() {
        assert_eq!(
            single_address("Udemy <no-reply@e.udemymail.com>").unwrap(),
            "no-reply@e.udemymail.com"
        );
        assert_eq!(single_address("a@b.org").unwrap(), "a@b.org");
        assert_eq!(single_address("a@b.org, c@d.org"), None);
        assert_eq!(single_address("X <a@b.org>, Y <c@d.org>"), None);
        assert_eq!(single_address("no address"), None);
    }
}
