//! DKIM-Signature tag parsing (RFC 6376 §3.2 tag-list, §3.5 signature tags).
//!
//! Pure Rust with no dependencies so the same code runs on the host and in the SP1 guest.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TagError {
    /// A tag-spec without `=` (RFC 6376 §3.2: `tag-spec = [FWS] tag-name [FWS] "=" ...`).
    MissingEquals(String),
    /// tag-name must be `ALPHA *ALNUMPUNC` (ALNUMPUNC = ALPHA / DIGIT / "_").
    InvalidTagName(String),
    /// RFC 6376 §3.2: "if a tag name does occur more than once, the entire tag-list is invalid".
    DuplicateTag(String),
    /// A required tag (§3.5: v, a, b, bh, d, h, s) is absent.
    MissingTag(&'static str),
    /// A numeric tag (l, t, x) is not a decimal integer.
    InvalidNumber(&'static str),
    /// A tag value contains a character outside VALCHAR / FWS.
    InvalidValue(String),
}

impl fmt::Display for TagError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TagError::MissingEquals(s) => write!(f, "tag-spec without '=': {s:?}"),
            TagError::InvalidTagName(s) => write!(f, "invalid tag name: {s:?}"),
            TagError::DuplicateTag(s) => write!(f, "duplicate tag: {s}"),
            TagError::MissingTag(s) => write!(f, "missing required tag: {s}"),
            TagError::InvalidNumber(s) => write!(f, "tag {s} is not a number"),
            TagError::InvalidValue(s) => write!(f, "tag {s} has an invalid character"),
        }
    }
}

impl std::error::Error for TagError {}

/// FWS characters (RFC 6376 §2.8: WSP and CRLF). Deliberately not Unicode whitespace, so the
/// host and the guest can never disagree on what is stripped.
fn is_fws(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\r' | '\n')
}

fn trim_fws(s: &str) -> &str {
    s.trim_matches(is_fws)
}

/// Splits a tag-list into `(name, value)` pairs with surrounding FWS trimmed.
/// Values keep their inner FWS; callers strip it where the RFC says to ignore it.
/// Values may only contain VALCHAR (%x21-3A / %x3C-7E) and FWS (§3.2 tval).
pub fn parse_tag_list(input: &str) -> Result<Vec<(String, String)>, TagError> {
    let mut tags: Vec<(String, String)> = Vec::new();
    for spec in input.split(';') {
        // A trailing ";" is allowed, which yields one empty final spec.
        if trim_fws(spec).is_empty() {
            continue;
        }
        let (name, value) = spec
            .split_once('=')
            .ok_or_else(|| TagError::MissingEquals(trim_fws(spec).to_string()))?;
        let name = trim_fws(name);
        let mut chars = name.chars();
        let valid = chars.next().is_some_and(|c| c.is_ascii_alphabetic())
            && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !valid {
            return Err(TagError::InvalidTagName(name.to_string()));
        }
        if tags.iter().any(|(n, _)| n == name) {
            return Err(TagError::DuplicateTag(name.to_string()));
        }
        let value = trim_fws(value);
        if !value
            .chars()
            .all(|c| is_fws(c) || matches!(c, '\x21'..='\x3a' | '\x3c'..='\x7e'))
        {
            return Err(TagError::InvalidValue(name.to_string()));
        }
        tags.push((name.to_string(), value.to_string()));
    }
    Ok(tags)
}

fn strip_ws(s: &str) -> String {
    s.chars().filter(|c| !is_fws(*c)).collect()
}

/// The DKIM-Signature tags zkCert inspects. `b`, `bh` and `h` have whitespace removed
/// (§3.5: whitespace in b= and bh= is ignored; h= allows FWS around ':').
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DkimTags {
    pub v: String,
    pub a: String,
    /// `c=` as written; defaults to "simple/simple" when absent (§3.5).
    pub c: String,
    pub d: String,
    pub s: String,
    /// Signed header names, lowercased (header names are case-insensitive, RFC 5322 §1.2.2).
    pub h: Vec<String>,
    pub bh: String,
    pub b: String,
    pub i: Option<String>,
    /// Body length limit. Its presence alone lets an attacker append content (§8.2).
    pub l: Option<u64>,
    pub t: Option<u64>,
    pub x: Option<u64>,
}

impl DkimTags {
    /// Parses the value of a DKIM-Signature header (everything after "DKIM-Signature:").
    pub fn parse(header_value: &str) -> Result<Self, TagError> {
        let tags = parse_tag_list(header_value)?;
        let get = |k: &str| tags.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        let req = |k: &'static str| get(k).ok_or(TagError::MissingTag(k));
        let num = |k: &'static str| -> Result<Option<u64>, TagError> {
            get(k)
                .map(|v| strip_ws(&v).parse().map_err(|_| TagError::InvalidNumber(k)))
                .transpose()
        };
        Ok(DkimTags {
            v: req("v")?,
            a: req("a")?,
            c: get("c").unwrap_or_else(|| "simple/simple".into()),
            d: req("d")?,
            s: req("s")?,
            h: strip_ws(&req("h")?)
                .split(':')
                .filter(|n| !n.is_empty())
                .map(|n| n.to_ascii_lowercase())
                .collect(),
            bh: strip_ws(&req("bh")?),
            b: strip_ws(&req("b")?),
            i: get("i"),
            l: num("l")?,
            t: num("t")?,
            x: num("x")?,
        })
    }

    pub fn signs_header(&self, name: &str) -> bool {
        self.h.iter().any(|h| h.eq_ignore_ascii_case(name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const COURSERA_LIKE: &str = "v=1; a=rsa-sha256; c=relaxed/relaxed; d=t.mail.coursera.org;\r\n\
        \ts=scph0616; t=1598137023; i=@t.mail.coursera.org;\r\n\
        \tbh=QJvcKSsOZocLkXoPnbF9sCea568BXhxRgbxlkHmq9bs=;\r\n\
        \th=To:Message-ID:Date:Content-Type:Subject:\r\n\t From;\r\n\
        \tb=N4OLYDPt\r\n\t Y5yM=";

    #[test]
    fn parses_folded_signature() {
        let t = DkimTags::parse(COURSERA_LIKE).unwrap();
        assert_eq!(t.a, "rsa-sha256");
        assert_eq!(t.d, "t.mail.coursera.org");
        assert_eq!(t.s, "scph0616");
        assert_eq!(
            t.h,
            [
                "to",
                "message-id",
                "date",
                "content-type",
                "subject",
                "from"
            ]
        );
        assert_eq!(t.b, "N4OLYDPtY5yM=");
        assert_eq!(t.t, Some(1598137023));
        assert_eq!(t.l, None);
        assert!(t.signs_header("From") && t.signs_header("subject"));
    }

    #[test]
    fn detects_l_tag_even_when_zero() {
        let t = DkimTags::parse(&format!("{COURSERA_LIKE}; l=0")).unwrap();
        assert_eq!(t.l, Some(0));
    }

    #[test]
    fn rejects_duplicate_tag() {
        let err = DkimTags::parse(&format!("{COURSERA_LIKE}; d=evil.com")).unwrap_err();
        assert_eq!(err, TagError::DuplicateTag("d".into()));
    }

    #[test]
    fn rejects_missing_required_tag() {
        let err = DkimTags::parse("v=1; a=rsa-sha256; d=x.org; s=s; h=from; b=AA==").unwrap_err();
        assert_eq!(err, TagError::MissingTag("bh"));
    }

    #[test]
    fn rejects_bad_tag_name_and_missing_equals() {
        assert!(matches!(
            parse_tag_list("1a=x"),
            Err(TagError::InvalidTagName(_))
        ));
        assert!(matches!(
            parse_tag_list("v=1; junk"),
            Err(TagError::MissingEquals(_))
        ));
    }

    #[test]
    fn rejects_non_numeric_l() {
        let err = DkimTags::parse(&format!("{COURSERA_LIKE}; l=12a")).unwrap_err();
        assert_eq!(err, TagError::InvalidNumber("l"));
    }

    #[test]
    fn rejects_non_valchar_value() {
        // U+00A0 is Unicode whitespace but not FWS, so it must not be silently stripped.
        let err = parse_tag_list("d=coursera.org\u{a0}").unwrap_err();
        assert_eq!(err, TagError::InvalidValue("d".into()));
    }

    #[test]
    fn defaults_canonicalization() {
        let t = DkimTags::parse("v=1;a=rsa-sha256;d=x.org;s=s;h=from;bh=AA==;b=AA==").unwrap();
        assert_eq!(t.c, "simple/simple");
    }
}
