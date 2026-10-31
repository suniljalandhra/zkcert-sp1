//! DKIM canonicalization and signed-header selection (RFC 6376 §3.4, §3.7, §5.4.2).

/// A header field as it appears in the message: name, and raw value after the ':' (folding kept,
/// final CRLF removed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Canon {
    Simple,
    Relaxed,
}

/// Parses `c=` (§3.5): "header/body", the body part defaulting to simple.
pub fn parse_c(c: &str) -> Option<(Canon, Canon)> {
    let one = |s: &str| match s {
        "simple" => Some(Canon::Simple),
        "relaxed" => Some(Canon::Relaxed),
        _ => None,
    };
    match c.split_once('/') {
        Some((h, b)) => Some((one(h)?, one(b)?)),
        None => Some((one(c)?, Canon::Simple)),
    }
}

/// Splits a message into header fields and body at the first empty line.
pub fn split_message(raw: &[u8]) -> Option<(Vec<RawHeader>, &[u8])> {
    let end = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&raw[..end]).ok()?;
    let body = &raw[end + 4..];
    let mut headers: Vec<RawHeader> = Vec::new();
    for line in head.split("\r\n") {
        if line.starts_with([' ', '\t']) {
            // Continuation of a folded header (RFC 5322 §2.2.3).
            let last = headers.last_mut()?;
            last.value.push_str("\r\n");
            last.value.push_str(line);
        } else {
            let (name, value) = line.split_once(':')?;
            headers.push(RawHeader {
                name: name.to_string(),
                value: value.to_string(),
            });
        }
    }
    Some((headers, body))
}

fn is_wsp(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

/// §3.4.2 relaxed header: lowercase name, unfold, collapse WSP runs to one SP, trim the value.
fn relaxed_header(name: &str, value: &str, out: &mut Vec<u8>) {
    out.extend(
        name.trim_end_matches([' ', '\t'])
            .to_ascii_lowercase()
            .bytes(),
    );
    out.push(b':');
    let unfolded: Vec<u8> = value
        .bytes()
        .filter(|&b| b != b'\r' && b != b'\n')
        .collect();
    let mut pending_space = false;
    let mut started = false;
    for b in unfolded {
        if is_wsp(b) {
            pending_space = started;
        } else {
            if pending_space {
                out.push(b' ');
                pending_space = false;
            }
            out.push(b);
            started = true;
        }
    }
}

fn canon_header(c: Canon, h: &RawHeader, out: &mut Vec<u8>) {
    match c {
        Canon::Simple => {
            out.extend(h.name.bytes());
            out.push(b':');
            out.extend(h.value.bytes());
        }
        Canon::Relaxed => relaxed_header(&h.name, &h.value, out),
    }
}

/// Removes the `b=` tag's value (§3.5 "b=": hashed as the empty string), keeping all other bytes.
pub fn strip_b(dkim_value: &str) -> String {
    dkim_value
        .split(';')
        .map(|spec| match spec.split_once('=') {
            Some((name, _)) if name.trim_matches([' ', '\t', '\r', '\n']) == "b" => {
                format!("{name}=")
            }
            _ => spec.to_string(),
        })
        .collect::<Vec<_>>()
        .join(";")
}

/// The header hash input (§3.7): each header named in `h=`, taken bottom-up so repeated names
/// consume successive instances and missing ones are skipped (§5.4.2), then the DKIM-Signature
/// header itself with `b=` emptied and no trailing CRLF.
pub fn signed_headers(c: Canon, headers: &[RawHeader], h: &[String], dkim: &RawHeader) -> Vec<u8> {
    let mut used = vec![false; headers.len()];
    let mut out = Vec::new();
    for name in h {
        let pick = (0..headers.len())
            .rev()
            .find(|&i| !used[i] && headers[i].name.trim().eq_ignore_ascii_case(name));
        if let Some(i) = pick {
            used[i] = true;
            canon_header(c, &headers[i], &mut out);
            out.extend(b"\r\n");
        }
    }
    let stripped = RawHeader {
        name: dkim.name.clone(),
        value: strip_b(&dkim.value),
    };
    canon_header(c, &stripped, &mut out);
    out
}

/// §3.4.3 simple / §3.4.4 relaxed body canonicalization.
pub fn body(c: Canon, body: &[u8]) -> Vec<u8> {
    let mut lines: Vec<Vec<u8>> = Vec::new();
    let mut rest = body;
    while !rest.is_empty() {
        let (line, next) = match rest.windows(2).position(|w| w == b"\r\n") {
            Some(i) => (&rest[..i], &rest[i + 2..]),
            None => (rest, &rest[rest.len()..]),
        };
        lines.push(match c {
            Canon::Simple => line.to_vec(),
            Canon::Relaxed => {
                let mut l = Vec::with_capacity(line.len());
                let mut ws = false;
                for &b in line {
                    if is_wsp(b) {
                        ws = true;
                    } else {
                        if ws {
                            l.push(b' ');
                        }
                        ws = false;
                        l.push(b);
                    }
                }
                l
            }
        });
        rest = next;
    }
    while lines.last().is_some_and(|l| l.is_empty()) {
        lines.pop();
    }
    let mut out = Vec::with_capacity(body.len());
    for l in &lines {
        out.extend(l);
        out.extend(b"\r\n");
    }
    // Simple: an empty body canonicalizes to a single CRLF. Relaxed: to nothing (RFC 6376 erratum 1384).
    if out.is_empty() && c == Canon::Simple {
        out.extend(b"\r\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6376 §3.4.5 example.
    const MSG: &[u8] = b"A: X\r\nB : Y\t\r\n\tZ  \r\n\r\n C \r\nD \t E\r\n\r\n\r\n";

    #[test]
    fn rfc_example_relaxed() {
        let (hs, b) = split_message(MSG).unwrap();
        let mut out = Vec::new();
        for h in &hs {
            canon_header(Canon::Relaxed, h, &mut out);
            out.extend(b"\r\n");
        }
        assert_eq!(out, b"a:X\r\nb:Y Z\r\n");
        assert_eq!(body(Canon::Relaxed, b), b" C\r\nD E\r\n");
    }

    #[test]
    fn rfc_example_simple() {
        let (hs, b) = split_message(MSG).unwrap();
        let mut out = Vec::new();
        for h in &hs {
            canon_header(Canon::Simple, h, &mut out);
            out.extend(b"\r\n");
        }
        assert_eq!(out, b"A: X\r\nB : Y\t\r\n\tZ  \r\n");
        assert_eq!(body(Canon::Simple, b), b" C \r\nD \t E\r\n");
    }

    #[test]
    fn empty_bodies() {
        assert_eq!(body(Canon::Simple, b""), b"\r\n");
        assert_eq!(body(Canon::Relaxed, b"\r\n\r\n"), b"");
    }

    #[test]
    fn strips_only_b() {
        assert_eq!(
            strip_b(" v=1; bh=abc;\r\n\tb=ZZ\r\n\t ZZ; d=x"),
            " v=1; bh=abc;\r\n\tb=; d=x"
        );
    }

    #[test]
    fn bottom_up_selection() {
        let raw = b"From: a@x\r\nSubject: s\r\nFrom: b@x\r\nDKIM-Signature: v=1; b=Q\r\n\r\n";
        let (hs, _) = split_message(raw).unwrap();
        let h = vec!["from".to_string(), "from".into(), "from".into()];
        let out = signed_headers(Canon::Relaxed, &hs[..3], &h, &hs[3]);
        assert_eq!(out, b"from:b@x\r\nfrom:a@x\r\ndkim-signature:v=1; b=");
    }

    #[test]
    fn parses_c() {
        assert_eq!(parse_c("relaxed"), Some((Canon::Relaxed, Canon::Simple)));
        assert_eq!(
            parse_c("simple/relaxed"),
            Some((Canon::Simple, Canon::Relaxed))
        );
        assert_eq!(parse_c("relaxed/fancy"), None);
    }
}
