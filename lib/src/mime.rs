//! Minimal MIME decoding for the guest: header lines of the signed-header blob, quoted-printable
//! (RFC 2045 §6.7), encoded words (RFC 2047), and multipart part selection (RFC 2046 §5.1).
//!
//! Only what Coursera and Udemy completion emails need. Anything unexpected is an error, never a
//! best-effort guess.

use base64::{engine::general_purpose::STANDARD as B64, Engine};

/// Splits a signed-header blob (canonicalized, CRLF-separated, last line without CRLF) into
/// `(lowercase name, value trimmed of FWS)`. Lines starting with WSP continue the previous field,
/// so a header value can never be mistaken for a new field.
pub fn header_fields(blob: &str) -> Option<Vec<(String, String)>> {
    let mut out: Vec<(String, String)> = Vec::new();
    for line in blob.split("\r\n") {
        if line.starts_with([' ', '\t']) {
            out.last_mut()?.1.push_str(line);
        } else {
            let (name, value) = line.split_once(':')?;
            out.push((name.trim().to_ascii_lowercase(), value.to_string()));
        }
    }
    for (_, v) in &mut out {
        *v = v.trim_matches([' ', '\t']).to_string();
    }
    Some(out)
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'A'..=b'F' => Some(b - b'A' + 10),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

/// Quoted-printable decoding. `=` + CRLF is a soft line break; `=XX` is a byte; a lone `=` is an error.
pub fn qp_decode(input: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] != b'=' {
            out.push(input[i]);
            i += 1;
        } else if input[i + 1..].starts_with(b"\r\n") {
            i += 3;
        } else {
            let hi = hex(*input.get(i + 1)?)?;
            let lo = hex(*input.get(i + 2)?)?;
            out.push(hi << 4 | lo);
            i += 3;
        }
    }
    Some(out)
}

/// Decodes RFC 2047 encoded words (UTF-8 or US-ASCII, B or Q). Whitespace between two adjacent
/// encoded words is dropped (§6.2). Text without encoded words is returned unchanged.
pub fn decode_words(value: &str) -> Option<String> {
    let mut out = String::new();
    let mut rest = value;
    let mut gap = String::new();
    let mut prev_encoded = false;
    while !rest.is_empty() {
        if let Some(word) = rest.strip_prefix("=?") {
            let (charset, word) = word.split_once('?')?;
            let (enc, word) = word.split_once('?')?;
            let (text, after) = word.split_once("?=")?;
            let cs = charset.to_ascii_lowercase();
            if cs != "utf-8" && cs != "us-ascii" {
                return None;
            }
            let bytes = match enc {
                "B" | "b" => B64.decode(text).ok()?,
                "Q" | "q" => qp_decode(text.replace('_', " ").as_bytes())?,
                _ => return None,
            };
            if !prev_encoded {
                out.push_str(&gap);
            }
            gap.clear();
            out.push_str(std::str::from_utf8(&bytes).ok()?);
            prev_encoded = true;
            rest = after;
        } else {
            let c = rest.chars().next()?;
            rest = &rest[c.len_utf8()..];
            if c == ' ' || c == '\t' {
                gap.push(c);
            } else {
                out.push_str(&gap);
                gap.clear();
                out.push(c);
                prev_encoded = false;
            }
        }
    }
    out.push_str(&gap);
    Some(out)
}

/// A `name=value` parameter of a structured header such as Content-Type (RFC 2045 §5.1).
pub fn param(value: &str, name: &str) -> Option<String> {
    value.split(';').skip(1).find_map(|p| {
        let (k, v) = p.split_once('=')?;
        k.trim()
            .eq_ignore_ascii_case(name)
            .then(|| v.trim().trim_matches('"').to_string())
    })
}

/// The decoded content of the single `text/plain` part of a multipart body. Errors if there are
/// zero or several such parts, or the part uses an encoding we do not handle.
pub fn text_plain_part(body: &[u8], boundary: &str) -> Option<String> {
    if boundary.is_empty() {
        return None;
    }
    let delim = format!("\r\n--{boundary}");
    let mut padded = b"\r\n".to_vec();
    padded.extend_from_slice(body);
    let mut parts = Vec::new();
    let mut rest = &padded[..];
    while let Some(i) = find(rest, delim.as_bytes()) {
        parts.push(&rest[..i]);
        rest = &rest[i + delim.len()..];
    }
    // parts[0] is the preamble; a part after the close delimiter ("--") is the epilogue.
    let mut found = None;
    for part in parts.iter().skip(1) {
        let part = part.strip_prefix(b"\r\n")?;
        // A part with no header fields starts with the blank line (RFC 2046 §5.1.1).
        let (head, content) = match part.strip_prefix(b"\r\n") {
            Some(content) => ("", content),
            None => {
                let split = find(part, b"\r\n\r\n")?;
                (
                    std::str::from_utf8(&part[..split]).ok()?,
                    &part[split + 4..],
                )
            }
        };
        let fields = if head.is_empty() {
            Vec::new()
        } else {
            header_fields(head)?
        };
        let get = |n: &str| fields.iter().find(|(k, _)| k == n).map(|(_, v)| v.as_str());
        let ctype = get("content-type").unwrap_or("text/plain");
        let mime = ctype.split(';').next()?.trim().to_ascii_lowercase();
        if mime != "text/plain" {
            continue;
        }
        if found.is_some() {
            return None;
        }
        let charset = param(ctype, "charset").unwrap_or_else(|| "us-ascii".into());
        if !charset.eq_ignore_ascii_case("utf-8") && !charset.eq_ignore_ascii_case("us-ascii") {
            return None;
        }
        let bytes = match get("content-transfer-encoding")
            .unwrap_or("7bit")
            .to_ascii_lowercase()
            .as_str()
        {
            "quoted-printable" => qp_decode(content)?,
            "7bit" | "8bit" => content.to_vec(),
            _ => return None,
        };
        found = Some(String::from_utf8(bytes).ok()?);
    }
    found
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qp() {
        assert_eq!(
            qp_decode(b"You=E2=80=99ve a=\r\nb =3D").unwrap(),
            "You\u{2019}ve ab =".as_bytes()
        );
        assert_eq!(qp_decode(b"bad =ZZ"), None);
        assert_eq!(qp_decode(b"trailing ="), None);
    }

    #[test]
    fn encoded_words() {
        assert_eq!(decode_words("plain \"Tally\"").unwrap(), "plain \"Tally\"");
        assert_eq!(
            decode_words("=?UTF-8?B?Q2Fmw6k=?= =?utf-8?Q?_x?= end").unwrap(),
            "Caf\u{e9} x end"
        );
        assert_eq!(decode_words("=?iso-8859-1?Q?x?="), None);
    }

    #[test]
    fn header_fields_unfold() {
        let f = header_fields("from:A <a@x>\r\nsubject:Hi\r\n there\r\ndkim-signature:v=1; b=")
            .unwrap();
        assert_eq!(f[1], ("subject".into(), "Hi there".into()));
        assert_eq!(f[2].0, "dkim-signature");
    }

    const MP: &[u8] = b"pre\r\n--B\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nH=C3=A9llo\r\n--B\r\nContent-Type: text/html\r\n\r\n<p>x</p>\r\n--B--\r\n";

    #[test]
    fn picks_text_plain() {
        assert_eq!(text_plain_part(MP, "B").unwrap(), "H\u{e9}llo");
    }

    #[test]
    fn rejects_two_text_parts() {
        let two = [
            MP.strip_suffix(b"--B--\r\n").unwrap(),
            b"--B\r\nContent-Type: text/plain\r\n\r\nsecond\r\n--B--\r\n",
        ]
        .concat();
        assert_eq!(text_plain_part(&two, "B"), None);
        // A headerless part defaults to text/plain, so it also counts as a second one.
        let headerless = [
            MP.strip_suffix(b"--B--\r\n").unwrap(),
            b"--B\r\n\r\nsecond\r\n--B--\r\n",
        ]
        .concat();
        assert_eq!(text_plain_part(&headerless, "B"), None);
        assert_eq!(
            text_plain_part(b"--B\r\n\r\nonly\r\n--B--\r\n", "B").unwrap(),
            "only"
        );
        assert_eq!(text_plain_part(&two, "B"), None);
    }

    #[test]
    fn content_type_param() {
        assert_eq!(
            param("multipart/alternative; boundary=\"=_x\"", "boundary").unwrap(),
            "=_x"
        );
    }
}
