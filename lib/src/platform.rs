//! Supported platforms and their body parsers.

/// Matches `PublicValues.platform` (1 = coursera, 2 = udemy).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Platform {
    Coursera = 1,
    Udemy = 2,
}

impl Platform {
    pub const ALL: [Platform; 2] = [Platform::Coursera, Platform::Udemy];

    pub fn root_domain(self) -> &'static str {
        match self {
            Platform::Coursera => "coursera.org",
            Platform::Udemy => "udemy.com",
        }
    }

    /// The platform whose root domain is `domain` or a parent of it. Label-boundary match,
    /// so `evilcoursera.org` and `coursera.org.evil.com` are rejected. Case-insensitive
    /// (DNS names, RFC 4343).
    pub fn from_domain(domain: &str) -> Option<Platform> {
        let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if d.split('.').any(str::is_empty) {
            return None;
        }
        Platform::ALL.into_iter().find(|p| {
            let root = p.root_domain();
            d == root || d.strip_suffix(root).is_some_and(|rest| rest.ends_with('.'))
        })
    }
}

/// Collapses all whitespace runs (including line wraps in text/plain) into single spaces.
pub fn normalize_ws(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub mod coursera {
    use super::normalize_ws;

    /// Fields found in a Coursera "Your Certificate is Ready" email body.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Fields {
        pub course_name: String,
    }

    const COMPLETED: &str = "Congratulations! You\u{2019}ve successfully completed ";
    const OFFICIAL: &str = "your official ";

    /// Extracts the course name from the decoded text/plain body.
    ///
    /// Observed template (2020): "Congratulations! You’ve successfully completed <COURSE>. On
    /// behalf of ..." and "... your official <COURSE> Certificate." Signed bodies can still carry
    /// user-controlled text (e.g. the profile name in "Dear <name>,"), so each anchor phrase must
    /// occur exactly once; an injected copy makes the email ambiguous and it is rejected. The
    /// two occurrences must also agree, which rejects names our ". " delimiter would truncate.
    pub fn parse(text: &str) -> Option<Fields> {
        let t = normalize_ws(text);
        if t.matches("successfully completed").count() != 1 || t.matches(OFFICIAL).count() != 1 {
            return None;
        }
        let completed = between(&t, COMPLETED, ". ")?;
        let official = between(&t, OFFICIAL, " Certificate")?;
        (completed == official && !completed.is_empty()).then(|| Fields {
            course_name: completed.to_string(),
        })
    }

    fn between<'a>(s: &'a str, start: &str, end: &str) -> Option<&'a str> {
        let from = s.find(start)? + start.len();
        let len = s[from..].find(end)?;
        Some(s[from..from + len].trim())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_matching() {
        assert_eq!(
            Platform::from_domain("coursera.org"),
            Some(Platform::Coursera)
        );
        assert_eq!(
            Platform::from_domain("t.mail.Coursera.ORG"),
            Some(Platform::Coursera)
        );
        assert_eq!(Platform::from_domain("e.udemymail.com"), None);
        assert_eq!(
            Platform::from_domain("mail.udemy.com."),
            Some(Platform::Udemy)
        );
    }

    #[test]
    fn domain_lookalikes_rejected() {
        assert_eq!(Platform::from_domain("evilcoursera.org"), None);
        assert_eq!(Platform::from_domain("coursera.org.evil.com"), None);
        assert_eq!(Platform::from_domain("sparkpostmail.com"), None);
        assert_eq!(Platform::from_domain(""), None);
        assert_eq!(Platform::from_domain("a..coursera.org"), None);
        assert_eq!(Platform::from_domain("evil-udemy.com"), None);
        assert_eq!(Platform::from_domain("udemy.com.attacker.net"), None);
    }

    const BODY: &str = "     Dear Learner,\n\n     Congratulations! You\u{2019}ve successfully completed The Bits and Bytes of\n     Computer Networking. On behalf of Google and Coursera we are pleased\n     to issue your official The Bits and Bytes of Computer Networking\n     Certificate.\n";

    #[test]
    fn coursera_course_name() {
        let f = coursera::parse(BODY).unwrap();
        assert_eq!(f.course_name, "The Bits and Bytes of Computer Networking");
    }

    #[test]
    fn coursera_rejects_mismatched_names() {
        let tampered = BODY.replacen("official The Bits", "official Machine Learning The Bits", 1);
        assert_eq!(coursera::parse(&tampered), None);
    }

    #[test]
    fn coursera_rejects_injected_phrases() {
        // Attacker sets their profile name so the greeting carries a fake claim.
        let injected = BODY.replace(
            "Dear Learner,",
            "Dear Congratulations! You\u{2019}ve successfully completed Fake Course. x your official Fake Course Certificate,",
        );
        assert_eq!(coursera::parse(&injected), None);
    }

    #[test]
    fn coursera_rejects_unrelated_email() {
        assert_eq!(
            coursera::parse("Your weekly learning digest. Keep going!"),
            None
        );
    }
}
