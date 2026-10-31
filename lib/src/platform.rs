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

    /// Domains the platform signs completion emails with. Udemy sends from `e.udemymail.com`
    /// (registered 2011, DMARC reports go to udemy.com; see docs/PHASE1_FINDINGS.md).
    pub fn root_domains(self) -> &'static [&'static str] {
        match self {
            Platform::Coursera => &["coursera.org"],
            Platform::Udemy => &["udemy.com", "udemymail.com"],
        }
    }

    /// The platform with a root domain equal to `domain` or a parent of it. Label-boundary match,
    /// so `evilcoursera.org` and `coursera.org.evil.com` are rejected. Case-insensitive
    /// (DNS names, RFC 4343).
    pub fn from_domain(domain: &str) -> Option<Platform> {
        let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if d.split('.').any(str::is_empty) {
            return None;
        }
        Platform::ALL.into_iter().find(|p| {
            p.root_domains().iter().any(|root| {
                d == *root || d.strip_suffix(root).is_some_and(|rest| rest.ends_with('.'))
            })
        })
    }
}

/// Collapses all whitespace runs (including line wraps in text/plain) into single spaces.
pub fn normalize_ws(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub mod coursera {
    use super::normalize_ws;

    /// Fields found in a Coursera certificate email body.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Fields {
        pub course_name: String,
    }

    /// A phrase pair around the course name. `unique` must occur exactly once in the body, so a
    /// copy injected through user-controlled text (e.g. the profile name in "Dear <name>,")
    /// makes the email ambiguous and it is rejected.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Anchor {
        pub unique: &'static str,
        pub start: &'static str,
        pub end: &'static str,
    }

    /// One known certificate email layout. Every anchor must yield the same non-empty name,
    /// which also rejects names an anchor's `end` delimiter would truncate.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Template {
        /// Free-form label; documents where the layout was observed.
        pub id: &'static str,
        /// The exact signed subject (whitespace-normalized). Other Coursera emails (forums,
        /// digests) can quote user text, so the subject selects the template first.
        pub subject: &'static str,
        pub anchors: &'static [Anchor],
    }

    /// Known layouts. Add one per real sample, with its own subject and anchors; never loosen an
    /// existing one. Changing this list changes the program vkey.
    pub const TEMPLATES: &[Template] = &[Template {
        // fixtures/sample.eml, signed 2020-08-22: "Congratulations! You’ve successfully
        // completed <COURSE>. On behalf of ... your official <COURSE> Certificate."
        id: "certificate-ready-2020",
        subject: "Congratulations, Your Certificate is Ready!",
        anchors: &[
            Anchor {
                unique: "successfully completed",
                start: "Congratulations! You\u{2019}ve successfully completed ",
                end: ". ",
            },
            Anchor {
                unique: "your official ",
                start: "your official ",
                end: " Certificate",
            },
        ],
    }];

    /// The course name from the decoded text/plain body, using the templates whose subject is
    /// exactly `subject`. If several match, they must agree, so a new template can never make an
    /// existing email parse to a different course.
    pub fn parse(templates: &[Template], subject: &str, text: &str) -> Option<Fields> {
        let subject = normalize_ws(subject);
        let t = normalize_ws(text);
        let mut found: Option<String> = None;
        for tpl in templates.iter().filter(|tpl| tpl.subject == subject) {
            let Some(name) = parse_template(tpl, &t) else {
                continue;
            };
            match &found {
                Some(prev) if *prev != name => return None,
                _ => found = Some(name),
            }
        }
        found.map(|course_name| Fields { course_name })
    }

    fn parse_template(tpl: &Template, t: &str) -> Option<String> {
        let mut name: Option<&str> = None;
        for a in tpl.anchors {
            if t.matches(a.unique).count() != 1 {
                return None;
            }
            let n = between(t, a.start, a.end)?;
            if n.is_empty() || name.is_some_and(|prev| prev != n) {
                return None;
            }
            name = Some(n);
        }
        name.map(str::to_string)
    }

    fn between<'a>(s: &'a str, start: &str, end: &str) -> Option<&'a str> {
        let from = s.find(start)? + start.len();
        let len = s[from..].find(end)?;
        Some(s[from..from + len].trim())
    }
}

pub mod udemy {
    use super::normalize_ws;

    const PREFIX: &str = "Your completion certificate is ready for \"";

    /// Extracts the course title from the signed subject (observed 2023):
    /// `Your completion certificate is ready for "<COURSE>"`. The title is everything between the
    /// fixed prefix and the final quote, so a title that itself contains quotes still parses whole.
    pub fn parse_subject(subject: &str) -> Option<String> {
        let s = normalize_ws(subject);
        let name = s.strip_prefix(PREFIX)?.strip_suffix('"')?.trim();
        (!name.is_empty()).then(|| name.to_string())
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
        assert_eq!(
            Platform::from_domain("e.udemymail.com"),
            Some(Platform::Udemy)
        );
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
        assert_eq!(Platform::from_domain("notudemymail.com"), None);
        assert_eq!(Platform::from_domain("udemymail.com.evil.io"), None);
        assert_eq!(Platform::from_domain("sendgrid.info"), None);
    }

    const BODY: &str = "     Dear Learner,\n\n     Congratulations! You\u{2019}ve successfully completed The Bits and Bytes of\n     Computer Networking. On behalf of Google and Coursera we are pleased\n     to issue your official The Bits and Bytes of Computer Networking\n     Certificate.\n";
    const SUBJECT: &str = "Congratulations, Your Certificate is Ready!";

    fn parse(text: &str) -> Option<coursera::Fields> {
        coursera::parse(coursera::TEMPLATES, SUBJECT, text)
    }

    /// A second, made-up layout for testing template selection.
    const NEW: coursera::Template = coursera::Template {
        id: "test-2026",
        subject: "You earned a certificate",
        anchors: &[coursera::Anchor {
            unique: "earned a certificate for",
            start: "You earned a certificate for ",
            end: "!",
        }],
    };

    #[test]
    fn coursera_template_invariants() {
        for t in coursera::TEMPLATES {
            // Two anchors cross-check each other (catches names an `end` delimiter truncates).
            assert!(t.anchors.len() >= 2, "{}", t.id);
            // Exactly-once on `unique` only implies `start` is unique if `start` contains it.
            assert!(
                t.anchors.iter().all(|a| a.start.contains(a.unique)),
                "{}",
                t.id
            );
            assert_eq!(normalize_ws(t.subject), t.subject, "{}", t.id);
        }
    }

    #[test]
    fn coursera_course_name() {
        let f = parse(BODY).unwrap();
        assert_eq!(f.course_name, "The Bits and Bytes of Computer Networking");
    }

    #[test]
    fn coursera_rejects_mismatched_names() {
        let tampered = BODY.replacen("official The Bits", "official Machine Learning The Bits", 1);
        assert_eq!(parse(&tampered), None);
    }

    #[test]
    fn coursera_rejects_injected_phrases() {
        // Attacker sets their profile name so the greeting carries a fake claim.
        let injected = BODY.replace(
            "Dear Learner,",
            "Dear Congratulations! You\u{2019}ve successfully completed Fake Course. x your official Fake Course Certificate,",
        );
        assert_eq!(parse(&injected), None);
    }

    #[test]
    fn coursera_subject_must_match_template_exactly() {
        let t = coursera::TEMPLATES;
        assert_eq!(
            coursera::parse(t, "Re: Congratulations, Your Certificate is Ready!", BODY),
            None
        );
        assert_eq!(
            coursera::parse(t, "Congratulations, Your Certificate is Ready", BODY),
            None
        );
        assert!(coursera::parse(
            t,
            "  Congratulations,  Your Certificate\r\n is Ready! ",
            BODY
        )
        .is_some());
    }

    #[test]
    fn coursera_multiple_templates() {
        let both = [coursera::TEMPLATES[0], NEW];
        let new_body = "Hi, You earned a certificate for Machine Learning! Share it.";
        assert_eq!(
            coursera::parse(&both, "You earned a certificate", new_body)
                .unwrap()
                .course_name,
            "Machine Learning"
        );
        assert_eq!(
            coursera::parse(&both, SUBJECT, BODY).unwrap().course_name,
            "The Bits and Bytes of Computer Networking"
        );
        // A body only parses with the template its own subject selects.
        assert_eq!(coursera::parse(&both, SUBJECT, new_body), None);
        assert_eq!(
            coursera::parse(&both, "You earned a certificate", BODY),
            None
        );
        // Exactly-once still applies per template.
        let twice = format!("{new_body} You earned a certificate for Fake!");
        assert_eq!(
            coursera::parse(&both, "You earned a certificate", &twice),
            None
        );
    }

    #[test]
    fn coursera_templates_sharing_a_subject_must_agree() {
        let other = coursera::Template {
            id: "conflicting",
            subject: SUBJECT,
            anchors: &[coursera::Anchor {
                unique: "On behalf of",
                start: "On behalf of ",
                end: " we",
            }],
        };
        // The 2020 template says "The Bits and Bytes...", this one "Google and Coursera".
        assert_eq!(
            coursera::parse(&[coursera::TEMPLATES[0], other], SUBJECT, BODY),
            None
        );
        assert!(coursera::parse(
            &[coursera::TEMPLATES[0], coursera::TEMPLATES[0]],
            SUBJECT,
            BODY
        )
        .is_some());
    }

    #[test]
    fn udemy_subject() {
        assert_eq!(
            udemy::parse_subject("Your completion certificate is ready for \"Tally With Tax\"")
                .unwrap(),
            "Tally With Tax"
        );
        assert_eq!(
            udemy::parse_subject("Your completion certificate is ready for \"A \"B\" C\"").unwrap(),
            "A \"B\" C"
        );
    }

    #[test]
    fn udemy_rejects_other_subjects() {
        assert_eq!(
            udemy::parse_subject("Your completion certificate is ready for \"\""),
            None
        );
        assert_eq!(
            udemy::parse_subject("Re: Your completion certificate is ready for \"X\""),
            None
        );
        assert_eq!(
            udemy::parse_subject("New message from your instructor"),
            None
        );
    }

    #[test]
    fn coursera_rejects_unrelated_email() {
        assert_eq!(parse("Your weekly learning digest. Keep going!"), None);
    }
}
