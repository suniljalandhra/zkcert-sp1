//! The DKIM keys the guest accepts. Compiled into the program, so the vkey commits to this table:
//! adding, removing or re-windowing a key is a new program version (new vkey), which verifiers and
//! the registry accept explicitly. DNS is never consulted at proof time.
//!
//! The records these hashes come from are in config/dkim-keys.json (the host needs the full key);
//! `script/src/keys.rs` tests that the two lists agree.

/// One accepted key. The signed DKIM `t=` must satisfy `valid_from <= t < valid_to`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinnedKey {
    /// `<selector>._domainkey.<domain>`, for humans only.
    pub name: &'static str,
    /// 1 = Coursera, 2 = Udemy. A key vouches only for its own platform.
    pub platform: u8,
    /// keccak256 of the SPKI DER (the `dkimKeyHash` public value).
    pub key_hash: [u8; 32],
    /// Unix seconds, inclusive. 0 = no lower bound.
    pub valid_from: u64,
    /// Unix seconds, exclusive. `u64::MAX` = no upper bound.
    pub valid_to: u64,
}

impl PinnedKey {
    /// A key with a bound needs the signed `t=` to check it; an unbounded key accepts any `t=`
    /// and none (Udemy's signatures carry no `t=`).
    pub fn bounded(&self) -> bool {
        self.valid_from > 0 || self.valid_to < u64::MAX
    }

    pub fn accepts_time(&self, t: Option<u64>) -> bool {
        match t {
            Some(t) => self.valid_from <= t && t < self.valid_to,
            None => !self.bounded(),
        }
    }
}

/// `0x`-less hex to bytes at compile time, so a typo fails the build instead of a proof.
const fn hex32(s: &str) -> [u8; 32] {
    const fn nib(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("key hash must be lowercase hex"),
        }
    }
    let b = s.as_bytes();
    assert!(b.len() == 64, "key hash must be 32 bytes");
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = nib(b[2 * i]) << 4 | nib(b[2 * i + 1]);
        i += 1;
    }
    out
}

/// 2016-06-01T00:00:00Z.
const JUNE_2016: u64 = 1_464_739_200;

/// Accepted keys (DNS fetched 2026-10-31; both still published then).
///
/// - Coursera `scph0616`: RSA-1024 via SparkPost, whose selectors are named `scph<MMYY>`, so the
///   key cannot predate June 2016 (an inference from the naming scheme, not a published date).
///   Still live, so no upper bound yet. When Coursera retires it, a new version can set `valid_to`
///   (this only stops an honest signer's later use). If it is compromised, a window does not help,
///   because the signer chooses `t=`: remove the key and retire every accepted vkey whose table has it.
///   Being bounded, it requires `t=`; Coursera's signatures carry one, so this fails closed only on
///   a signature without `t=`.
/// - Udemy `s1`: RSA-2048 via SendGrid. Udemy's signatures have no `t=`, so a window could never
///   be checked; the key is unbounded and rotation relies on a new program version alone.
pub const KEYS: &[PinnedKey] = &[
    PinnedKey {
        name: "scph0616._domainkey.t.mail.coursera.org",
        platform: 1,
        key_hash: hex32("34258a3d226293c85b11044d63a85aee881725f9df3400c5dec295b0ac5ce699"),
        valid_from: JUNE_2016,
        valid_to: u64::MAX,
    },
    PinnedKey {
        name: "s1._domainkey.e.udemymail.com",
        platform: 2,
        key_hash: hex32("148b127e51c61a3f7d101bbf429c81e955ce720227d3c091e7b1b32f564a2451"),
        valid_from: 0,
        valid_to: u64::MAX,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    const K: PinnedKey = PinnedKey {
        name: "k",
        platform: 1,
        key_hash: [0; 32],
        valid_from: 100,
        valid_to: 200,
    };

    #[test]
    fn window_bounds() {
        assert!(!K.accepts_time(Some(99)));
        assert!(K.accepts_time(Some(100)));
        assert!(K.accepts_time(Some(199)));
        assert!(!K.accepts_time(Some(200)));
        assert!(!K.accepts_time(None), "a bounded key needs t=");
    }

    #[test]
    fn unbounded_key_accepts_missing_t() {
        let open = PinnedKey {
            valid_from: 0,
            valid_to: u64::MAX,
            ..K
        };
        assert!(open.accepts_time(None) && open.accepts_time(Some(0)));
    }

    #[test]
    fn production_windows() {
        let coursera = KEYS.iter().find(|k| k.platform == 1).unwrap();
        let udemy = KEYS.iter().find(|k| k.platform == 2).unwrap();
        assert!(!coursera.accepts_time(None));
        assert!(!coursera.accepts_time(Some(JUNE_2016 - 1)));
        assert!(
            coursera.accepts_time(Some(1_598_137_023)),
            "the 2020 sample"
        );
        assert!(udemy.accepts_time(None));
    }

    #[test]
    fn hex_decoding() {
        assert_eq!(hex32(&"0f".repeat(32)), [0x0f; 32]);
        assert_eq!(KEYS[0].key_hash[0], 0x34);
        assert_eq!(KEYS[1].key_hash[31], 0x51);
    }
}
