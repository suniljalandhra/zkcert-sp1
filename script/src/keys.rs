//! The DKIM key allowlist (config/dkim-keys.json). A proof is only meaningful if its
//! `dkimKeyHash` is one of these keys: DNS answers are untrusted and keys rotate.

use std::collections::HashMap;

use alloy_primitives::B256;
use serde::Deserialize;

use crate::discover::KeySource;

const ALLOWLIST_JSON: &str = include_str!("../../config/dkim-keys.json");

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KnownKey {
    pub platform: u8,
    /// `<selector>._domainkey.<domain>`.
    pub name: String,
    /// The DKIM TXT record as published.
    pub record: String,
    pub key_hash: B256,
}

#[derive(Deserialize)]
struct File {
    keys: Vec<KnownKey>,
}

pub fn allowlist() -> Vec<KnownKey> {
    serde_json::from_str::<File>(ALLOWLIST_JSON)
        .expect("config/dkim-keys.json is valid")
        .keys
}

/// The allowlisted key with this hash, if it belongs to `platform`.
pub fn lookup(platform: u8, key_hash: B256) -> Option<KnownKey> {
    allowlist()
        .into_iter()
        .find(|k| k.key_hash == key_hash && k.platform == platform)
}

/// Resolve keys from the allowlist only (no DNS): reproducible and immune to key rotation.
pub fn pinned_source() -> KeySource {
    KeySource::Pinned(
        allowlist()
            .into_iter()
            .map(|k| (k.name, k.record))
            .collect::<HashMap<_, _>>(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discover::key_info;

    #[test]
    fn hashes_match_records() {
        for k in allowlist() {
            assert_eq!(
                key_info(&k.record).unwrap().der_keccak,
                k.key_hash,
                "{}",
                k.name
            );
        }
    }
}
