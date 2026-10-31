//! The DKIM key records (config/dkim-keys.json) the host needs to build guest inputs.

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
    fn records_match_guest_table() {
        let mut json: Vec<_> = allowlist()
            .into_iter()
            .map(|k| (k.platform, k.key_hash.0, k.name))
            .collect();
        let mut table: Vec<_> = zkcert_lib::keys::KEYS
            .iter()
            .map(|k| (k.platform, k.key_hash, k.name.to_string()))
            .collect();
        json.sort();
        table.sort();
        assert_eq!(
            json, table,
            "config/dkim-keys.json and lib/src/keys.rs disagree"
        );
    }

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
