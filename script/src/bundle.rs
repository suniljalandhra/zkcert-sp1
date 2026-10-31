//! `zkcert-proof.json`: the downloadable proof bundle, and its offline verification.

use alloy_primitives::hex;
use alloy_sol_types::SolType;
use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use zkcert_lib::PublicValues;

pub const BUNDLE_VERSION: &str = "zkcert-v1";
pub const SP1_VERSION: &str = "6.10.0";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Decoded {
    pub platform: String,
    pub platform_id: u8,
    pub course_hash: String,
    pub course_name: String,
    pub email_signed_at: u64,
    pub dkim_key_hash: String,
    pub nullifier: String,
    pub wallet: String,
}

impl From<&PublicValues> for Decoded {
    fn from(v: &PublicValues) -> Self {
        Decoded {
            platform: match v.platform {
                1 => "coursera",
                2 => "udemy",
                _ => "unknown",
            }
            .into(),
            platform_id: v.platform,
            course_hash: v.courseHash.to_string(),
            course_name: v.courseName.clone(),
            email_signed_at: v.emailSignedAt,
            dkim_key_hash: v.dkimKeyHash.to_string(),
            nullifier: v.nullifier.to_string(),
            wallet: v.wallet.to_checksum(None),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProofBundle {
    pub version: String,
    pub sp1_version: String,
    /// "groth16" (verifiable on-chain) or "mock" (development only, not a proof).
    pub proof_system: String,
    /// Program verification key hash (bytes32).
    pub vkey: String,
    /// Compressed proofs only: the same vkey as SP1's KoalaBear digest (bincode, hex), which the
    /// compressed verifier needs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vkey_hash: Option<String>,
    pub proof: String,
    pub public_values: String,
    /// Human-readable copy of `public_values`; never trusted, always re-derived.
    pub decoded: Decoded,
}

impl ProofBundle {
    pub fn new(system: &str, vkey: String, proof: &[u8], public_values: &[u8]) -> Result<Self> {
        let values = PublicValues::abi_decode(public_values).context("public values")?;
        Ok(ProofBundle {
            version: BUNDLE_VERSION.into(),
            sp1_version: SP1_VERSION.into(),
            proof_system: system.into(),
            vkey,
            vkey_hash: None,
            proof: hex::encode_prefixed(proof),
            public_values: hex::encode_prefixed(public_values),
            decoded: Decoded::from(&values),
        })
    }
}

/// Everything a verifier must check, in order. Returns the trusted public values.
pub fn verify_bundle(
    b: &ProofBundle,
    accepted_vkeys: &[String],
    allow_mock: bool,
) -> Result<PublicValues> {
    ensure!(
        b.version == BUNDLE_VERSION,
        "unknown bundle version {}",
        b.version
    );
    ensure!(
        accepted_vkeys
            .iter()
            .any(|v| v.eq_ignore_ascii_case(&b.vkey)),
        "vkey {} is not an accepted zkCert program version: the proof is for a different program",
        b.vkey
    );
    let pv = hex::decode(&b.public_values).context("publicValues is not hex")?;
    let values = PublicValues::abi_decode(&pv).context("publicValues do not decode")?;
    ensure!(
        Decoded::from(&values) == b.decoded,
        "decoded fields do not match publicValues"
    );
    match b.proof_system.as_str() {
        "groth16" => {
            let proof = hex::decode(&b.proof).context("proof is not hex")?;
            sp1_verifier::Groth16Verifier::verify(
                &proof,
                &pv,
                &b.vkey,
                &sp1_verifier::GROTH16_VK_BYTES,
            )
            .map_err(|e| anyhow::anyhow!("Groth16 proof invalid: {e}"))?;
        }
        "compressed" => {
            let proof = hex::decode(&b.proof).context("proof is not hex")?;
            let vkey_hash = hex::decode(
                b.vkey_hash
                    .as_deref()
                    .context("compressed bundle has no vkeyHash")?,
            )
            .context("vkeyHash is not hex")?;
            // The proof is checked against vkeyHash, so that digest must be the accepted `vkey`.
            let vkey = zkcert_verifier::vkey_bytes32(&vkey_hash).map_err(|e| anyhow::anyhow!(e))?;
            ensure!(
                vkey.eq_ignore_ascii_case(&b.vkey),
                "vkeyHash is for program {vkey}, not {}",
                b.vkey
            );
            zkcert_verifier::verify_compressed(&proof, &pv, &vkey_hash)
                .map_err(|e| anyhow::anyhow!("compressed proof invalid: {e}"))?;
        }
        "mock" if allow_mock => {}
        "mock" => bail!("mock bundle: not a real proof (pass --allow-mock for development)"),
        other => bail!("unsupported proof system {other}"),
    }
    Ok(values)
}
