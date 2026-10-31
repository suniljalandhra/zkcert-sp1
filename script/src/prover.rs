//! The SP1 program and proving, shared by the CLI and the server.

use alloy_sol_types::SolType;
use anyhow::{bail, Result};
use sp1_sdk::{
    blocking::{EnvProver, EnvProvingKey, MockProver, ProveRequest, Prover, ProverClient},
    include_elf, Elf, HashableKey, ProvingKey, SP1Proof, SP1Stdin,
};
use zkcert_lib::{verify::GuestInput, PublicValues};

use crate::bundle::ProofBundle;

pub const ZKCERT_ELF: Elf = include_elf!("zkcert-program");

const PROGRAM_JSON: &str = include_str!("../../config/program.json");

/// The vkey of the current program (config/program.json `vkey`, written by `zkcert vkey --write`).
/// Comparing against this, not the locally built ELF, means a modified build is not trusted.
pub fn pinned_vkey() -> Result<String> {
    let v: serde_json::Value = serde_json::from_str(PROGRAM_JSON)?;
    Ok(v["vkey"].as_str().unwrap_or_default().to_string())
}

/// Every program version verifiers accept (config/program.json `accepted`). A key-table change
/// is a new version; an old one stays accepted until it is removed here (and in the registry).
pub fn accepted_vkeys() -> Result<Vec<String>> {
    let v: serde_json::Value = serde_json::from_str(PROGRAM_JSON)?;
    Ok(v["accepted"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default())
}

/// The program verification key (bytes32 hex). It depends only on the ELF.
pub fn program_vkey() -> String {
    let pk = MockProver::new().setup(ZKCERT_ELF).expect("setup");
    pk.verifying_key().bytes32()
}

fn stdin(input: &GuestInput) -> SP1Stdin {
    let mut stdin = SP1Stdin::new();
    stdin.write(input);
    stdin
}

/// Which proof to produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofSystem {
    /// SP1's compressed STARK: made locally on a laptop, verified off-chain (CLI or browser).
    Compressed,
    /// The compressed proof wrapped in Groth16: ~260 bytes, verifiable on-chain. The wrap needs far
    /// more memory than a 16 GB machine has, so in practice it needs `SP1_PROVER=network`.
    Groth16,
}

impl ProofSystem {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "compressed" => Some(ProofSystem::Compressed),
            "groth16" => Some(ProofSystem::Groth16),
            _ => None,
        }
    }
}

/// `SP1_PROVER` as configured (`cpu` when unset, as in sp1-sdk).
pub fn prover_kind() -> String {
    std::env::var("SP1_PROVER").unwrap_or_else(|_| "cpu".into())
}

/// The proof system label for bundles: `SP1_PROVER=mock` produces no real proof.
pub fn proof_label(system: ProofSystem) -> &'static str {
    match (prover_kind().as_str(), system) {
        ("mock", _) => "mock",
        (_, ProofSystem::Compressed) => "compressed",
        (_, ProofSystem::Groth16) => "groth16",
    }
}

/// A prover configured from the environment (`SP1_PROVER`, `NETWORK_PRIVATE_KEY`), set up once.
pub struct ZkProver {
    client: EnvProver,
    pk: EnvProvingKey,
}

impl ZkProver {
    pub fn from_env() -> Result<Self> {
        let client = ProverClient::from_env();
        let pk = client.setup(ZKCERT_ELF)?;
        Ok(ZkProver { client, pk })
    }

    /// Runs the guest without proving. Returns the committed values and the cycle count.
    pub fn execute(&self, input: &GuestInput) -> Result<(PublicValues, u64)> {
        let (output, report) = self.client.execute(ZKCERT_ELF, stdin(input)).run()?;
        if report.exit_code != 0 {
            bail!("guest rejected the email (exit code {})", report.exit_code);
        }
        Ok((
            PublicValues::abi_decode(output.as_slice())?,
            report.total_instruction_count(),
        ))
    }

    /// A proof packaged as a bundle.
    pub fn prove(&self, input: &GuestInput, system: ProofSystem) -> Result<ProofBundle> {
        let vk = self.pk.verifying_key();
        let request = self.client.prove(&self.pk, stdin(input));
        let label = proof_label(system);
        match system {
            ProofSystem::Groth16 => {
                let proof = request.groth16().run()?;
                ProofBundle::new(
                    label,
                    vk.bytes32(),
                    &proof.bytes(),
                    proof.public_values.as_slice(),
                )
            }
            ProofSystem::Compressed => {
                let proof = request.compressed().run()?;
                let bytes = match &proof.proof {
                    SP1Proof::Compressed(_) => bincode::serialize(&proof.proof)?,
                    // The mock prover returns an empty proof of another kind; nothing to encode.
                    _ if label == "mock" => Vec::new(),
                    _ => bail!("the prover did not return a compressed proof"),
                };
                let mut bundle =
                    ProofBundle::new(label, vk.bytes32(), &bytes, proof.public_values.as_slice())?;
                bundle.vkey_hash = Some(alloy_primitives::hex::encode_prefixed(
                    bincode::serialize(&vk.hash_koalabear())?,
                ));
                Ok(bundle)
            }
        }
    }
}
