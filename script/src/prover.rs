//! The SP1 program and proving, shared by the CLI and the server.

use alloy_sol_types::SolType;
use anyhow::{bail, Result};
use sp1_sdk::{
    blocking::{EnvProver, EnvProvingKey, MockProver, ProveRequest, Prover, ProverClient},
    include_elf, Elf, HashableKey, ProvingKey, SP1Stdin,
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

/// The proof system label for bundles: `SP1_PROVER=mock` produces no real proof.
pub fn proof_system() -> &'static str {
    match std::env::var("SP1_PROVER").as_deref() {
        Ok("mock") => "mock",
        _ => "groth16",
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

    /// A Groth16 proof (on-chain verifiable) packaged as a bundle.
    pub fn prove(&self, input: &GuestInput) -> Result<ProofBundle> {
        let proof = self.client.prove(&self.pk, stdin(input)).groth16().run()?;
        ProofBundle::new(
            proof_system(),
            self.pk.verifying_key().bytes32(),
            &proof.bytes(),
            proof.public_values.as_slice(),
        )
    }
}
