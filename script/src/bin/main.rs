//! zkcert CLI.

use std::{path::PathBuf, process::ExitCode};

use alloy_primitives::Address;
use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use zkcert_lib::{keys::KEYS, PublicValues};
use zkcert_script::{
    bundle::{verify_bundle, Decoded, ProofBundle},
    discover::KeySource,
    inputs::{guest_input, prepare, Prepared},
    keys,
    prover::{accepted_vkeys, program_vkey, ProofSystem, ZkProver},
    synth,
};

#[derive(Parser)]
#[command(about = "Prove a Coursera/Udemy certificate email with SP1")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the guest without proving and print the cycle count.
    Execute {
        #[command(flatten)]
        email: EmailArgs,
        /// Skip the host's copy of the guest checks and run the guest directly, to show what the
        /// guest itself rejects (an email it rejects exits non-zero, so no proof can exist).
        #[arg(long)]
        no_host_check: bool,
    },
    /// Generate a proof and write a proof bundle.
    Prove {
        #[command(flatten)]
        email: EmailArgs,
        #[arg(long, default_value = "zkcert-proof.json")]
        out: PathBuf,
        /// `compressed` (local, verified off-chain) or `groth16` (on-chain; needs
        /// SP1_PROVER=network or a machine with much more than 16 GB RAM).
        #[arg(long, default_value = "compressed", value_parser = ["compressed", "groth16"])]
        proof_system: String,
    },
    /// Verify a proof bundle offline (accepted program vkey, then the compressed or Groth16 proof).
    Verify {
        bundle: PathBuf,
        /// Accept bundles made with SP1_PROVER=mock (they contain no real proof).
        #[arg(long)]
        allow_mock: bool,
    },
    /// Print the program verification key.
    Vkey {
        /// Also pin it in config/program.json as the current version and add it to `accepted` (read
        /// by `verify`, the web UI and the deploy).
        #[arg(long)]
        write: bool,
    },
    /// Write a synthetic Udemy email signed with a fresh throwaway key, plus its DKIM record (for
    /// fixtures and demos without personal data).
    Synth {
        #[arg(long, default_value = "fixtures/redacted")]
        dir: PathBuf,
    },
}

#[derive(Args)]
struct EmailArgs {
    /// The completion email (.eml).
    eml: PathBuf,
    /// Wallet the proof is bound to (required for `prove`; `execute` defaults to zero).
    #[arg(long, default_value_t = Address::ZERO)]
    wallet: Address,
    /// Reveal the course name in the public values.
    #[arg(long)]
    disclose: bool,
    /// Fetch DKIM key records from live DNS instead of config/dkim-keys.json.
    #[arg(long, conflicts_with = "key")]
    dns: bool,
    /// Use this key record instead of config/dkim-keys.json:
    /// `<selector>._domainkey.<domain>=<file>`.
    #[arg(long, value_name = "NAME=FILE")]
    key: Vec<String>,
}

fn key_source(args: &EmailArgs) -> Result<KeySource> {
    Ok(if args.dns {
        KeySource::Dns
    } else if !args.key.is_empty() {
        let mut map = std::collections::HashMap::new();
        for spec in &args.key {
            let (name, file) = spec.split_once('=').context("--key expects NAME=FILE")?;
            map.insert(
                name.to_ascii_lowercase(),
                std::fs::read_to_string(file)?.trim().to_string(),
            );
        }
        KeySource::Pinned(map)
    } else {
        keys::pinned_source()
    })
}

fn read_eml(args: &EmailArgs) -> Result<Vec<u8>> {
    std::fs::read(&args.eml).with_context(|| format!("reading {}", args.eml.display()))
}

fn load(args: &EmailArgs) -> Result<Prepared> {
    let (raw, keys) = (read_eml(args)?, key_source(args)?);
    tokio::runtime::Runtime::new()?.block_on(prepare(
        &raw,
        &keys,
        KEYS,
        args.wallet.into_array(),
        args.disclose,
    ))
}

fn print_values(v: &PublicValues) {
    println!(
        "{}",
        serde_json::to_string_pretty(&Decoded::from(v)).unwrap()
    );
    if let Some(k) = KEYS
        .iter()
        .find(|k| k.key_hash == v.dkimKeyHash.0 && k.platform == v.platform)
    {
        println!("key: {}", k.name);
    }
}

fn run() -> Result<()> {
    dotenv::dotenv().ok();
    sp1_sdk::utils::setup_logger();
    match Cli::parse().cmd {
        Cmd::Execute {
            email,
            no_host_check: false,
        } => {
            let p = load(&email)?;
            let (values, cycles) = ZkProver::from_env()?.execute(&p.input)?;
            if values != p.expected {
                bail!("guest output differs from host verification");
            }
            print_values(&values);
            println!("cycles: {cycles}");
        }
        Cmd::Execute {
            email,
            no_host_check: true,
        } => {
            let (raw, keys) = (read_eml(&email)?, key_source(&email)?);
            let input = tokio::runtime::Runtime::new()?.block_on(guest_input(
                &raw,
                &keys,
                email.wallet.into_array(),
                email.disclose,
            ))?;
            println!("host checks skipped; running the SP1 guest");
            let (values, cycles) = ZkProver::from_env()?.execute(&input)?;
            print_values(&values);
            println!("cycles: {cycles}");
        }
        Cmd::Prove {
            email,
            out,
            proof_system,
        } => {
            if email.wallet == Address::ZERO {
                bail!(
                    "--wallet is required: the proof is bound to it and only that wallet can claim"
                );
            }
            let p = load(&email)?;
            let system = ProofSystem::parse(&proof_system).expect("clap checked it");
            let bundle = ZkProver::from_env()?.prove(&p.input, system)?;
            std::fs::write(&out, serde_json::to_string_pretty(&bundle)?)?;
            print_values(&p.expected);
            println!("wrote {}", out.display());
        }
        Cmd::Verify { bundle, allow_mock } => {
            let b: ProofBundle =
                serde_json::from_slice(&std::fs::read(&bundle)?).context("not a zkcert bundle")?;
            let values = verify_bundle(&b, &accepted_vkeys()?, allow_mock)?;
            print_values(&values);
            println!("VALID ({})", b.proof_system);
        }
        Cmd::Vkey { write } => {
            let vkey = program_vkey();
            println!("{vkey}");
            if write {
                let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../config/program.json");
                let mut accepted = accepted_vkeys()?;
                if !accepted.iter().any(|v| v.eq_ignore_ascii_case(&vkey)) {
                    accepted.push(vkey.clone());
                }
                let json = serde_json::json!({ "vkey": vkey, "accepted": accepted });
                std::fs::write(path, serde_json::to_string_pretty(&json)? + "\n")?;
                println!("pinned in config/program.json (rebuild to embed it)");
            }
        }
        Cmd::Synth { dir } => {
            let key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048)?;
            let mail = synth::udemy();
            std::fs::create_dir_all(&dir)?;
            std::fs::write(dir.join("synthetic-udemy.eml"), synth::sign(&mail, &key))?;
            std::fs::write(dir.join("synthetic-udemy.key"), synth::record(&key))?;
            println!(
                "wrote {0}/synthetic-udemy.eml and {0}/synthetic-udemy.key",
                dir.display()
            );
            println!(
                "use: --key {}={}/synthetic-udemy.key",
                synth::key_name(&mail),
                dir.display()
            );
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}
