//! zkcert CLI.
//!
//! ```shell
//! cargo run --release -- execute fixtures/sample.eml            # run the guest, print cycles
//! cargo run --release -- prove fixtures/sample.eml --wallet 0x… # Groth16 proof -> zkcert-proof.json
//! cargo run --release -- verify zkcert-proof.json               # offline verification
//! cargo run --release -- vkey                                   # program verification key
//! ```
//! `SP1_PROVER=mock|cpu|cuda|network` selects the prover (see .env.example).

use std::{path::PathBuf, process::ExitCode};

use alloy_primitives::Address;
use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use zkcert_lib::PublicValues;
use zkcert_script::{
    bundle::{verify_bundle, Decoded, ProofBundle},
    discover::KeySource,
    inputs::{prepare, Prepared},
    keys,
    prover::{pinned_vkey, program_vkey, ZkProver},
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
    Execute(EmailArgs),
    /// Generate a Groth16 proof and write a proof bundle.
    Prove {
        #[command(flatten)]
        email: EmailArgs,
        #[arg(long, default_value = "zkcert-proof.json")]
        out: PathBuf,
    },
    /// Verify a proof bundle offline (vkey, key allowlist, Groth16 proof).
    Verify {
        bundle: PathBuf,
        /// Accept bundles made with SP1_PROVER=mock (they contain no real proof).
        #[arg(long)]
        allow_mock: bool,
    },
    /// Print the program verification key.
    Vkey {
        /// Also pin it in config/program.json (read by `verify`, the web UI and the deploy).
        #[arg(long)]
        write: bool,
    },
    /// Write a synthetic Udemy email signed with a fresh throwaway key, plus its DKIM record
    /// (for fixtures and demos without personal data).
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
    /// Fetch DKIM keys from live DNS instead of config/dkim-keys.json.
    #[arg(long, conflicts_with = "key")]
    dns: bool,
    /// Use this key record instead of the allowlist: `<selector>._domainkey.<domain>=<file>`.
    /// The proof is still produced; verifiers reject it unless the key is allowlisted.
    #[arg(long, value_name = "NAME=FILE")]
    key: Vec<String>,
}

fn load(args: &EmailArgs) -> Result<Prepared> {
    let raw =
        std::fs::read(&args.eml).with_context(|| format!("reading {}", args.eml.display()))?;
    let keys = if args.dns {
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
    };
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(prepare(
        &raw,
        &keys,
        args.wallet.into_array(),
        args.disclose,
    ))
}

fn print_values(v: &PublicValues) {
    println!(
        "{}",
        serde_json::to_string_pretty(&Decoded::from(v)).unwrap()
    );
    if keys::lookup(v.platform, v.dkimKeyHash).is_none() {
        println!(
            "warning: DKIM key {} is not on the allowlist",
            v.dkimKeyHash
        );
    }
}

fn run() -> Result<()> {
    dotenv::dotenv().ok();
    sp1_sdk::utils::setup_logger();
    match Cli::parse().cmd {
        Cmd::Execute(args) => {
            let p = load(&args)?;
            let (values, cycles) = ZkProver::from_env()?.execute(&p.input)?;
            if values != p.expected {
                bail!("guest output differs from host verification");
            }
            print_values(&values);
            println!("cycles: {cycles}");
        }
        Cmd::Prove { email, out } => {
            if email.wallet == Address::ZERO {
                bail!(
                    "--wallet is required: the proof is bound to it and only that wallet can claim"
                );
            }
            let p = load(&email)?;
            let bundle = ZkProver::from_env()?.prove(&p.input)?;
            std::fs::write(&out, serde_json::to_string_pretty(&bundle)?)?;
            print_values(&p.expected);
            println!("wrote {}", out.display());
        }
        Cmd::Verify { bundle, allow_mock } => {
            let b: ProofBundle =
                serde_json::from_slice(&std::fs::read(&bundle)?).context("not a zkcert bundle")?;
            let values = verify_bundle(&b, &pinned_vkey()?, &keys::allowlist(), allow_mock)?;
            print_values(&values);
            println!("VALID ({})", b.proof_system);
        }
        Cmd::Vkey { write } => {
            let vkey = program_vkey();
            println!("{vkey}");
            if write {
                let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../config/program.json");
                std::fs::write(path, format!("{{\n  \"vkey\": \"{vkey}\"\n}}\n"))?;
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
