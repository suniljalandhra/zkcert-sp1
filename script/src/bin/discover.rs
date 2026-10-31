//! Inspect the DKIM signatures and parseable fields of a completion email.

use std::{collections::HashMap, path::PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use zkcert_script::discover::{analyze, KeySource};

#[derive(Parser)]
#[command(about = "List DKIM signatures, verify them on the host, and show parsed course fields")]
struct Args {
    /// Path to the .eml file.
    eml: PathBuf,
    /// Use a pinned key record instead of DNS: `<selector>._domainkey.<domain>=<file>`, where the
    /// file holds the TXT record value.
    #[arg(long = "key")]
    keys: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let raw =
        std::fs::read(&args.eml).with_context(|| format!("reading {}", args.eml.display()))?;

    let keys = if args.keys.is_empty() {
        KeySource::Dns
    } else {
        let mut map = HashMap::new();
        for spec in &args.keys {
            let (name, file) = spec.split_once('=').context("--key must be name=file")?;
            let record =
                std::fs::read_to_string(file).with_context(|| format!("reading {file}"))?;
            map.insert(
                name.to_ascii_lowercase(),
                record.trim().trim_matches('"').to_string(),
            );
        }
        KeySource::Pinned(map)
    };

    let report = analyze(&raw, &keys).await?;

    println!(
        "From:     {} (platform: {:?})",
        report.from_address, report.from_platform
    );
    println!("Subject:  {}", report.subject);
    println!("Date:     {}", report.date);
    println!("DKIM-Signature headers: {}", report.signatures.len());

    for (i, sig) in report.signatures.iter().enumerate() {
        println!(
            "\n[{i}] {}",
            if report.selected == Some(i) {
                "<- selected"
            } else {
                ""
            }
        );
        match &sig.tags {
            Ok(t) => {
                println!("  d={}  s={}  a={}  c={}", t.d, t.s, t.a, t.c);
                println!("  h={}", t.h.join(":"));
                println!("  l={:?}  t={:?}  x={:?}  i={:?}", t.l, t.t, t.x, t.i);
                println!("  bh={}", t.bh);
                println!("  platform from d=: {:?}", sig.platform());
            }
            Err(e) => println!("  tag parse error: {e}"),
        }
        if let Some(name) = &sig.key_name {
            println!("  key: {name}");
        }
        match &sig.key {
            Ok(k) => println!("  key: RSA-{} keccak256(DER)={}", k.bits, k.der_keccak),
            Err(e) => println!("  key: unavailable ({e})"),
        }
        println!("  host DKIM verify (mail-auth): {}", sig.host_verify);
        for (name, ok) in &sig.checks {
            println!("  [{}] {name}", if *ok { "ok" } else { "FAIL" });
        }
    }

    println!("\nParsed body fields:");
    match &report.coursera {
        Some(f) => println!("  coursera.course_name = {:?}", f.course_name),
        None => println!("  none (no usable signature, or the parser found no course name)"),
    }
    if report.selected.is_none() {
        std::process::exit(2);
    }
    Ok(())
}
