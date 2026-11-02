# zkCert

Prove "I completed course X on Coursera or Udemy" with an SP1 zero-knowledge proof of the platform's
**DKIM-signed completion email**. The email, your address and your name stay private; anyone can
verify the proof in a browser, and you can optionally record it on-chain as an EAS attestation.

Builds on the approach pioneered by [ZK Email](https://github.com/zkemail), implemented in the
[SP1 zkVM](https://github.com/succinctlabs/sp1): no zkTLS and no platform API. The signature the
platform's mail server already puts on every email is the source of truth.

## How it works
1. **Generate:** drop the `.eml` in the web app. The prover (on your machine by default) checks the
   DKIM signature and runs the SP1 program, which commits only the public values below.
2. **Verify:** anyone drops `zkcert-proof.json` into the Verify tab; the proof is checked in the
   browser with SP1's verifier compiled to WebAssembly. No server, no chain.
3. **Mint (optional):** an on-chain (Groth16) proof can be claimed in `ZkCertRegistry`, which
   writes an EAS attestation to the bound wallet, once per certificate.

| | Coursera | Udemy |
|---|---|---|
| DKIM signer | `t.mail.coursera.org` (RSA-1024) | `e.udemymail.com` (RSA-2048) |
| Course name from | signed text/plain body | signed Subject |

**Public values:** `platform`, `courseHash`, `courseName` (empty unless disclosed), `emailSignedAt`
(DKIM `t=`, day precision), `dkimKeyHash`, `nullifier` (hash of platform, course and the hashed To
address), `wallet`.

## What the proof checks (`lib/src/verify.rs`, run inside SP1)
- `sha256(body) == bh=` and the RSA signature over the signed headers (RFC 6376).
- The key is in the program's pinned table (`lib/src/keys.rs`) for the signing domain's platform,
  and `t=` is inside the key's window. DNS is never trusted.
- `v=1`, `a=rsa-sha256`, no `l=`, `d=`/`i=` on the platform domain, From on the same platform.
- From, Subject and To are signed, exactly once each; signed fields follow `h=`.
- Exact certificate subject; course name anchors appear exactly once and agree (stops text
  injected through a profile name); exactly one text/plain part.

Verifiers additionally accept only the program versions in `config/program.json`, so a modified
program can't produce an accepted proof. Every check has a negative test.

## Run locally
Requirements: [SP1 6.10.0](https://docs.succinct.xyz/docs/sp1/getting-started/install), Rust,
Node 24, Foundry (contracts only). Proving needs ~20 GB peak memory; on a 16 GB Mac it works via
memory compression with other heavy apps closed.

```bash
cp .env.example .env            # SP1_PROVER=cpu: proofs are made on this machine
cp web/.env.example web/.env
(cd web && npm install)
cargo build --release -p zkcert-script -p zkcert-server
```

Terminal 1, prover server (wait for `listening on http://127.0.0.1:8080`):
```bash
cargo run --release -p zkcert-server
```
Terminal 2, web app at http://localhost:3000:
```bash
cd web && npm run dev
```
Drop your `.eml`, paste any wallet address, keep **Off-chain**, and generate (1–2 minutes). Then
load the downloaded file in **Verify**.

CLI:
```bash
./target/release/zkcert prove fixtures/your.eml --wallet 0x… --out proof.json
./target/release/zkcert verify proof.json
./target/release/zkcert execute fixtures/your.eml --no-host-check   # run only the SP1 program
```

No email of your own? No sample proof is committed: a valid one would come from a real inbox. Instead,
`fixtures/redacted/synthetic-udemy.eml` is a fake Udemy email signed with a throwaway key. Run it
through the SP1 program with that key supplied, and the program itself rejects it (key not pinned):
```bash
./target/release/zkcert execute fixtures/redacted/synthetic-udemy.eml --no-host-check \
  --key test._domainkey.e.udemymail.com=fixtures/redacted/synthetic-udemy.key
```

Tests (135 Rust, 19 Foundry; the 2 ignored Rust and 7 skipped Foundry tests need a real Groth16 proof in `contracts/src/fixtures/groth16-proof.json`):
```bash
cargo test --release -p zkcert-lib -p zkcert-script -p zkcert-server -p zkcert-verifier
(cd contracts && forge test)
(cd web && npm run build && npm run lint)
```

The browser verifier is prebuilt in `web/src/wasm`; rebuild it with `web/build-wasm.sh`.

## On-chain (optional)
Groth16 proofs need `SP1_PROVER=network` (Succinct's prover network, which receives the email) or a
machine with much more than 16 GB RAM. Deploy the registry to Base Sepolia:
```bash
cd contracts && forge script script/Deploy.s.sol --rpc-url $BASE_SEPOLIA_RPC_URL --private-key $PRIVATE_KEY --broadcast
```
then set `NEXT_PUBLIC_REGISTRY_ADDRESS` in `web/.env`.

## Trust model and limits
- **Root of trust** is the platform's DKIM key (held by its email provider: SparkPost, SendGrid).
- **The prover sees the email.** Run it locally (the default) and nothing leaves your machine.
- **Possession, not ownership:** the proof shows someone holds a genuine certificate email. Binding
  it to the inbox owner needs an identity step (a salted To commitment plus a one-time code).
- `courseHash` of a public catalogue title is guessable; the nullifier is brute-forceable from a
  guessed email address. Udemy course titles are not unique.

| | Coursera | Udemy |
|---|---|---|
| SP1 cycles | 2.30M | 0.47M |
| Off-chain proof, 16 GB M4 | ~90 s | ~60 s |
| Proof file | 2.5 MB | 2.5 MB |
| Browser verification | ~60 ms | ~60 ms |
