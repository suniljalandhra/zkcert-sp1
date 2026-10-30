# zkcert-sp1

Prove a Coursera/Udemy course completion from its DKIM-signed email with SP1, without revealing the email.
Design: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) · progress: [docs/PHASES.md](docs/PHASES.md) · choices and pinned versions: [docs/DECISIONS.md](docs/DECISIONS.md).

## Prerequisites
SP1 6.10.0 (`curl -L https://sp1up.succinct.xyz | bash && sp1up`), Rust stable, Node 24, Foundry, protoc.

## Run (Phase 0)
```bash
git submodule update --init --recursive
cd script && SP1_PROVER=mock cargo run --release -- --execute   # build guest + execute
cd script && cargo run --release --bin vkey                      # print program vkey
cargo run -p zkcert-server                                       # http://127.0.0.1:8080/health
cd web && npm install && npm run dev                             # http://localhost:3000
cd contracts && forge test
```
