# Rust Pure Demo Ledger

This repository contains a compact Rust showcase project that mimics the core mechanics of a tamper-evident ledger. The goal is to highlight practical systems programming skills - cryptography, persistence, and CLI ergonomics - without the scope of a full blockchain.

## Features

- **Signed appends** - Entries must be signed with an Ed25519 secret key before being accepted.
- **Hash chaining** - Each record stores the hash of the previous one plus its own data, so tampering is detectable.
- **Durable JSONL storage** - Appends stream to `ledger.jsonl`, making the ledger easy to inspect or replay.
- **CLI + library** - Use the binary for demos, or link against the crate in other Rust programs.

## Repository Layout

- `rust_pure_demo/src/ledger.rs` - Ledger core: keypair helpers, append path, file persistence, validation.
- `rust_pure_demo/src/lib.rs` - Re-exports the ledger types for downstream use.
- `rust_pure_demo/src/main.rs` - Clap-powered CLI front-end.
- `ledger.jsonl` - Created on demand when the CLI appends entries.

## Quickstart

```bash
cd rust_pure_demo
cargo test             # run the unit tests
```

Common CLI flows (default ledger file: `ledger.jsonl`):

```bash
# Generate a base64-encoded Ed25519 keypair
cargo run -- generate-key

# Append a payload using the secret key from above
cargo run -- append --payload "hello" --secret-key <BASE64_SECRET>

# Dump the ledger contents as pretty JSON
cargo run -- show
```

Use `--ledger <path>` to target a different ledger file, and `--timestamp <secs>` if you need deterministic timestamps (for tests or demos).

### Desktop GUI

There is also a lightweight native GUI built with `eframe`:

```bash
cargo run --bin gui
```

The window shows the current ledger contents and lets you append new entries by providing a payload and the base64 secret key. Leave the timestamp field blank to use the current wall clock.

## Ledger File Format

Entries are stored one per line as JSON objects. Each record contains:

| Field        | Description |
|--------------|-------------|
| `index`      | Monotonic counter starting at 0. Recomputed on append. |
| `timestamp`  | UNIX seconds supplied by the client (default: wall clock). |
| `payload`    | Arbitrary UTF-8 string. |
| `prev_hash`  | `GENESIS` for the first entry, otherwise the previous entry's `hash`. |
| `hash`       | SHA-256 digest over index, timestamp, payload, prev_hash, public key, and signature. |
| `public_key` | Base64-encoded Ed25519 public key that signed the entry. |
| `signature`  | Base64-encoded signature over the entry's `signable_content`. |

To verify the log independently, read each line, recompute the `hash`, and validate the signature using the stored `public_key`.

## Library Usage

Link against the crate to programmatically manage a ledger:

```rust
use rust_pure_demo::{Keypair, Ledger};

let mut ledger = Ledger::open("/tmp/demo-ledger.jsonl")?;
let keypair = Keypair::generate();
let now = 1_700_000_000;
let request = ledger.prepare_append("hello", &keypair.secret_key, now)?;
ledger.append(request)?;
```

`Ledger::prepare_append` encapsulates signing logic so callers do not need to manipulate dalek types directly.

## Testing

Run the unit test suite:

```bash
cargo test
```

Tests cover append + reload semantics to ensure persistence, signature validation, and hash chaining work as expected.

## Limitations & Future Work

- No consensus or networking - this is a single-node ledger intended for demos.
- Timestamps are caller-supplied, so clock skew or malicious inputs are only bounded by the ledger's monotonic check.
- Secrets are supplied on the command line; for real deployments, prefer environment variables, files, or key management services.

Possible extensions include batch verification tooling, richer payload schemas, or a lightweight HTTP API over the ledger core.
