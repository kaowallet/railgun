# RAILGUN Engine — Rust

A faithful, tests-first Rust port of the RAILGUN engine TypeScript SDK, built for
native desktop wallets. The original TS source (`../src`) is kept as the
reference oracle; every module is validated against the TS known-answer vectors
**and** differential-fuzzed against the real TS SDK run under Bun
(see [Testing](#testing)). **205 tests pass, zero warnings.**

> Cryptography is delegated to existing, audited crates (arkworks, RustCrypto,
> dalek, light-poseidon / poseidon-ark). Nothing re-implements a cipher, curve,
> or hash from scratch.

## Is it ready to integrate?

**Partially — and honestly so.** It is a solid, verified *library* for the
offline / key-management / commitment-crypto layers a wallet needs. It is **not
yet a turnkey engine**: syncing balances from chain and generating spend proofs
are not functional out of the box (see ❌ rows). Read this table before building.

| Capability | Status |
|---|---|
| Mnemonic create/restore, 0zk + 0x addresses, view-only & hardware-connector | ✅ **Ready** |
| Encrypted local storage (AES-256-GCM values over a `KvStore`) | ✅ **Ready** (you supply a backend) |
| Note commitment crypto — hash / nullifier / NPK / token hash, V2 (AES) + V3 (XChaCha) encrypt+decrypt | ✅ **Ready** |
| Merkle trees (UTXO + TXID), railgun-txid, bound-params, EdDSA-Poseidon signing | ✅ **Ready** |
| Coin selection (spending solutions) | ✅ **Ready** |
| POI blinded commitments / status logic | ✅ **Ready** |
| **Balance sync from chain** (events → merkletree → decrypt → per-token balances, spent excluded) | ✅ **Ready** via the `railgun` facade — you inject a `QuickSyncEvents` source |
| Ethereum JSON-RPC / quick-sync / POI / artifacts (the data sources) | ⚠️ **You implement** the trait (`QuickSyncEvents`, `EventProvider`, `POINodeInterface`, `ArtifactGetter`, …) over your own RPC/indexer — trait-only, no bundled HTTP |
| Spend-proof generation (Groth16) | 🟡 **Backend wired** — pure-Rust `ArkCircomBackend` (feature `prover-arkcircom`) reads RAILGUN's real `.zkey`/`.wasm` (verified); a *full* proof still needs valid circuit inputs from the transaction pipeline. See [docs/PROVING.md](docs/PROVING.md) |
| V3 `extract-transaction-data` | ❌ Deferred |

**Bottom line:** you can ship wallet creation/restore, address generation,
encrypted storage, **and a working balance/sync path** today (you supply the
event source). You **cannot** yet ship spending without wiring a Groth16 prover
backend (native rapidsnark + circuit artifacts).

## Framework quick start (the `railgun` crate)

The `railgun` crate is the one-stop front door: register wallets, sync from your
event source, read balances. It re-exports the whole ecosystem
(`railgun::wallet`, `railgun::crypto`, …) and adds the `Railgun` manager.

```rust
use railgun::prelude::*;

# async fn run<Q: QuickSyncEvents>(quick_sync: &Q) -> Result<(), FrameworkError> {
let mut db = Database::in_memory();                 // or your redb-backed KvStore
let key = [0x11u8; 32];
let mnemonic = Mnemonic::generate(128);
let chain = Chain { chain_type: 0, id: 1 };

let wallet = RailgunWallet::from_mnemonic(&mut db, &key, &mnemonic, 0, None)
    .map_err(|e| FrameworkError::Wallet(e.to_string()))?;

let mut rg = Railgun::new(db, chain, TXIDVersion::V2_PoseidonMerkle);
rg.add_wallet(wallet);

// `quick_sync` is YOUR `QuickSyncEvents` impl (RPC/The Graph/indexer).
rg.sync(quick_sync, 0).await?;                       // events → tree → decrypt → store
let balances = rg.token_balances(0)?;               // { tokenHash → amount }, spent excluded
# let _ = balances; Ok(())
# }
```

You implement one trait — `QuickSyncEvents` — returning the chain's
commitment/nullifier/unshield events; the framework builds the UTXO merkletree,
decrypts the notes addressed to your wallet, and computes spendable balances. See
the end-to-end test [`crates/railgun/tests/e2e_sync_balances.rs`](crates/railgun/tests/e2e_sync_balances.rs)
for a complete fixture-driven example (sync → balance → spend → balance).

## Quick start (works today)

```toml
# Cargo.toml — depend on the crates you need (no published versions yet; use a path/git dep)
[dependencies]
railgun-wallet         = { path = "rust/crates/railgun-wallet" }
railgun-db             = { path = "rust/crates/railgun-db" }
railgun-key-derivation = { path = "rust/crates/railgun-key-derivation" }
railgun-models         = { path = "rust/crates/railgun-models" }
```

```rust
use railgun_db::Database;
use railgun_key_derivation::Mnemonic;
use railgun_models::engine_types::Chain;
use railgun_wallet::{RailgunWallet, ViewOnlyWallet};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Storage. `in_memory()` for tests; back it with a real `KvStore` in prod.
    // Wallet secrets are AES-256-GCM-encrypted under `encryption_key` — derive
    // it from the OS keychain / a user password; never hard-code it.
    let mut db = Database::in_memory();
    let encryption_key = [0x11u8; 32];

    // Create a wallet from a fresh 12-word mnemonic at account index 0.
    let mnemonic = Mnemonic::generate(128);
    let wallet = RailgunWallet::from_mnemonic(&mut db, &encryption_key, &mnemonic, 0, None)?;

    // Addresses: 0zk is chain-scoped; 0x is the matching EVM account.
    let ethereum = Chain { chain_type: 0, id: 1 };
    let zk_address = wallet.wallet.get_address(Some(ethereum));
    let evm_address = wallet.get_chain_address(&db, &encryption_key, None)?;

    // Restore later by id (no mnemonic needed to load; only to spend).
    let id = wallet.wallet.id.clone();
    let restored = RailgunWallet::load_existing(&db, &encryption_key, &id, None)?;
    assert_eq!(restored.wallet.get_address(Some(ethereum)), zk_address);

    // Export a view-only key; rebuild a watch-only wallet (same address, can't spend).
    let shareable = wallet.wallet.generate_shareable_viewing_key()?;
    let view_only =
        ViewOnlyWallet::from_shareable_viewing_key(&mut db, &encryption_key, &shareable, None)?;
    assert_eq!(view_only.wallet.get_address(Some(ethereum)), zk_address);

    let _ = (zk_address, evm_address);
    Ok(())
}
```

Run the full version: `cargo run -p railgun-wallet --example desktop_wallet`
([source](crates/railgun-wallet/examples/desktop_wallet.rs)).

### Persistent storage — bring your own DB (no engine is bundled)

`railgun-db` does **not** ship or depend on any database engine (no redb,
rocksdb, sled, leveldb). It defines the `KvStore` trait and one in-memory impl,
`MemStore` (a `BTreeMap`, used by tests). Everything is generic over the
backend, so **your wallet uses its own store** — e.g. your own `redb`.

To wire it up, implement `KvStore` (5 methods) over a single table and pass it
to `Database::new(store)`:

```rust
pub trait KvStore {
    fn put(&mut self, key: String, value: Vec<u8>);
    fn get(&self, key: &str) -> Option<Vec<u8>>;
    fn del(&mut self, key: &str);
    fn range(&self, gte: &str, lte: &str) -> Vec<(String, Vec<u8>)>; // inclusive, lexicographic
    fn clear_range(&mut self, gte: &str, lte: &str);
}
```

The only requirement is a sorted `String -> Vec<u8>` table with inclusive range
scans (for namespace queries). RAILGUN's own key layout and AES-256-GCM value
sealing sit *on top* — your redb just stores opaque bytes, alongside whatever
else your app keeps in the same database.

A complete, compiling redb adapter (≈40 lines) is in
[`examples/redb_backend.rs`](crates/railgun-wallet/examples/redb_backend.rs):
`cargo run -p railgun-wallet --example redb_backend`.

## What you must provide (the trait seams)

The engine never makes network calls itself — it calls traits you implement, so
*you* own where data comes from. To go beyond key management you implement:

| Trait | Crate | Purpose |
|---|---|---|
| `EventProvider` | `railgun-contracts` | `eth_getLogs` / `eth_call` / `getBlockNumber` (wrap `alloy`) |
| `ArtifactGetter` | `railgun-prover` | fetch circuit `wasm`/`zkey`/`vkey`/`dat` bytes (HTTP or bundled files) |
| `Groth16Backend` | `railgun-prover` | generate/verify proofs — wire the native `rapidsnark` (build the crate with `--features rapidsnark` and link `librapidsnark`) |
| `POINodeInterface` | `railgun-poi` | proof-of-innocence node (HTTP/JSON-RPC) |
| `TokenDataGetter` | `railgun-note` | resolve NFT token data on cache miss |
| `QuickSyncEvents` / `MerklerootValidator` | `railgun-engine` | bulk event sync + on-chain merkleroot validation |

Spending additionally requires the engine sync loop (currently stubbed) to build
the UTXO/TXID merkletrees from on-chain events. Until that lands, treat this as a
wallet-keys + crypto library, not a full engine.

## Crate guide

| Crate | Use it for |
|---|---|
| `railgun-utils` | hex / bigint / byte conversions (`ByteUtils`) |
| `railgun-crypto` | Poseidon, BabyJubJub EdDSA, Ed25519, X25519 ECDH, AES-GCM/CTR, XChaCha20-Poly1305, hashes |
| `railgun-key-derivation` | BIP39, BabyJubJub BIP32, wallet keys, `0zk` bech32m addresses |
| `railgun-models` | shared data types / enums (`Chain`, `TokenData`, …) |
| `railgun-db` | `KvStore` + encrypted key/value storage |
| `railgun-note` | shield / unshield / transact notes, memos, token hashing |
| `railgun-merkletree` | UTXO + TXID Poseidon merkle trees |
| `railgun-solutions` | coin selection / spending-solution groups |
| `railgun-transaction` | railgun-txid, bound-params, public-input signing |
| `railgun-poi` | blinded commitments, POI status, POI-node trait |
| `railgun-prover` | Groth16 prover trait + rapidsnark FFI scaffold |
| `railgun-contracts` | V2/V3 contract ABIs + RPC trait seam (`alloy`) |
| `railgun-wallet` | `RailgunWallet`, `ViewOnlyWallet`, `HardwareWallet` |
| `railgun-engine` | lower-level orchestrator + injected trait definitions (`QuickSyncEvents`, …) |
| **`railgun`** | **the framework facade** — unified API, `Railgun` manager (register / sync / balances) |

## Building & testing

```sh
cargo build                 # whole workspace, zero warnings
cargo test                  # 205 tests (KAVs + differential-fuzz replay)
cargo build -p railgun-prover --features rapidsnark   # enable the native prover FFI
just                        # full parallel differential fuzz (random seeds) — see below
```

### Testing

Two layers, both pinning behaviour to the TypeScript reference:

1. **Known-answer vectors** ported from `../src/**/__tests__/*.test.ts`.
2. **Differential fuzzing** — `oracle/gen.ts` runs the *real* TS SDK over a
   deterministic PRNG and writes input→output corpora to `vectors/*.json`;
   `crates/*/tests/fuzz_*.rs` replay them and assert byte-equality.

   From the repo root, **`just`** is the one command: it builds once, then runs
   the unit tests plus several independent fuzz rounds **in parallel**, each
   against a fresh **random**-seed corpus generated by the Bun oracle. A
   divergence prints the exact seed + command to reproduce it.

   ```sh
   just                   # 8 parallel rounds × 400 cases, random seeds
   just fuzz 16 1000      # heavier sweep:  just fuzz [jobs] [count] [seed]
   just fuzz 8 400 42     # reproducible (seeds 42, 43, …)
   ```

   Each fuzz test also honours `RAILGUN_VECTORS_DIR` (the runner points each
   round at its own corpus). Regenerate the committed corpus (so a plain
   `cargo test` works with no Bun) with `NODE_ENV=test bun run
   rust/oracle/gen.ts 12648430 400`.

   Covers ByteUtils, hashes, Poseidon (incl. the 13-input wide path), keys,
   addresses, AES/XChaCha, **EdDSA-Poseidon sign+verify, X25519 note-blinding
   keys, ECIES JSON encrypt/decrypt**, token/note hashing, **nullifiers**,
   railgun-txid, blinded commitments, and tree positions. (The blinding-key
   fuzz caught a real scalar-reduction bug in the port — see git history.)

## Roadmap & design decisions

See [PORT_PLAN.md](PORT_PLAN.md) for the full dependency-ordered roadmap, the
crate mapping, the network inventory, the scaffolded/deferred items, and the
recorded decisions (V2+V3 no-legacy scope, rapidsnark FFI proving, fresh-resync
DB).
