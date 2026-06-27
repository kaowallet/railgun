# Differential-fuzz oracle (Bun)

Uses the **real RAILGUN TypeScript SDK** (`/src/**.ts`) as the ground-truth oracle
for the Rust port. `gen.ts` runs the TS crypto/byte/mnemonic functions over seeded
random + boundary inputs and writes (input, output) corpora to `rust/vectors/`. The
Rust integration tests (`crates/*/tests/fuzz_*.rs`) replay those and assert byte
equality.

## Setup (once)

```sh
bun install            # from repo root — installs the SDK's JS deps (incl. WASM)
```

## Generate a corpus

```sh
NODE_ENV=test bun run rust/oracle/gen.ts [seed] [count]
# default: seed=0xc0ffee, count=400  -> rust/vectors/{bytes,crypto,keyderivation}.json
```

Deterministic: same seed+count ⇒ identical corpus (so the checked-in default is
reproducible and CI-stable).

## Run the Rust side

```sh
cargo test --manifest-path rust/Cargo.toml against_ts_oracle
```

## Fuzz (hunt for divergences)

Sweep seeds — each run is hundreds of fresh inputs per function:

```sh
for s in 11 22 333 4444 55555; do
  NODE_ENV=test bun run rust/oracle/gen.ts $s 250
  cargo test --manifest-path rust/Cargo.toml against_ts_oracle || break
done
```

## What's covered

- **bytes** — hexlify (bytes/bigint), arrayify, nToHex, formatToByteLength,
  padToLength, trim, chunk/combine, hexToBigInt, bytesToN, UTF-8 roundtrip.
- **crypto** — sha256/sha512/keccak256, HMAC-SHA512, Poseidon (arity 1–6, incl.
  inputs ≥ field prime), poseidonHex, BabyJubJub spending keys, Ed25519 viewing
  keys, the FIPS-186 private scalar, and X25519 ECDH (incl. invalid-point ⇒ `None`
  parity).
- **key-derivation** — BIP39 seed/entropy/0x-key, the custom BabyJubJub BIP32
  (master + hardened child), wallet spending/viewing/nullifying keys along random
  hardened paths, and `0zk` address encode+decode roundtrips (with/without chain).

Inputs deliberately include boundary values (0, 1, field-prime − 1, 2²⁵⁶ − 1) and
adversarial cases (values ≥ the field modulus, random 32-byte "public keys" that
are usually invalid curve points).
