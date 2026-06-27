# Proving (Groth16)

RAILGUN spends require a Groth16 proof over circom circuits. The framework keeps
proving behind two seams in `railgun-prover`:

- **`Groth16Backend`** — generates/verifies the proof.
- **`ArtifactGetter`** — supplies each circuit's `.wasm` (witness calculator) +
  `.zkey` (proving key) + `.vkey` (verifying key) (+ `.dat` for POI).

Both are caller-injected; the prover never fetches or links anything itself.

## Backend: ark-circom (pure Rust) — the chosen default

`ArkCircomBackend` (feature `ark-circom`) proves with [`ark-circom`] +
`ark-groth16` — it reads the circom `.wasm` and `.zkey` directly. **No native
library, no GMP, no per-platform CI matrix** — it ships as plain Rust on every
target. (ark-circom pulls arkworks 0.6 internally; it's isolated from the
workspace's 0.5 — proofs cross the boundary only as the decimal-string `Proof`
struct.)

Enable it via the facade:

```toml
railgun = { path = "...", features = ["prover-arkcircom"] }
```

```rust
use railgun::prover::{ArkCircomBackend, Prover};
let mut prover = Prover::new(my_artifact_getter);
prover.set_groth16(Box::new(ArkCircomBackend));
```

### What's verified vs pending

- ✅ **Artifact compatibility** — `read_zkey` parses RAILGUN's real proving keys
  and the witness-calculator `.wasm` instantiates, for both a transaction circuit
  (1x2) and a POI circuit (3x3). See the tests in `ark_circom_backend.rs`.
- ✅ **Generic prove/verify engine** + the `Groth16Backend` wiring compile.
- ⏳ **A full RAILGUN proof** also needs valid circuit inputs assembled by the
  transaction pipeline (deferred). The `FormattedCircuitInputs* → circom signal
  name` mapping in `ark_circom_backend.rs` is the contract with the circuit; the
  witness calculator errors loudly on a wrong signal name, so it's validated the
  first time it runs against real inputs.
- ⏳ **On-chain verifier parity** — confirm the `pi_b` G2 coordinate order (snarkjs
  swaps Fq2 to `[c1, c0]`, which the backend follows) matches the deployed BN254
  verifier before relying on a proof in production.

### Alternative: rapidsnark (FFI)

Faster, but requires building + statically linking `librapidsnark` + a witness
calculator + GMP per target. Scaffolded behind the `rapidsnark` feature
(`rapidsnark.rs`); the default returns `ProverError::NoBackend`. Prefer
ark-circom unless proving speed becomes the bottleneck — the `Groth16Backend`
seam lets you swap later without touching the rest of the framework.

## Artifacts

Circuits are large (`.zkey` is tens–hundreds of MB each, many circuits). Don't
embed them in the binary.

- **Tests / dev:** `BundledArtifactGetter` (feature `bundled-test-artifacts`)
  loads the repo's brotli-compressed `src/test/test-artifacts-lite/` circuits
  from disk — no network. This is the "testing-purpose fetch".
- **Production:** implement `ArtifactGetter` to **download the official RAILGUN
  artifacts on first use and cache to disk** (brotli-decompress `.zkey.br`/
  `.wasm.br`). The `.zkey` must come from RAILGUN's official trusted setup so it
  matches the on-chain verifier — do not regenerate keys.

Both produce the same `Artifact { wasm, zkey, vkey, dat }` the backend consumes.
