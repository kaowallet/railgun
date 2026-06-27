//! Pure-Rust Groth16 backend via [`ark-circom`] — reads the circom `.wasm`
//! (witness) + `.zkey` (proving key) and proves with `ark-groth16`. No native
//! library, no GMP: ships as plain Rust on every target.
//!
//! Isolation: ark-circom pulls **arkworks 0.6** (the rest of the workspace is on
//! 0.5). We never expose those types across crate boundaries — inputs arrive as
//! `BigUint`/`FormattedCircuitInputs*` and proofs leave as the decimal-string
//! [`Proof`] struct, so the two arkworks versions never meet.
//!
//! Status: the generic prove/verify engine and the artifact compatibility
//! (`read_zkey` + witness load over the real RAILGUN circuits) are exercised by
//! tests. A *full* RAILGUN proof additionally needs valid circuit inputs from the
//! transaction pipeline (deferred) — the input-name mapping below is the contract
//! with the circom circuit and is validated the first time it runs against real
//! inputs (the witness calculator errors loudly on an unknown signal name).

use std::io::Cursor;

use ark_bn254::{Bn254, Fr};
use ark_circom::{read_zkey, CircomReduction, WitnessCalculator};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::Groth16;
use ark_std::rand::thread_rng;
use ark_std::UniformRand;
use async_trait::async_trait;
use num_bigint::{BigInt, BigUint};
use railgun_models::prover_types::{
    Artifact, FormattedCircuitInputsPOI, FormattedCircuitInputsRailgun, Proof,
};
use wasmer::{Module, Store};

use crate::{Groth16Backend, ProverError};

fn fr_to_dec(fr: &Fr) -> String {
    BigUint::from_bytes_le(&fr.into_bigint().to_bytes_le()).to_string()
}

fn to_bigint(n: &BigUint) -> BigInt {
    BigInt::from(n.clone())
}

/// snarkjs-style proof formatting. NOTE the G2 (`pi_b`) coordinate swap: snarkjs
/// emits each Fq2 as `[c1, c0]` (the reverse of arkworks' internal `c0, c1`),
/// matching what the on-chain BN254 verifier expects.
fn format_proof(proof: &ark_groth16::Proof<Bn254>) -> Proof {
    let g1 = |p: &ark_bn254::G1Affine| [fr_field(&p.x), fr_field(&p.y)];
    Proof {
        pi_a: g1(&proof.a),
        pi_b: [
            [fr_field(&proof.b.x.c1), fr_field(&proof.b.x.c0)],
            [fr_field(&proof.b.y.c1), fr_field(&proof.b.y.c0)],
        ],
        pi_c: g1(&proof.c),
    }
}

fn fr_field(f: &ark_bn254::Fq) -> String {
    BigUint::from_bytes_le(&f.into_bigint().to_bytes_le()).to_string()
}

/// Parse a circom `.zkey` into the proving key + constraint matrices.
pub fn read_proving_key(
    zkey: &[u8],
) -> Result<
    (
        ark_groth16::ProvingKey<Bn254>,
        ark_circom::index::NPIndex<Fr>,
    ),
    ProverError,
> {
    let mut cursor = Cursor::new(zkey);
    read_zkey(&mut cursor).map_err(|e| ProverError::Native(format!("read_zkey: {e}")))
}

/// Load a circom witness-calculator `.wasm` (from bytes) into its wasmer runtime.
pub fn load_witness_calculator(wasm: &[u8]) -> Result<(Store, WitnessCalculator), ProverError> {
    let mut store = Store::default();
    let module =
        Module::new(&store, wasm).map_err(|e| ProverError::Native(format!("wasm module: {e}")))?;
    let wtns = WitnessCalculator::from_module(&mut store, module)
        .map_err(|e| ProverError::Native(format!("witness calculator: {e}")))?;
    Ok((store, wtns))
}

/// Circuit-agnostic Groth16 prove: witness from `wasm` + named `inputs`, proving
/// key from `zkey`. Returns the snarkjs-formatted proof and the public signals.
pub fn prove(
    wasm: &[u8],
    zkey: &[u8],
    inputs: Vec<(String, Vec<BigInt>)>,
) -> Result<(Proof, Vec<String>), ProverError> {
    let (mut store, mut wtns) = load_witness_calculator(wasm)?;
    let full_assignment = wtns
        .calculate_witness_element::<Fr, _>(&mut store, inputs, false)
        .map_err(|e| ProverError::Native(format!("witness: {e}")))?;

    let (pk, matrices) = read_proving_key(zkey)?;
    let num_inputs = matrices.num_instance_variables;
    let num_constraints = matrices.num_constraints;
    let mats = [matrices.a, matrices.b, matrices.c]
        .iter()
        .map(|m| m.clone().into())
        .collect::<Vec<_>>();

    let mut rng = thread_rng();
    let r = Fr::rand(&mut rng);
    let s = Fr::rand(&mut rng);
    let proof = Groth16::<Bn254, CircomReduction>::create_proof_with_reduction_and_matrices(
        &pk,
        r,
        s,
        &mats,
        num_inputs,
        num_constraints,
        full_assignment.as_slice(),
    )
    .map_err(|e| ProverError::Native(format!("create_proof: {e}")))?;

    let public_signals = full_assignment[1..num_inputs]
        .iter()
        .map(fr_to_dec)
        .collect();
    Ok((format_proof(&proof), public_signals))
}

/// Pure-Rust [`Groth16Backend`] over ark-circom.
#[derive(Clone, Copy, Debug, Default)]
pub struct ArkCircomBackend;

#[async_trait]
impl Groth16Backend for ArkCircomBackend {
    async fn full_prove_railgun(
        &self,
        formatted_inputs: &FormattedCircuitInputsRailgun,
        artifacts: &Artifact,
        progress_callback: &mut (dyn FnMut(f64) + Send),
    ) -> Result<Proof, ProverError> {
        progress_callback(0.0);
        let wasm = artifacts
            .wasm
            .as_deref()
            .ok_or(ProverError::MissingArtifact)?;
        let (proof, _public) = prove(wasm, &artifacts.zkey, railgun_inputs(formatted_inputs))?;
        progress_callback(100.0);
        Ok(proof)
    }

    async fn full_prove_poi(
        &self,
        formatted_inputs: &FormattedCircuitInputsPOI,
        artifacts: &Artifact,
        progress_callback: &mut (dyn FnMut(f64) + Send),
    ) -> Result<(Proof, Option<Vec<String>>), ProverError> {
        progress_callback(0.0);
        let wasm = artifacts
            .wasm
            .as_deref()
            .ok_or(ProverError::MissingArtifact)?;
        let (proof, public) = prove(wasm, &artifacts.zkey, poi_inputs(formatted_inputs))?;
        progress_callback(100.0);
        Ok((proof, Some(public)))
    }
    // `verify` uses the trait default (`None` = skip wallet-side check; on-chain
    // verification still runs). A pure-Rust verifier can be added by parsing the
    // snarkjs vkey JSON into an ark VerifyingKey.
}

/// `FormattedCircuitInputsRailgun` -> circom signal names. These names are the
/// contract with the RAILGUN transaction circuit (validated when run with real
/// inputs).
fn railgun_inputs(f: &FormattedCircuitInputsRailgun) -> Vec<(String, Vec<BigInt>)> {
    let one = |n: &BigUint| vec![to_bigint(n)];
    let many = |v: &[BigUint]| v.iter().map(to_bigint).collect::<Vec<_>>();
    vec![
        ("merkleRoot".into(), one(&f.merkle_root)),
        ("boundParamsHash".into(), one(&f.bound_params_hash)),
        ("nullifiers".into(), many(&f.nullifiers)),
        ("commitmentsOut".into(), many(&f.commitments_out)),
        ("token".into(), one(&f.token)),
        ("publicKey".into(), many(&f.public_key)),
        ("signature".into(), many(&f.signature)),
        ("randomIn".into(), many(&f.random_in)),
        ("valueIn".into(), many(&f.value_in)),
        ("pathElements".into(), many(&f.path_elements)),
        ("leavesIndices".into(), many(&f.leaves_indices)),
        ("nullifyingKey".into(), one(&f.nullifying_key)),
        ("npkOut".into(), many(&f.npk_out)),
        ("valueOut".into(), many(&f.value_out)),
    ]
}

/// `FormattedCircuitInputsPOI` -> circom signal names (the 2-D path-elements
/// signal is flattened row-major, as the witness calculator expects).
fn poi_inputs(f: &FormattedCircuitInputsPOI) -> Vec<(String, Vec<BigInt>)> {
    let one = |n: &BigUint| vec![to_bigint(n)];
    let many = |v: &[BigUint]| v.iter().map(to_bigint).collect::<Vec<_>>();
    let flat = f
        .poi_in_merkle_proof_path_elements
        .iter()
        .flatten()
        .map(to_bigint)
        .collect::<Vec<_>>();
    vec![
        (
            "anyRailgunTxidMerklerootAfterTransaction".into(),
            one(&f.any_railgun_txid_merkleroot_after_transaction),
        ),
        ("poiMerkleroots".into(), many(&f.poi_merkleroots)),
        ("boundParamsHash".into(), one(&f.bound_params_hash)),
        ("nullifiers".into(), many(&f.nullifiers)),
        ("commitmentsOut".into(), many(&f.commitments_out)),
        ("spendingPublicKey".into(), many(&f.spending_public_key)),
        ("nullifyingKey".into(), one(&f.nullifying_key)),
        ("token".into(), one(&f.token)),
        ("randomsIn".into(), many(&f.randoms_in)),
        ("valuesIn".into(), many(&f.values_in)),
        ("utxoPositionsIn".into(), many(&f.utxo_positions_in)),
        ("utxoTreeIn".into(), one(&f.utxo_tree_in)),
        ("npksOut".into(), many(&f.npks_out)),
        ("valuesOut".into(), many(&f.values_out)),
        (
            "utxoBatchGlobalStartPositionOut".into(),
            one(&f.utxo_batch_global_start_position_out),
        ),
        (
            "railgunTxidIfHasUnshield".into(),
            one(&f.railgun_txid_if_has_unshield),
        ),
        (
            "railgunTxidMerkleProofIndices".into(),
            one(&f.railgun_txid_merkle_proof_indices),
        ),
        (
            "railgunTxidMerkleProofPathElements".into(),
            many(&f.railgun_txid_merkle_proof_path_elements),
        ),
        (
            "poiInMerkleProofIndices".into(),
            many(&f.poi_in_merkle_proof_indices),
        ),
        ("poiInMerkleProofPathElements".into(), flat),
    ]
}

#[cfg(all(test, feature = "bundled-test-artifacts"))]
mod tests {
    use super::*;
    use crate::bundled_artifacts::BundledArtifactGetter;
    use crate::ArtifactGetter;
    use num_bigint::BigUint;
    use railgun_models::prover_types::PublicInputsRailgun;

    fn pub_inputs(n: usize, m: usize) -> PublicInputsRailgun {
        PublicInputsRailgun {
            merkle_root: BigUint::from(0u8),
            bound_params_hash: BigUint::from(0u8),
            nullifiers: vec![BigUint::from(0u8); n],
            commitments_out: vec![BigUint::from(0u8); m],
        }
    }

    // ark-circom reads RAILGUN's real proving key (the compatibility proof).
    #[tokio::test]
    async fn read_zkey_parses_real_railgun_circuit() {
        let getter = BundledArtifactGetter::repo_test_artifacts();
        let artifact = getter.get_artifacts(&pub_inputs(1, 2)).await.unwrap();

        let (_pk, matrices) = read_proving_key(&artifact.zkey).unwrap();
        assert!(matrices.num_constraints > 0, "real circuit has constraints");
        // num_instance_variables == nPublic + 1; the 1x2 vkey reports nPublic = 5.
        assert_eq!(matrices.num_instance_variables, 6);
    }

    // The real witness-calculator .wasm instantiates in the wasmer runtime.
    #[tokio::test]
    async fn witness_calculator_loads_real_wasm() {
        let getter = BundledArtifactGetter::repo_test_artifacts();
        let artifact = getter.get_artifacts(&pub_inputs(1, 2)).await.unwrap();
        let wasm = artifact.wasm.expect("wasm");
        let (_store, _wtns) = load_witness_calculator(&wasm).unwrap();
    }

    // POI circuit artifacts parse too.
    #[tokio::test]
    async fn read_zkey_parses_real_poi_circuit() {
        let getter = BundledArtifactGetter::repo_test_artifacts();
        let artifact = getter.get_artifacts_poi(3, 3).await.unwrap();
        let (_pk, matrices) = read_proving_key(&artifact.zkey).unwrap();
        assert!(matrices.num_constraints > 0);
        load_witness_calculator(&artifact.wasm.unwrap()).unwrap();
    }
}
