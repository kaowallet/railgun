//! `railgun-prover` — Groth16 prove/verify, proof caches, and progress service.
//!
//! Port of `src/prover/` (`prover.ts`, `proof-cache.ts`, `proof-cache-poi.ts`,
//! `progress-service.ts`) plus the `ArtifactGetter` interface from
//! `src/models/prover-types.ts`.
//!
//! ## Design
//!
//! - **Crypto is not re-implemented.** Field/byte conversions go through
//!   `railgun-utils`; proof structs live in `railgun-models::prover_types`.
//! - **Proving is via the native rapidsnark backend** (PORT_PLAN.md §Decisions
//!   2). It lives behind the [`rapidsnark`](crate::rapidsnark) module, gated by
//!   the `rapidsnark` cargo feature. Without the feature the crate still
//!   compiles; real proving returns [`ProverError::NoBackend`].
//! - **`ArtifactGetter`** is an injected async trait — the caller fetches
//!   circuit `.zkey`/`.wasm`/`.dat`/`.vkey` over HTTP or filesystem; the prover
//!   never fetches.
//! - **`Groth16Backend`** abstracts the actual prove/verify so snarkjs, the
//!   native prover, or a test fake can all plug in.
//!
//! The *pure-logic* pieces — public-input derivation, proof formatting, input
//! formatting (padding) and the proof caches — are ported with KAV tests.
//! Real proof generation/verification requires the native lib + artifacts and
//! is deferred (see TODOs).

#[cfg(feature = "ark-circom")]
pub mod ark_circom_backend;
#[cfg(feature = "bundled-test-artifacts")]
pub mod bundled_artifacts;
pub mod error;
pub mod progress_service;
pub mod proof_cache;
pub mod proof_cache_poi;
pub mod rapidsnark;

#[cfg(feature = "ark-circom")]
pub use ark_circom_backend::ArkCircomBackend;
#[cfg(feature = "bundled-test-artifacts")]
pub use bundled_artifacts::BundledArtifactGetter;

use async_trait::async_trait;
use num_bigint::BigUint;
use num_traits::Zero;

use railgun_models::merkletree_types::merkle_zero_value_bigint;
use railgun_models::poi_types::POIEngineProofInputs;
use railgun_models::prover_types::{
    Artifact, FormattedCircuitInputsPOI, FormattedCircuitInputsRailgun, G1Point, G2Point, Proof,
    PublicInputsPOI, PublicInputsRailgun, SnarkProof,
};
use railgun_utils::{hex_to_bigint, n_to_hex, ByteLength};

pub use error::ProverError;
pub use progress_service::ProgressService;
pub use proof_cache::ProofCache;
pub use proof_cache_poi::ProofCachePOI;

/// Progress callback, called with a 0-100 percentage.
pub type ProverProgressCallback<'a> = dyn FnMut(f64) + 'a;

/// `ArtifactGetter` — injected dependency. The caller fetches Groth16 circuit
/// artifacts over HTTP or filesystem; the prover only calls these. Mirrors the
/// TS `ArtifactGetter` type but async (the TS methods return Promises).
#[async_trait]
pub trait ArtifactGetter: Send + Sync {
    /// Asserts artifacts exist for the given input/output counts; used by the
    /// dummy prover. Synchronous in the TS.
    fn assert_artifact_exists(
        &self,
        nullifiers: usize,
        commitments: usize,
    ) -> Result<(), ProverError>;

    async fn get_artifacts(
        &self,
        public_inputs: &PublicInputsRailgun,
    ) -> Result<Artifact, ProverError>;

    async fn get_artifacts_poi(
        &self,
        max_inputs: usize,
        max_outputs: usize,
    ) -> Result<Artifact, ProverError>;
}

/// `Groth16Implementation` — the prove/verify backend. Abstracts the snarkjs /
/// native rapidsnark / test backends behind one trait.
///
/// `verify` returning `None` mirrors the TS where the native prover supplies no
/// verifier (`verify: undefined`) — wallet-side verification is then skipped as
/// a fail-safe; on-chain/gas-estimate verification still occurs.
#[async_trait]
pub trait Groth16Backend: Send + Sync {
    async fn full_prove_railgun(
        &self,
        formatted_inputs: &FormattedCircuitInputsRailgun,
        artifacts: &Artifact,
        progress_callback: &mut (dyn FnMut(f64) + Send),
    ) -> Result<Proof, ProverError>;

    async fn full_prove_poi(
        &self,
        formatted_inputs: &FormattedCircuitInputsPOI,
        artifacts: &Artifact,
        progress_callback: &mut (dyn FnMut(f64) + Send),
    ) -> Result<(Proof, Option<Vec<String>>), ProverError>;

    /// Verify a proof against the vkey + public signals. `None` means "no
    /// verifier available" (skip wallet-side check).
    async fn verify(
        &self,
        _vkey: &[u8],
        _public_signals: &[BigUint],
        _proof: &Proof,
    ) -> Option<bool> {
        None
    }
}

/// `Prover` — orchestrates artifact fetch, input formatting, proving and
/// caching. Generic over the injected [`ArtifactGetter`] and an optional
/// [`Groth16Backend`].
pub struct Prover<A: ArtifactGetter> {
    artifact_getter: A,
    groth16: Option<Box<dyn Groth16Backend>>,
    railgun_cache: ProofCache,
    poi_cache: ProofCachePOI,
}

impl<A: ArtifactGetter> Prover<A> {
    pub fn new(artifact_getter: A) -> Self {
        Self {
            artifact_getter,
            groth16: None,
            railgun_cache: ProofCache::new(),
            poi_cache: ProofCachePOI::new(),
        }
    }

    /// Inject the Groth16 backend (snarkjs / native / fake).
    pub fn set_groth16(&mut self, backend: Box<dyn Groth16Backend>) {
        self.groth16 = Some(backend);
    }

    pub fn artifact_getter(&self) -> &A {
        &self.artifact_getter
    }

    // ----- zero / dummy proof -----

    /// `Prover.zeroProof` — all field elements are the 1-byte hex `"00"`.
    pub fn zero_proof() -> Proof {
        let zero = n_to_hex(&BigUint::zero(), ByteLength::Uint8, false);
        Proof {
            pi_a: [zero.clone(), zero.clone()],
            pi_b: [[zero.clone(), zero.clone()], [zero.clone(), zero.clone()]],
            pi_c: [zero.clone(), zero],
        }
    }

    /// `dummyProveRailgun` — asserts artifacts exist (the dummy proof itself
    /// does not use them) and returns the zero proof.
    pub fn dummy_prove_railgun(
        &self,
        public_inputs: &PublicInputsRailgun,
    ) -> Result<Proof, ProverError> {
        self.artifact_getter.assert_artifact_exists(
            public_inputs.nullifiers.len(),
            public_inputs.commitments_out.len(),
        )?;
        Ok(Self::zero_proof())
    }

    // ----- public-input derivation (pure) -----

    /// `getPublicInputsPOI`. Pure: builds the padded POI public inputs.
    pub fn get_public_inputs_poi(
        any_railgun_txid_merkleroot_after_transaction: &str,
        blinded_commitments_out: &[String],
        poi_merkleroots: &[String],
        railgun_txid_if_has_unshield: &str,
        max_inputs: usize,
        max_outputs: usize,
    ) -> PublicInputsPOI {
        PublicInputsPOI {
            blinded_commitments_out: pad_with_zeros_to_max(
                blinded_commitments_out
                    .iter()
                    .map(|x| hex_to_bigint(x))
                    .collect(),
                max_outputs,
                // Use Zero = 0 here (TS passes 0n explicitly).
                BigUint::zero(),
            ),
            railgun_txid_if_has_unshield: hex_to_bigint(railgun_txid_if_has_unshield),
            any_railgun_txid_merkleroot_after_transaction: hex_to_bigint(
                any_railgun_txid_merkleroot_after_transaction,
            ),
            poi_merkleroots: pad_with_zeros_to_max(
                poi_merkleroots.iter().map(|x| hex_to_bigint(x)).collect(),
                max_inputs,
                zero_value_poi(),
            ),
        }
    }

    /// `getMaxInputsOutputsForPOI`: 3x3 "mini" circuit if both <= 3, else 13x13.
    pub fn get_max_inputs_outputs_for_poi(inputs: &POIEngineProofInputs) -> (usize, usize) {
        if inputs.nullifiers.len() <= 3 && inputs.commitments_out.len() <= 3 {
            (3, 3)
        } else {
            (13, 13)
        }
    }

    // ----- proof / input formatting (pure) -----

    /// `Prover.formatProof` — note the b-point coordinate swap (snarkjs G2
    /// little-endian -> Solidity verifier ordering).
    pub fn format_proof(proof: &Proof) -> SnarkProof {
        let to_n = |s: &str| -> BigUint {
            // snarkjs emits decimal strings.
            s.parse::<BigUint>().unwrap_or_default()
        };
        SnarkProof {
            a: G1Point {
                x: to_n(&proof.pi_a[0]),
                y: to_n(&proof.pi_a[1]),
            },
            b: G2Point {
                x: [to_n(&proof.pi_b[0][1]), to_n(&proof.pi_b[0][0])],
                y: [to_n(&proof.pi_b[1][1]), to_n(&proof.pi_b[1][0])],
            },
            c: G1Point {
                x: to_n(&proof.pi_c[0]),
                y: to_n(&proof.pi_c[1]),
            },
        }
    }

    /// `formatPOIInputs` — pads to the circuit's max sizes. Pure.
    pub fn format_poi_inputs(
        proof_inputs: &POIEngineProofInputs,
        max_inputs: usize,
        max_outputs: usize,
    ) -> FormattedCircuitInputsPOI {
        let zero = zero_value_poi();
        FormattedCircuitInputsPOI {
            any_railgun_txid_merkleroot_after_transaction: hex_to_bigint(
                &proof_inputs.any_railgun_txid_merkleroot_after_transaction,
            ),
            bound_params_hash: hex_to_bigint(&proof_inputs.bound_params_hash),
            nullifiers: pad_with_zeros_to_max(
                proof_inputs
                    .nullifiers
                    .iter()
                    .map(|x| hex_to_bigint(x))
                    .collect(),
                max_inputs,
                zero.clone(),
            ),
            commitments_out: pad_with_zeros_to_max(
                proof_inputs
                    .commitments_out
                    .iter()
                    .map(|x| hex_to_bigint(x))
                    .collect(),
                max_outputs,
                zero.clone(),
            ),
            spending_public_key: proof_inputs.spending_public_key.clone(),
            nullifying_key: proof_inputs.nullifying_key.clone(),
            token: hex_to_bigint(&proof_inputs.token),
            randoms_in: pad_with_zeros_to_max(
                proof_inputs
                    .randoms_in
                    .iter()
                    .map(|x| hex_to_bigint(x))
                    .collect(),
                max_inputs,
                zero.clone(),
            ),
            values_in: pad_with_zeros_to_max(
                proof_inputs.values_in.clone(),
                max_outputs,
                // Use Zero = 0 here.
                BigUint::zero(),
            ),
            utxo_positions_in: pad_with_zeros_to_max(
                proof_inputs
                    .utxo_positions_in
                    .iter()
                    .map(|x| BigUint::from(*x))
                    .collect(),
                max_inputs,
                zero.clone(),
            ),
            utxo_tree_in: BigUint::from(proof_inputs.utxo_tree_in),
            npks_out: pad_with_zeros_to_max(
                proof_inputs.npks_out.clone(),
                max_outputs,
                zero.clone(),
            ),
            values_out: pad_with_zeros_to_max(
                proof_inputs.values_out.clone(),
                max_outputs,
                BigUint::zero(),
            ),
            utxo_batch_global_start_position_out: proof_inputs
                .utxo_batch_global_start_position_out
                .clone(),
            railgun_txid_if_has_unshield: hex_to_bigint(&proof_inputs.railgun_txid_if_has_unshield),
            railgun_txid_merkle_proof_indices: hex_to_bigint(
                &proof_inputs.railgun_txid_merkle_proof_indices,
            ),
            railgun_txid_merkle_proof_path_elements: proof_inputs
                .railgun_txid_merkle_proof_path_elements
                .iter()
                .map(|x| hex_to_bigint(x))
                .collect(),
            poi_merkleroots: pad_with_zeros_to_max(
                proof_inputs
                    .poi_merkleroots
                    .iter()
                    .map(|x| hex_to_bigint(x))
                    .collect(),
                max_inputs,
                zero.clone(),
            ),
            poi_in_merkle_proof_indices: pad_with_zeros_to_max(
                proof_inputs
                    .poi_in_merkle_proof_indices
                    .iter()
                    .map(|x| hex_to_bigint(x))
                    .collect(),
                max_inputs,
                // Use Zero = 0 here.
                BigUint::zero(),
            ),
            poi_in_merkle_proof_path_elements: pad_with_arrays_of_zeros_to_max_and_length(
                proof_inputs
                    .poi_in_merkle_proof_path_elements
                    .iter()
                    .map(|path| path.iter().map(|x| hex_to_bigint(x)).collect())
                    .collect(),
                max_inputs,
                16,
                zero,
            ),
        }
    }

    // ----- verification (delegates to backend) -----

    /// `verifyRailgunProof`. If no backend verifier is available, returns `true`
    /// (fail-safe; on-chain verification still occurs).
    pub async fn verify_railgun_proof(
        &self,
        public_inputs: &PublicInputsRailgun,
        proof: &Proof,
        artifacts: &Artifact,
    ) -> Result<bool, ProverError> {
        let groth16 = self
            .groth16
            .as_ref()
            .ok_or(ProverError::NoGroth16Implementation)?;

        let mut public_signals: Vec<BigUint> = Vec::new();
        public_signals.push(public_inputs.merkle_root.clone());
        public_signals.push(public_inputs.bound_params_hash.clone());
        public_signals.extend(public_inputs.nullifiers.iter().cloned());
        public_signals.extend(public_inputs.commitments_out.iter().cloned());

        match groth16
            .verify(&artifacts.vkey, &public_signals, proof)
            .await
        {
            None => Ok(true),
            Some(ok) => Ok(ok),
        }
    }

    /// `verifyPOIProof`. Public-signal ordering MUST match the circuit:
    /// `[...blindedCommitmentsOut, anyRailgunTxidMerklerootAfterTransaction,
    ///   railgunTxidIfHasUnshield, ...poiMerkleroots]`.
    pub async fn verify_poi_proof(
        &self,
        public_inputs: &PublicInputsPOI,
        proof: &Proof,
        max_inputs: usize,
        max_outputs: usize,
    ) -> Result<bool, ProverError> {
        let groth16 = self
            .groth16
            .as_ref()
            .ok_or(ProverError::NoGroth16Implementation)?;

        let artifacts = self
            .artifact_getter
            .get_artifacts_poi(max_inputs, max_outputs)
            .await?;

        let mut public_signals: Vec<BigUint> = Vec::new();
        public_signals.extend(public_inputs.blinded_commitments_out.iter().cloned());
        public_signals.push(
            public_inputs
                .any_railgun_txid_merkleroot_after_transaction
                .clone(),
        );
        public_signals.push(public_inputs.railgun_txid_if_has_unshield.clone());
        public_signals.extend(public_inputs.poi_merkleroots.iter().cloned());

        match groth16
            .verify(&artifacts.vkey, &public_signals, proof)
            .await
        {
            None => Ok(true),
            Some(ok) => Ok(ok),
        }
    }

    // ----- POI proving -----

    /// `provePOI` — picks the circuit size, then proves.
    pub async fn prove_poi(
        &self,
        inputs: &POIEngineProofInputs,
        list_key: &str,
        blinded_commitments_in: &[String],
        blinded_commitments_out: &[String],
        progress_callback: &mut (dyn FnMut(f64) + Send),
    ) -> Result<(Proof, PublicInputsPOI), ProverError> {
        let (max_inputs, max_outputs) = Self::get_max_inputs_outputs_for_poi(inputs);
        self.prove_poi_for_inputs_outputs(
            inputs,
            list_key,
            blinded_commitments_in,
            blinded_commitments_out,
            max_inputs,
            max_outputs,
            progress_callback,
        )
        .await
    }

    /// `provePOIForInputsOutputs`.
    #[allow(clippy::too_many_arguments)]
    pub async fn prove_poi_for_inputs_outputs(
        &self,
        inputs: &POIEngineProofInputs,
        list_key: &str,
        _blinded_commitments_in: &[String],
        blinded_commitments_out: &[String],
        max_inputs: usize,
        max_outputs: usize,
        progress_callback: &mut (dyn FnMut(f64) + Send),
    ) -> Result<(Proof, PublicInputsPOI), ProverError> {
        let groth16 = self
            .groth16
            .as_ref()
            .ok_or(ProverError::NoGroth16Implementation)?;

        let public_inputs = Self::get_public_inputs_poi(
            &inputs.any_railgun_txid_merkleroot_after_transaction,
            blinded_commitments_out,
            &inputs.poi_merkleroots,
            &inputs.railgun_txid_if_has_unshield,
            max_inputs,
            max_outputs,
        );

        // Cache hit (re-verified before reuse).
        if let Some(existing) = self.poi_cache.get(
            list_key,
            &inputs.any_railgun_txid_merkleroot_after_transaction,
            blinded_commitments_out,
            &inputs.poi_merkleroots,
            &inputs.railgun_txid_if_has_unshield,
        ) {
            if self
                .verify_poi_proof(&public_inputs, &existing, max_inputs, max_outputs)
                .await?
            {
                return Ok((existing, public_inputs));
            }
        }

        progress_callback(5.0);

        let artifacts = self
            .artifact_getter
            .get_artifacts_poi(max_inputs, max_outputs)
            .await?;
        if artifacts.wasm.is_none() && artifacts.dat.is_none() {
            return Err(ProverError::MissingArtifact);
        }

        let formatted_inputs = Self::format_poi_inputs(inputs, max_inputs, max_outputs);

        let initial = 10.0;
        let final_ = 95.0;
        progress_callback(initial);

        let (proof, public_signals) = {
            let mut inner = |progress: f64| {
                progress_callback((progress * (final_ - initial)) / 100.0 + initial);
            };
            groth16
                .full_prove_poi(&formatted_inputs, &artifacts, &mut inner)
                .await?
        };

        // If snarkjs provides publicSignals, validate the blinded commitments.
        if let Some(public_signals) = public_signals {
            for (i, _bc) in blinded_commitments_out.iter().enumerate() {
                let expected = public_inputs.blinded_commitments_out[i].to_string();
                let got = public_signals.get(i).cloned().unwrap_or_default();
                if expected != got {
                    return Err(ProverError::InvalidBlindedCommitmentOut {
                        expected: got,
                        got: expected,
                    });
                }
            }
        }

        progress_callback(final_);

        // Trim the proof to the 3 points (snarkjs adds extra fields).
        let snark_proof = Proof {
            pi_a: [proof.pi_a[0].clone(), proof.pi_a[1].clone()],
            pi_b: [
                [proof.pi_b[0][0].clone(), proof.pi_b[0][1].clone()],
                [proof.pi_b[1][0].clone(), proof.pi_b[1][1].clone()],
            ],
            pi_c: [proof.pi_c[0].clone(), proof.pi_c[1].clone()],
        };

        if !self
            .verify_poi_proof(&public_inputs, &snark_proof, max_inputs, max_outputs)
            .await?
        {
            return Err(ProverError::VerificationFailed);
        }

        self.poi_cache.store(
            list_key,
            &inputs.any_railgun_txid_merkleroot_after_transaction,
            blinded_commitments_out,
            &inputs.poi_merkleroots,
            &inputs.railgun_txid_if_has_unshield,
            snark_proof.clone(),
        );

        progress_callback(100.0);

        Ok((snark_proof, public_inputs))
    }

    pub fn proof_cache(&self) -> &ProofCache {
        &self.railgun_cache
    }

    pub fn poi_cache(&self) -> &ProofCachePOI {
        &self.poi_cache
    }
}

// ----- pure helpers (module-level, mirror the TS static methods) -----

/// `ZERO_VALUE_POI = MERKLE_ZERO_VALUE_BIGINT`.
pub fn zero_value_poi() -> BigUint {
    merkle_zero_value_bigint()
}

/// `padWithZerosToMax`.
pub fn pad_with_zeros_to_max(
    mut array: Vec<BigUint>,
    max: usize,
    zero_value: BigUint,
) -> Vec<BigUint> {
    while array.len() < max {
        array.push(zero_value.clone());
    }
    array
}

/// `padWithArraysOfZerosToMaxAndLength`.
pub fn pad_with_arrays_of_zeros_to_max_and_length(
    mut double_array: Vec<Vec<BigUint>>,
    max: usize,
    length: usize,
    zero_value: BigUint,
) -> Vec<Vec<BigUint>> {
    while double_array.len() < max {
        double_array.push(vec![zero_value.clone(); length]);
    }
    double_array
}

#[cfg(test)]
mod tests {
    use super::*;
    use railgun_models::prover_types::Artifact;

    // ----- ArtifactGetter test fake -----
    struct FakeArtifactGetter;

    #[async_trait]
    impl ArtifactGetter for FakeArtifactGetter {
        fn assert_artifact_exists(&self, _n: usize, _c: usize) -> Result<(), ProverError> {
            Ok(())
        }
        async fn get_artifacts(
            &self,
            _public_inputs: &PublicInputsRailgun,
        ) -> Result<Artifact, ProverError> {
            Ok(Artifact::default())
        }
        async fn get_artifacts_poi(
            &self,
            _max_inputs: usize,
            _max_outputs: usize,
        ) -> Result<Artifact, ProverError> {
            Ok(Artifact::default())
        }
    }

    // ----- KAV: zero proof -----
    #[test]
    fn zero_proof_is_all_zero_byte_hex() {
        let p = Prover::<FakeArtifactGetter>::zero_proof();
        assert_eq!(p.pi_a, ["00".to_string(), "00".to_string()]);
        assert_eq!(
            p.pi_b,
            [
                ["00".to_string(), "00".to_string()],
                ["00".to_string(), "00".to_string()]
            ]
        );
        assert_eq!(p.pi_c, ["00".to_string(), "00".to_string()]);
    }

    #[test]
    fn dummy_prove_railgun_returns_zero_proof() {
        let prover = Prover::new(FakeArtifactGetter);
        let pi = PublicInputsRailgun {
            merkle_root: BigUint::from(1u8),
            bound_params_hash: BigUint::from(2u8),
            nullifiers: vec![BigUint::from(3u8)],
            commitments_out: vec![BigUint::from(4u8), BigUint::from(5u8)],
        };
        let proof = prover.dummy_prove_railgun(&pi).unwrap();
        assert_eq!(proof, Prover::<FakeArtifactGetter>::zero_proof());
    }

    // ----- KAV: formatProof coordinate swap -----
    #[test]
    fn format_proof_swaps_g2_coordinates() {
        let proof = Proof {
            pi_a: ["1".into(), "2".into()],
            pi_b: [["10".into(), "11".into()], ["20".into(), "21".into()]],
            pi_c: ["7".into(), "8".into()],
        };
        let s = Prover::<FakeArtifactGetter>::format_proof(&proof);
        assert_eq!(s.a.x, BigUint::from(1u8));
        assert_eq!(s.a.y, BigUint::from(2u8));
        // b.x = [pi_b[0][1], pi_b[0][0]] -> [11, 10]
        assert_eq!(s.b.x, [BigUint::from(11u8), BigUint::from(10u8)]);
        // b.y = [pi_b[1][1], pi_b[1][0]] -> [21, 20]
        assert_eq!(s.b.y, [BigUint::from(21u8), BigUint::from(20u8)]);
        assert_eq!(s.c.x, BigUint::from(7u8));
        assert_eq!(s.c.y, BigUint::from(8u8));
    }

    // ----- KAV: getPublicInputsPOI derivation (3x3) from test-vector-poi.json -----
    //
    // Ported from prover.test.ts "Should generate and validate POI proof - 3x3":
    // blindedCommitmentsOut = [] (empty), so it pads to 3 zeros.
    #[test]
    fn get_public_inputs_poi_3x3_from_test_vector() {
        let any_root = "185cc7d2c8e1c3954ee5421a6589cd05036708ff059b97b9c10e0261ad7d6875";
        let poi_merkleroots =
            vec!["05821c33a316fcf991536a5e744753f5a31c5ef14804df906f746aaad16cb4ac".to_string()];
        let railgun_txid_if_has_unshield =
            "0x018d6143a22e09c18ba2a713985bd1e43a095605d5d259d72d96da2cca604f3e";
        let blinded_commitments_out: Vec<String> = vec![]; // empty in the vector

        let pi = Prover::<FakeArtifactGetter>::get_public_inputs_poi(
            any_root,
            &blinded_commitments_out,
            &poi_merkleroots,
            railgun_txid_if_has_unshield,
            3,
            3,
        );

        // Lengths padded to max.
        assert_eq!(pi.poi_merkleroots.len(), 3);
        assert_eq!(pi.blinded_commitments_out.len(), 3);

        // anyRailgunTxidMerklerootAfterTransaction
        assert_eq!(
            pi.any_railgun_txid_merkleroot_after_transaction,
            hex_to_bigint(any_root)
        );
        // railgunTxidIfHasUnshield
        assert_eq!(
            pi.railgun_txid_if_has_unshield,
            hex_to_bigint(railgun_txid_if_has_unshield)
        );

        // first poi merkleroot is the parsed hex; padding uses ZERO_VALUE_POI.
        assert_eq!(pi.poi_merkleroots[0], hex_to_bigint(&poi_merkleroots[0]));
        assert_eq!(pi.poi_merkleroots[1], zero_value_poi());
        assert_eq!(pi.poi_merkleroots[2], zero_value_poi());

        // blindedCommitmentsOut padding uses 0 (NOT the merkle zero value).
        assert_eq!(pi.blinded_commitments_out[0], BigUint::zero());
        assert_eq!(pi.blinded_commitments_out[1], BigUint::zero());
        assert_eq!(pi.blinded_commitments_out[2], BigUint::zero());
    }

    // ----- KAV: getPublicInputsPOI derivation (13x13) -----
    #[test]
    fn get_public_inputs_poi_13x13_from_test_vector() {
        let any_root = "185cc7d2c8e1c3954ee5421a6589cd05036708ff059b97b9c10e0261ad7d6875";
        let poi_merkleroots =
            vec!["05821c33a316fcf991536a5e744753f5a31c5ef14804df906f746aaad16cb4ac".to_string()];
        let railgun_txid_if_has_unshield =
            "0x018d6143a22e09c18ba2a713985bd1e43a095605d5d259d72d96da2cca604f3e";

        let pi = Prover::<FakeArtifactGetter>::get_public_inputs_poi(
            any_root,
            &[],
            &poi_merkleroots,
            railgun_txid_if_has_unshield,
            13,
            13,
        );
        assert_eq!(pi.poi_merkleroots.len(), 13);
        assert_eq!(pi.blinded_commitments_out.len(), 13);
        assert_eq!(pi.poi_merkleroots[0], hex_to_bigint(&poi_merkleroots[0]));
        for r in &pi.poi_merkleroots[1..] {
            assert_eq!(*r, zero_value_poi());
        }
        for bc in &pi.blinded_commitments_out {
            assert_eq!(*bc, BigUint::zero());
        }
    }

    // ----- KAV: known railgunTxidIfHasUnshield value from test vector -----
    // From the test vector, railgunTxidIfHasUnshield decimal == this bigint.
    #[test]
    fn railgun_txid_if_has_unshield_bigint() {
        let hex = "0x018d6143a22e09c18ba2a713985bd1e43a095605d5d259d72d96da2cca604f3e";
        let expected = BigUint::parse_bytes(
            b"702109577508614192687157007886308755723992845597739802305604799122078977854",
            10,
        )
        .unwrap();
        assert_eq!(hex_to_bigint(hex), expected);
    }

    // ----- pad helpers -----
    #[test]
    fn pad_with_zeros_uses_custom_zero() {
        let out = pad_with_zeros_to_max(vec![BigUint::from(9u8)], 3, BigUint::from(7u8));
        assert_eq!(
            out,
            vec![BigUint::from(9u8), BigUint::from(7u8), BigUint::from(7u8)]
        );
    }

    #[test]
    fn pad_arrays_of_zeros() {
        let out = pad_with_arrays_of_zeros_to_max_and_length(
            vec![vec![BigUint::from(1u8), BigUint::from(2u8)]],
            3,
            2,
            BigUint::zero(),
        );
        assert_eq!(out.len(), 3);
        assert_eq!(out[1], vec![BigUint::zero(), BigUint::zero()]);
        assert_eq!(out[2], vec![BigUint::zero(), BigUint::zero()]);
    }
}
