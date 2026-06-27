//! A **test/dev** [`ArtifactGetter`](crate::ArtifactGetter) that loads circuits
//! from the repo's `src/test/test-artifacts-lite/` directory (the same
//! brotli-compressed `wasm`/`zkey`/`vkey`/`dat` artifacts the TS suite uses).
//!
//! This is deliberately offline — no HTTP. A production wallet would implement
//! `ArtifactGetter` to download + cache the official RAILGUN artifacts (see the
//! `railgun-prover` docs / PROVING.md). Gated behind the `bundled-test-artifacts`
//! feature.

use std::io::Read;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use railgun_models::prover_types::{Artifact, PublicInputsRailgun};

use crate::{ArtifactGetter, ProverError};

/// Loads RAILGUN circuit artifacts from a local `test-artifacts-lite`-style tree:
/// `<root>/<n>x<m>/{wasm.br, zkey.br, vkey.json}` for transaction circuits and
/// `<root>/poi/<i>x<o>/{wasm.br, zkey.br, dat.br, vkey.json}` for POI circuits.
#[derive(Clone, Debug)]
pub struct BundledArtifactGetter {
    root: PathBuf,
}

impl BundledArtifactGetter {
    /// Use an explicit artifacts root directory.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Point at the repo's checked-in `src/test/test-artifacts-lite` (resolved
    /// relative to this crate), for use in tests.
    pub fn repo_test_artifacts() -> Self {
        let root =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../src/test/test-artifacts-lite");
        Self::new(root)
    }

    fn read_decompress(&self, path: &Path) -> Result<Vec<u8>, ProverError> {
        let bytes = std::fs::read(path)
            .map_err(|e| ProverError::ArtifactGetter(format!("read {}: {e}", path.display())))?;
        let mut out = Vec::new();
        brotli::Decompressor::new(&bytes[..], 4096)
            .read_to_end(&mut out)
            .map_err(|e| ProverError::ArtifactGetter(format!("brotli {}: {e}", path.display())))?;
        Ok(out)
    }

    fn read_raw(&self, path: &Path) -> Result<Vec<u8>, ProverError> {
        std::fs::read(path)
            .map_err(|e| ProverError::ArtifactGetter(format!("read {}: {e}", path.display())))
    }

    fn load_dir(&self, dir: &Path, with_dat: bool) -> Result<Artifact, ProverError> {
        if !dir.is_dir() {
            return Err(ProverError::ArtifactGetter(format!(
                "no artifacts at {}",
                dir.display()
            )));
        }
        Ok(Artifact {
            wasm: Some(self.read_decompress(&dir.join("wasm.br"))?),
            zkey: self.read_decompress(&dir.join("zkey.br"))?,
            vkey: self.read_raw(&dir.join("vkey.json"))?,
            dat: if with_dat {
                Some(self.read_decompress(&dir.join("dat.br"))?)
            } else {
                None
            },
        })
    }

    fn transaction_dir(&self, nullifiers: usize, commitments: usize) -> PathBuf {
        self.root.join(format!("{nullifiers}x{commitments}"))
    }

    fn poi_dir(&self, max_inputs: usize, max_outputs: usize) -> PathBuf {
        self.root
            .join("poi")
            .join(format!("{max_inputs}x{max_outputs}"))
    }
}

#[async_trait]
impl ArtifactGetter for BundledArtifactGetter {
    fn assert_artifact_exists(
        &self,
        nullifiers: usize,
        commitments: usize,
    ) -> Result<(), ProverError> {
        let dir = self.transaction_dir(nullifiers, commitments);
        if dir.is_dir() {
            Ok(())
        } else {
            Err(ProverError::ArtifactGetter(format!(
                "no circuit for {nullifiers}x{commitments}"
            )))
        }
    }

    async fn get_artifacts(
        &self,
        public_inputs: &PublicInputsRailgun,
    ) -> Result<Artifact, ProverError> {
        let dir = self.transaction_dir(
            public_inputs.nullifiers.len(),
            public_inputs.commitments_out.len(),
        );
        self.load_dir(&dir, false)
    }

    async fn get_artifacts_poi(
        &self,
        max_inputs: usize,
        max_outputs: usize,
    ) -> Result<Artifact, ProverError> {
        let dir = self.poi_dir(max_inputs, max_outputs);
        self.load_dir(&dir, true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;

    fn pub_inputs(nullifiers: usize, commitments: usize) -> PublicInputsRailgun {
        PublicInputsRailgun {
            merkle_root: BigUint::from(0u8),
            bound_params_hash: BigUint::from(0u8),
            nullifiers: vec![BigUint::from(0u8); nullifiers],
            commitments_out: vec![BigUint::from(0u8); commitments],
        }
    }

    #[tokio::test]
    async fn loads_transaction_circuit_1x2() {
        let getter = BundledArtifactGetter::repo_test_artifacts();
        getter.assert_artifact_exists(1, 2).unwrap();
        let a = getter.get_artifacts(&pub_inputs(1, 2)).await.unwrap();

        // wasm magic header "\0asm"
        let wasm = a.wasm.expect("wasm present");
        assert_eq!(&wasm[..4], b"\0asm", "decompressed wasm has the wasm magic");
        assert!(a.zkey.len() > 1000, "zkey decompressed to a real key");
        assert!(a.dat.is_none());

        // vkey is the snarkjs groth16 verifying key
        let vkey: serde_json::Value = serde_json::from_slice(&a.vkey).unwrap();
        assert_eq!(vkey["protocol"], "groth16");
        assert_eq!(vkey["curve"], "bn128");
    }

    #[tokio::test]
    async fn loads_poi_circuit_3x3_with_dat() {
        let getter = BundledArtifactGetter::repo_test_artifacts();
        let a = getter.get_artifacts_poi(3, 3).await.unwrap();
        assert_eq!(&a.wasm.unwrap()[..4], b"\0asm");
        assert!(a.zkey.len() > 1000);
        assert!(a.dat.is_some(), "POI circuits ship a .dat witness graph");
        let vkey: serde_json::Value = serde_json::from_slice(&a.vkey).unwrap();
        assert_eq!(vkey["protocol"], "groth16");
    }

    #[tokio::test]
    async fn missing_circuit_errors() {
        let getter = BundledArtifactGetter::repo_test_artifacts();
        assert!(getter.get_artifacts(&pub_inputs(99, 99)).await.is_err());
    }
}
