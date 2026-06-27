//! Prover error type.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProverError {
    #[error("Requires groth16 implementation")]
    NoGroth16Implementation,

    #[error("Requires WASM or DAT prover artifact")]
    MissingArtifact,

    #[error("DAT artifact is required.")]
    MissingDat,

    #[error("No circuit found for {0}")]
    NoCircuit(String),

    #[error("Proof verification failed")]
    VerificationFailed,

    #[error("Invalid blindedCommitmentOut value: expected {expected}, got {got}")]
    InvalidBlindedCommitmentOut { expected: String, got: String },

    /// No proving backend is compiled in (the `rapidsnark` feature is off).
    #[error(
        "No proving backend available: build with the `rapidsnark` feature and link the native prover"
    )]
    NoBackend,

    /// Error surfaced by the native rapidsnark backend.
    #[error("Native prover error: {0}")]
    Native(String),

    /// Error from the injected `ArtifactGetter`.
    #[error("Artifact getter error: {0}")]
    ArtifactGetter(String),

    #[error("{0}")]
    Other(String),
}
