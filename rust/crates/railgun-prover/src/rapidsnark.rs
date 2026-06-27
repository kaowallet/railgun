//! Native rapidsnark FFI backend.
//!
//! DECISION (PORT_PLAN.md §Decisions 2): ZK proving is delegated to the native
//! rapidsnark prover + witness calculator via FFI. The native library and the
//! circuit artifacts (`.zkey`/`.dat`) are not present in this workspace, so:
//!
//! - With the `rapidsnark` cargo feature, this module declares the `extern "C"`
//!   entry points and wraps them in a safe [`prove_groth16`] helper. Linking
//!   against the real `librapidsnark` is the integrator's responsibility (build
//!   script / `-l` flags); the symbols below mirror the rapidsnark C API.
//! - Without the feature, [`prove_groth16`] returns
//!   [`ProverError::NoBackend`], and the FFI symbols are not referenced — the
//!   crate compiles cleanly for downstream crates that do not need proving.
//!
//! The rapidsnark public entry point is roughly:
//! ```c
//! int groth16_prover(
//!     const void *zkey_buffer,   unsigned long zkey_size,
//!     const void *wtns_buffer,   unsigned long wtns_size,
//!     char       *proof_buffer,  unsigned long *proof_size,
//!     char       *public_buffer, unsigned long *public_size,
//!     char       *error_msg,     unsigned long  error_msg_max_size);
//! ```
//! Witness calculation (circuit `.dat` + inputs JSON -> `.wtns`) is performed by
//! the companion witness-calculator library; its symbol is declared here too.

use crate::error::ProverError;

#[cfg(feature = "rapidsnark")]
mod ffi {
    use std::os::raw::{c_char, c_int, c_ulong, c_void};

    extern "C" {
        /// rapidsnark Groth16 prover. Returns 0 on success.
        pub fn groth16_prover(
            zkey_buffer: *const c_void,
            zkey_size: c_ulong,
            wtns_buffer: *const c_void,
            wtns_size: c_ulong,
            proof_buffer: *mut c_char,
            proof_size: *mut c_ulong,
            public_buffer: *mut c_char,
            public_size: *mut c_ulong,
            error_msg: *mut c_char,
            error_msg_max_size: c_ulong,
        ) -> c_int;

        /// Witness calculator: circuit `.dat` + JSON inputs -> binary `.wtns`.
        /// Returns 0 on success.
        pub fn witnesscalc(
            circuit_buffer: *const c_void,
            circuit_size: c_ulong,
            json_buffer: *const c_char,
            json_size: c_ulong,
            wtns_buffer: *mut c_char,
            wtns_size: *mut c_ulong,
            error_msg: *mut c_char,
            error_msg_max_size: c_ulong,
        ) -> c_int;
    }
}

/// Output of a native prove: the snarkjs-style proof JSON and the public
/// signals JSON, exactly as rapidsnark emits them.
#[derive(Clone, Debug)]
pub struct NativeProveOutput {
    pub proof_json: String,
    pub public_signals_json: String,
}

/// Run the native Groth16 prover over a zkey, a circuit `.dat`, and the
/// formatted inputs JSON.
///
/// Without the `rapidsnark` feature this returns [`ProverError::NoBackend`].
#[cfg(feature = "rapidsnark")]
pub fn prove_groth16(
    zkey: &[u8],
    dat: &[u8],
    inputs_json: &str,
) -> Result<NativeProveOutput, ProverError> {
    use std::os::raw::{c_char, c_ulong, c_void};

    // 1. Witness calculation.
    let mut wtns = vec![0u8; 100 * 1024 * 1024];
    let mut wtns_size: c_ulong = wtns.len() as c_ulong;
    let mut err_buf = vec![0u8; 4096];

    let rc = unsafe {
        ffi::witnesscalc(
            dat.as_ptr() as *const c_void,
            dat.len() as c_ulong,
            inputs_json.as_ptr() as *const c_char,
            inputs_json.len() as c_ulong,
            wtns.as_mut_ptr() as *mut c_char,
            &mut wtns_size,
            err_buf.as_mut_ptr() as *mut c_char,
            err_buf.len() as c_ulong,
        )
    };
    if rc != 0 {
        return Err(ProverError::Native(c_error_string(&err_buf)));
    }
    wtns.truncate(wtns_size as usize);

    // 2. Proof generation.
    let mut proof = vec![0u8; 4 * 1024 * 1024];
    let mut proof_size: c_ulong = proof.len() as c_ulong;
    let mut public_buf = vec![0u8; 4 * 1024 * 1024];
    let mut public_size: c_ulong = public_buf.len() as c_ulong;

    let rc = unsafe {
        ffi::groth16_prover(
            zkey.as_ptr() as *const c_void,
            zkey.len() as c_ulong,
            wtns.as_ptr() as *const c_void,
            wtns.len() as c_ulong,
            proof.as_mut_ptr() as *mut c_char,
            &mut proof_size,
            public_buf.as_mut_ptr() as *mut c_char,
            &mut public_size,
            err_buf.as_mut_ptr() as *mut c_char,
            err_buf.len() as c_ulong,
        )
    };
    if rc != 0 {
        return Err(ProverError::Native(c_error_string(&err_buf)));
    }
    proof.truncate(proof_size as usize);
    public_buf.truncate(public_size as usize);

    Ok(NativeProveOutput {
        proof_json: String::from_utf8_lossy(&proof)
            .trim_end_matches('\0')
            .to_string(),
        public_signals_json: String::from_utf8_lossy(&public_buf)
            .trim_end_matches('\0')
            .to_string(),
    })
}

#[cfg(feature = "rapidsnark")]
fn c_error_string(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).to_string()
}

/// Stub when the native backend is not compiled in.
#[cfg(not(feature = "rapidsnark"))]
pub fn prove_groth16(
    _zkey: &[u8],
    _dat: &[u8],
    _inputs_json: &str,
) -> Result<NativeProveOutput, ProverError> {
    Err(ProverError::NoBackend)
}
