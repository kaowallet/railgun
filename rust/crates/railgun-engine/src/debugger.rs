//! Port of `src/debugger/debugger.ts` — a thin `tracing` wrapper.
//!
//! The TS `EngineDebug` is a static singleton holding an optional injected
//! `EngineDebugger`. Here we keep the same surface (`log`, `error`,
//! `verbose_scan_logging`) but bridge to the `tracing` crate so the host
//! application controls sinks/filters. An optional injected [`EngineDebugger`]
//! mirrors the TS behaviour for callers that want their own callback.

use std::sync::RwLock;

/// `EngineDebugger` — injected debug sink (port of the TS interface).
pub trait EngineDebugger: Send + Sync {
    fn log(&self, msg: &str);
    fn error(&self, err: &str);
    fn verbose_scan_logging(&self) -> bool {
        false
    }
}

static DEBUGGER: RwLock<Option<Box<dyn EngineDebugger>>> = RwLock::new(None);

/// `EngineDebug` — static debug helper, port of the TS singleton class.
pub struct EngineDebug;

impl EngineDebug {
    /// `EngineDebug.init` — install an injected debugger.
    pub fn init(debugger: Box<dyn EngineDebugger>) {
        if let Ok(mut guard) = DEBUGGER.write() {
            *guard = Some(debugger);
        }
    }

    /// `EngineDebug.log` — emit a debug line. Always traces; also forwards to the
    /// injected debugger if present.
    pub fn log(msg: &str) {
        tracing::debug!(target: "railgun_engine", "{msg}");
        if let Ok(guard) = DEBUGGER.read() {
            if let Some(d) = guard.as_ref() {
                d.log(msg);
            }
        }
    }

    /// `EngineDebug.error`.
    pub fn error(err: &str) {
        tracing::error!(target: "railgun_engine", "{err}");
        if let Ok(guard) = DEBUGGER.read() {
            if let Some(d) = guard.as_ref() {
                d.error(err);
            }
        }
    }

    /// `EngineDebug.verboseScanLogging`.
    pub fn verbose_scan_logging() -> bool {
        DEBUGGER
            .read()
            .ok()
            .and_then(|g| g.as_ref().map(|d| d.verbose_scan_logging()))
            .unwrap_or(false)
    }
}
