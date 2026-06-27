//! Port of `src/prover/progress-service.ts`.
//!
//! Drives a progress callback linearly between `start_value` and `end_value`,
//! emitting once every `delay_msec` until [`ProgressService::stop`] is called.
//!
//! The TS implementation uses `await delay(...)` to space the callbacks over
//! wall-clock time. The pure computation — how the progress value advances per
//! iteration — is what the tests pin, so it is exposed via
//! [`ProgressService::value_at_iteration`]. The async pacing loop
//! ([`ProgressService::progress_steadily`]) is feature-free and uses
//! `std::thread::sleep` so the crate stays runtime-agnostic; callers that need a
//! tokio-driven version can build one on top of `value_at_iteration`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct ProgressService {
    start_value: f64,
    end_value: f64,
    total_msec: f64,
    delay_msec: f64,
    stopped: Arc<AtomicBool>,
}

impl ProgressService {
    pub fn new(start_value: f64, end_value: f64, total_msec: f64, delay_msec: f64) -> Self {
        Self {
            start_value,
            end_value,
            total_msec,
            delay_msec,
            stopped: Arc::new(AtomicBool::new(false)),
        }
    }

    /// The progress value emitted at `iteration`, mirroring the TS arithmetic
    /// exactly:
    /// `startValue + (iteration / numTotalIterations) * (endValue - startValue)`.
    pub fn value_at_iteration(&self, iteration: usize) -> f64 {
        let num_total_iterations = self.total_msec / self.delay_msec;
        self.start_value
            + (iteration as f64 / num_total_iterations) * (self.end_value - self.start_value)
    }

    fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::SeqCst)
    }

    /// Calls `progress_callback` once every `delay_msec`, progressing linearly
    /// until `stop()` is called or the value would exceed `end_value`.
    pub fn progress_steadily<F: FnMut(f64)>(&self, mut progress_callback: F) {
        let mut iteration = 0usize;
        loop {
            if self.is_stopped() {
                return;
            }
            let current_value = self.value_at_iteration(iteration);
            if current_value > self.end_value {
                return;
            }
            progress_callback(current_value);
            std::thread::sleep(Duration::from_secs_f64(self.delay_msec / 1000.0));
            iteration += 1;
        }
    }

    pub fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_progression_matches_ts_arithmetic() {
        // Mirrors `setSnarkJSGroth16` railgun config: 0 -> 95 over 1500ms / 250ms.
        let service = ProgressService::new(0.0, 95.0, 1500.0, 250.0);
        // numTotalIterations = 1500 / 250 = 6
        assert_eq!(service.value_at_iteration(0), 0.0);
        assert_eq!(service.value_at_iteration(3), 47.5); // 0 + (3/6)*95
        assert_eq!(service.value_at_iteration(6), 95.0);
    }

    #[test]
    fn poi_progression() {
        // POI config: 0 -> 95 over 3000ms / 250ms => numTotalIterations = 12.
        let service = ProgressService::new(0.0, 95.0, 3000.0, 250.0);
        assert_eq!(service.value_at_iteration(0), 0.0);
        assert_eq!(service.value_at_iteration(6), 47.5);
        assert_eq!(service.value_at_iteration(12), 95.0);
    }

    #[test]
    fn stop_halts_loop() {
        let service = ProgressService::new(0.0, 95.0, 1500.0, 1.0);
        let stopper = service.clone();
        let mut count = 0usize;
        // Stop after the first callback via interior mutability of the shared flag.
        service.progress_steadily(|_| {
            count += 1;
            if count == 1 {
                stopper.stop();
            }
        });
        assert_eq!(count, 1);
    }
}
