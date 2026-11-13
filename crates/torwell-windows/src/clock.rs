use std::time::{Duration, Instant};

/// Monotonic time and sleeping, injectable so timeouts are testable without waiting.
pub trait Clock {
    /// Elapsed time since an arbitrary fixed origin.
    fn now(&self) -> Duration;
    fn sleep(&self, d: Duration);
}

pub struct SystemClock(Instant);

impl SystemClock {
    pub fn new() -> Self {
        Self(Instant::now())
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Duration {
        self.0.elapsed()
    }
    fn sleep(&self, d: Duration) {
        std::thread::sleep(d);
    }
}
