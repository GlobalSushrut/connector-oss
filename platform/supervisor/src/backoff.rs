use std::time::Duration;

/// Exponential backoff with cap (restart policy).
#[derive(Debug, Clone)]
pub struct Backoff {
    base: Duration,
    max: Duration,
    attempt: u32,
}

impl Backoff {
    pub fn new(base: Duration, max: Duration) -> Self {
        Self {
            base,
            max,
            attempt: 0,
        }
    }

    /// Next sleep before retry; advances internal attempt counter.
    pub fn next_sleep(&mut self) -> Duration {
        let shift = self.attempt.min(20);
        self.attempt = self.attempt.saturating_add(1);
        let mul = 1u128 << shift;
        let ms = (self.base.as_millis() as u128)
            .saturating_mul(mul)
            .min(self.max.as_millis() as u128);
        Duration::from_millis(u64::try_from(ms).unwrap_or(self.max.as_millis() as u64))
    }

    pub fn attempt(&self) -> u32 {
        self.attempt
    }

    pub fn reset(&mut self) {
        self.attempt = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_then_caps() {
        let mut b = Backoff::new(Duration::from_millis(100), Duration::from_millis(500));
        assert_eq!(b.next_sleep(), Duration::from_millis(100));
        assert_eq!(b.next_sleep(), Duration::from_millis(200));
        assert_eq!(b.next_sleep(), Duration::from_millis(400));
        assert_eq!(b.next_sleep(), Duration::from_millis(500));
    }
}
