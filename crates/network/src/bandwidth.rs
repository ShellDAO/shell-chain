//! Bandwidth tracking and rate limiting for P2P connections.
//!
//! Provides a thread-safe [`BandwidthTracker`] that monitors inbound/outbound
//! byte rates per second. When configured limits are exceeded, `record_*`
//! methods return `false` so the caller can log warnings or shed load.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Snapshot of current bandwidth usage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BandwidthStats {
    /// Inbound bytes recorded in the current one-second window.
    pub inbound_bytes_per_sec: u64,
    /// Outbound bytes recorded in the current one-second window.
    pub outbound_bytes_per_sec: u64,
    /// Cumulative inbound bytes since tracker creation.
    pub total_inbound: u64,
    /// Cumulative outbound bytes since tracker creation.
    pub total_outbound: u64,
}

#[derive(Debug)]
struct TokenBucket {
    tokens: u64,
    refill_per_sec: u64,
    capacity: u64,
    last_refill: Instant,
    refill_remainder: u128,
}

impl TokenBucket {
    fn new(refill_per_sec: u64) -> Self {
        let capacity = refill_per_sec.saturating_add(refill_per_sec / 2);
        Self {
            tokens: refill_per_sec,
            refill_per_sec,
            capacity,
            last_refill: Instant::now(),
            refill_remainder: 0,
        }
    }

    fn refill(&mut self, now: Instant) {
        let elapsed_nanos = now.saturating_duration_since(self.last_refill).as_nanos();
        if elapsed_nanos == 0 || self.refill_per_sec == 0 {
            return;
        }

        let nanos_per_sec = Duration::from_secs(1).as_nanos();
        let credit = elapsed_nanos
            .saturating_mul(self.refill_per_sec as u128)
            .saturating_add(self.refill_remainder);
        let refill = credit / nanos_per_sec;
        self.tokens = (self.tokens as u128 + refill).min(self.capacity as u128) as u64;
        // Consume elapsed time once, retaining only the fractional token credit.
        // Idle time beyond the burst capacity must not fund later requests.
        self.refill_remainder = if self.tokens == self.capacity {
            0
        } else {
            credit % nanos_per_sec
        };
        self.last_refill = now;
    }

    fn allow(&mut self, bytes: u64, now: Instant) -> bool {
        self.refill(now);
        if bytes > self.tokens {
            return false;
        }
        self.tokens -= bytes;
        true
    }
}

/// Thread-safe bandwidth tracker with smoothed token-bucket rate limiting.
///
/// Window counters (`inbound_bytes` / `outbound_bytes`) still report the current
/// one-second usage and are reset by [`reset_if_needed`], while enforcement uses
/// token buckets so short bursts can be absorbed without the hard edges of a
/// fixed-window limiter. A limit of `0` means **unlimited**.
pub struct BandwidthTracker {
    inbound_bytes: Arc<AtomicU64>,
    outbound_bytes: Arc<AtomicU64>,
    total_inbound: Arc<AtomicU64>,
    total_outbound: Arc<AtomicU64>,
    max_inbound: u64,
    max_outbound: u64,
    inbound_limiter: Option<Mutex<TokenBucket>>,
    outbound_limiter: Option<Mutex<TokenBucket>>,
    last_reset: Mutex<Instant>,
}

impl BandwidthTracker {
    /// Create a new tracker.
    ///
    /// `max_in` / `max_out` are bytes-per-second limits; pass `0` for unlimited.
    pub fn new(max_in: u64, max_out: u64) -> Self {
        Self {
            inbound_bytes: Arc::new(AtomicU64::new(0)),
            outbound_bytes: Arc::new(AtomicU64::new(0)),
            total_inbound: Arc::new(AtomicU64::new(0)),
            total_outbound: Arc::new(AtomicU64::new(0)),
            max_inbound: max_in,
            max_outbound: max_out,
            inbound_limiter: (max_in != 0).then(|| Mutex::new(TokenBucket::new(max_in))),
            outbound_limiter: (max_out != 0).then(|| Mutex::new(TokenBucket::new(max_out))),
            last_reset: Mutex::new(Instant::now()),
        }
    }

    fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
        match mutex.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn saturating_add_counter(counter: &AtomicU64, bytes: u64) {
        let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
            Some(v.saturating_add(bytes))
        });
    }

    fn record_limited(
        bytes: u64,
        total_counter: &AtomicU64,
        window_counter: &AtomicU64,
        max_bytes: u64,
        limiter: &Option<Mutex<TokenBucket>>,
    ) -> bool {
        Self::saturating_add_counter(total_counter, bytes);
        if max_bytes == 0 {
            Self::saturating_add_counter(window_counter, bytes);
            return true;
        }

        let Some(limiter) = limiter else {
            Self::saturating_add_counter(window_counter, bytes);
            return true;
        };
        let allowed = Self::lock_unpoisoned(limiter).allow(bytes, Instant::now());
        if allowed {
            Self::saturating_add_counter(window_counter, bytes);
        }
        allowed
    }

    /// Record `bytes` of inbound traffic. Returns `false` if the configured
    /// per-second inbound limit would be exceeded (bytes NOT counted when over limit).
    pub fn record_inbound(&self, bytes: u64) -> bool {
        Self::record_limited(
            bytes,
            &self.total_inbound,
            &self.inbound_bytes,
            self.max_inbound,
            &self.inbound_limiter,
        )
    }

    /// Record `bytes` of outbound traffic. Returns `false` if the configured
    /// per-second outbound limit would be exceeded (bytes NOT counted when over limit).
    pub fn record_outbound(&self, bytes: u64) -> bool {
        Self::record_limited(
            bytes,
            &self.total_outbound,
            &self.outbound_bytes,
            self.max_outbound,
            &self.outbound_limiter,
        )
    }

    /// Reset per-second counters if at least one second has elapsed.
    pub fn reset_if_needed(&self) {
        let mut last = Self::lock_unpoisoned(&self.last_reset);
        if last.elapsed() >= Duration::from_secs(1) {
            let now = Instant::now();
            if let Some(limiter) = &self.inbound_limiter {
                Self::lock_unpoisoned(limiter).refill(now);
            }
            if let Some(limiter) = &self.outbound_limiter {
                Self::lock_unpoisoned(limiter).refill(now);
            }

            self.inbound_bytes.store(0, Ordering::SeqCst);
            self.outbound_bytes.store(0, Ordering::SeqCst);
            *last = now;
        }
    }

    /// Return a snapshot of current usage.
    pub fn stats(&self) -> BandwidthStats {
        BandwidthStats {
            inbound_bytes_per_sec: self.inbound_bytes.load(Ordering::Relaxed),
            outbound_bytes_per_sec: self.outbound_bytes.load(Ordering::Relaxed),
            total_inbound: self.total_inbound.load(Ordering::Relaxed),
            total_outbound: self.total_outbound.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unlimited_always_allows() {
        let tracker = BandwidthTracker::new(0, 0);
        assert!(tracker.record_inbound(u64::MAX / 2));
        assert!(tracker.record_outbound(u64::MAX / 2));
    }

    #[test]
    fn inbound_limit_triggers() {
        // Use limit=1 so a rejected retry cannot be made flaky by sub-ms refill.
        let tracker = BandwidthTracker::new(1, 0);
        assert!(tracker.record_inbound(1));
        assert!(!tracker.record_inbound(1));
    }

    #[test]
    fn outbound_limit_triggers() {
        // Use limit=1 so that a single token takes 1 second to refill — the test
        // is then immune to sub-millisecond timing jitter on slow CI machines.
        let tracker = BandwidthTracker::new(0, 1);
        assert!(tracker.record_outbound(1));
        assert!(!tracker.record_outbound(1));
    }

    #[test]
    fn rejected_bytes_not_counted_in_window() {
        let tracker = BandwidthTracker::new(100, 0);
        assert!(tracker.record_inbound(100));
        assert!(!tracker.record_inbound(101)); // rejected
                                               // Window counter stays at 100, not 201
        assert_eq!(tracker.stats().inbound_bytes_per_sec, 100);
    }

    #[test]
    fn reset_clears_window_counters() {
        let tracker = BandwidthTracker::new(1, 1);
        assert!(tracker.record_inbound(1));
        assert!(!tracker.record_inbound(1));
        assert!(tracker.record_outbound(1));
        assert!(!tracker.record_outbound(1));

        // Force a reset by backdating both the stats window and limiter clock.
        {
            let mut last = tracker.last_reset.lock().unwrap();
            *last = Instant::now() - Duration::from_secs(2);
        }
        {
            let mut limiter = tracker.inbound_limiter.as_ref().unwrap().lock().unwrap();
            limiter.last_refill = Instant::now() - Duration::from_secs(2);
        }
        {
            let mut limiter = tracker.outbound_limiter.as_ref().unwrap().lock().unwrap();
            limiter.last_refill = Instant::now() - Duration::from_secs(2);
        }
        tracker.reset_if_needed();

        // Window counters are zeroed; should be allowed again.
        assert!(tracker.record_inbound(1));
        assert!(tracker.record_outbound(1));
    }

    #[test]
    fn stats_reflect_current_usage() {
        let tracker = BandwidthTracker::new(0, 0);
        tracker.record_inbound(42);
        tracker.record_outbound(84);

        let s = tracker.stats();
        assert_eq!(s.inbound_bytes_per_sec, 42);
        assert_eq!(s.outbound_bytes_per_sec, 84);
        assert_eq!(s.total_inbound, 42);
        assert_eq!(s.total_outbound, 84);
    }

    #[test]
    fn total_counters_survive_reset() {
        let tracker = BandwidthTracker::new(100, 100);
        tracker.record_inbound(50);
        tracker.record_outbound(75);

        // Force reset.
        {
            let mut last = tracker.last_reset.lock().unwrap();
            *last = Instant::now() - std::time::Duration::from_secs(2);
        }
        tracker.reset_if_needed();

        tracker.record_inbound(10);
        tracker.record_outbound(20);

        let s = tracker.stats();
        assert_eq!(s.inbound_bytes_per_sec, 10);
        assert_eq!(s.outbound_bytes_per_sec, 20);
        assert_eq!(s.total_inbound, 60);
        assert_eq!(s.total_outbound, 95);
    }

    #[test]
    fn total_counters_saturate_not_wrap() {
        let tracker = BandwidthTracker::new(0, 0);
        // Pre-fill near max
        tracker
            .total_inbound
            .store(u64::MAX - 10, Ordering::Relaxed);
        tracker.record_inbound(100);
        assert_eq!(tracker.stats().total_inbound, u64::MAX);
    }

    #[test]
    fn window_counters_saturate_not_wrap() {
        let tracker = BandwidthTracker::new(0, 0);
        tracker
            .inbound_bytes
            .store(u64::MAX - 10, Ordering::Relaxed);
        tracker
            .outbound_bytes
            .store(u64::MAX - 5, Ordering::Relaxed);

        assert!(tracker.record_inbound(100));
        assert!(tracker.record_outbound(100));

        let stats = tracker.stats();
        assert_eq!(stats.inbound_bytes_per_sec, u64::MAX);
        assert_eq!(stats.outbound_bytes_per_sec, u64::MAX);
    }

    #[test]
    fn no_reset_within_one_second() {
        let tracker = BandwidthTracker::new(100, 100);
        tracker.record_inbound(80);
        tracker.reset_if_needed(); // less than 1s elapsed — should be a no-op
        let s = tracker.stats();
        assert_eq!(s.inbound_bytes_per_sec, 80);
    }

    #[test]
    fn token_bucket_allows_smoothed_burst_after_idle_refill() {
        let now = Instant::now();
        let mut bucket = TokenBucket::new(100);
        bucket.last_refill = now;
        assert!(bucket.allow(100, now));
        assert!(!bucket.allow(1, now));

        assert!(bucket.allow(150, now + Duration::from_millis(1500)));
        assert!(!bucket.allow(1, now + Duration::from_millis(1500)));
    }

    #[test]
    fn token_bucket_caps_idle_credit_at_burst_capacity() {
        let tracker = BandwidthTracker::new(100, 0);
        assert!(tracker.record_inbound(100));

        {
            let mut limiter = tracker.inbound_limiter.as_ref().unwrap().lock().unwrap();
            limiter.last_refill = Instant::now() - Duration::from_secs(10);
        }

        assert!(tracker.record_inbound(150));
        assert!(!tracker.record_inbound(151));
    }

    #[test]
    fn token_bucket_cannot_reuse_elapsed_time_at_high_rates() {
        for rate in [1_250_000_000, 1_500_000_000, 2_000_000_000, 2_500_000_000] {
            let mut bucket = TokenBucket::new(rate);
            let start = bucket.last_refill;
            assert!(bucket.allow(rate, start));
            let now = start + Duration::from_nanos(1);
            let admitted = (0..16).filter(|_| bucket.allow(1, now)).count();
            assert_eq!(admitted as u64, rate / 1_000_000_000, "rate={rate}");
        }
    }

    #[test]
    fn token_bucket_retains_fractional_refill_credit() {
        let mut bucket = TokenBucket::new(3);
        let start = bucket.last_refill;
        assert!(bucket.allow(3, start));
        for millis in 1..=1000 {
            let allowed = bucket.allow(1, start + Duration::from_millis(millis));
            assert_eq!(allowed, matches!(millis, 334 | 667 | 1000));
        }
    }

    #[test]
    fn token_bucket_discards_excess_idle_credit_at_maximum_rate() {
        let mut bucket = TokenBucket::new(u64::MAX);
        let start = bucket.last_refill;
        assert!(bucket.allow(u64::MAX, start));
        let now = start + Duration::from_secs(10);
        assert!(bucket.allow(u64::MAX, now));
        assert!(!bucket.allow(1, now));
    }

    #[test]
    fn poisoned_limiter_lock_does_not_panic() {
        let tracker = Arc::new(BandwidthTracker::new(10, 0));
        let poisoned = Arc::clone(&tracker);
        let _ = std::thread::spawn(move || {
            let _guard = poisoned.inbound_limiter.as_ref().unwrap().lock().unwrap();
            panic!("poison inbound limiter for test");
        })
        .join();

        assert!(std::panic::catch_unwind(|| tracker.record_inbound(1)).is_ok());
    }

    #[test]
    fn poisoned_reset_lock_does_not_panic() {
        let tracker = Arc::new(BandwidthTracker::new(10, 10));
        let poisoned = Arc::clone(&tracker);
        let _ = std::thread::spawn(move || {
            let _guard = poisoned.last_reset.lock().unwrap();
            panic!("poison reset lock for test");
        })
        .join();

        assert!(std::panic::catch_unwind(|| tracker.reset_if_needed()).is_ok());
    }

    #[test]
    fn default_config_bandwidth_unlimited() {
        use crate::config::NetworkConfig;
        let cfg = NetworkConfig::default();
        assert_eq!(cfg.max_inbound_bandwidth, 0);
        assert_eq!(cfg.max_outbound_bandwidth, 0);
    }
}
