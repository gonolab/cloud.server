//! Failed-attempt limiter of the authentication entry points.
//!
//! Each client address has a token bucket of [`BURST`] failed attempts that refills by one
//! token every [`REFILL_INTERVAL`]; every failed verification takes one token with
//! [`RateLimiter::record_failure`], and [`RateLimiter::check`] says whether the bucket is
//! empty. Requests without credentials and successful sign-ins cost nothing. There are two
//! limiters with different policies:
//!
//! - The web login (Argon2 passwords people choose) checks its limiter **before** verifying
//!   and answers `429 Too Many Requests` without verifying anything while the bucket is empty
//!   ([`crate::web`]).
//! - Device authentication (random app passwords and pre-auth tokens) verifies first and
//!   answers only *failures* with `429` while the bucket is empty, so that one failing client
//!   behind a shared address cannot lock out the others ([`crate::auth`]).
//!
//! IPv6 clients are tracked per `/64` network, the smallest block a single host usually
//! controls. The table is bounded: once it holds [`MAX_TRACKED`] clients, buckets that have
//! refilled completely are dropped.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Mutex,
    time::{Duration, Instant},
};

/// Failed attempts a client may make in a burst.
pub const BURST: u32 = 20;

/// Time after which one more failed attempt is allowed.
pub const REFILL_INTERVAL: Duration = Duration::from_secs(10);

/// Number of clients tracked before full buckets are pruned.
const MAX_TRACKED: usize = 4096;

/// Failed-attempt limiter, keyed by client address.
#[derive(Debug, Default)]
pub struct RateLimiter {
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    /// Failed attempts still allowed, as of `updated`.
    tokens: f64,
    updated: Instant,
}

impl Bucket {
    fn full(now: Instant) -> Self {
        Self {
            tokens: f64::from(BURST),
            updated: now,
        }
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.updated);
        let gained = elapsed.as_secs_f64() / REFILL_INTERVAL.as_secs_f64();
        self.tokens = (self.tokens + gained).min(f64::from(BURST));
        self.updated = now;
    }
}

impl RateLimiter {
    /// Creates an empty limiter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns how long `client` has to wait, or `None` if it may try to authenticate now.
    pub fn check(&self, client: IpAddr) -> Option<Duration> {
        self.check_at(client, Instant::now())
    }

    /// Takes one token from `client` after a failed verification.
    pub fn record_failure(&self, client: IpAddr) {
        self.record_failure_at(client, Instant::now());
    }

    fn check_at(&self, client: IpAddr, now: Instant) -> Option<Duration> {
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        let bucket = buckets.get_mut(&key(client))?;
        bucket.refill(now);
        if bucket.tokens >= 1.0 {
            None
        } else {
            Some(REFILL_INTERVAL.mul_f64(1.0 - bucket.tokens))
        }
    }

    fn record_failure_at(&self, client: IpAddr, now: Instant) {
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        if buckets.len() >= MAX_TRACKED {
            buckets.retain(|_, bucket| {
                bucket.refill(now);
                bucket.tokens < f64::from(BURST)
            });
        }
        let bucket = buckets
            .entry(key(client))
            .or_insert_with(|| Bucket::full(now));
        bucket.refill(now);
        bucket.tokens = (bucket.tokens - 1.0).max(0.0);
    }
}

/// IPv4 addresses are tracked individually, IPv6 addresses per /64.
fn key(client: IpAddr) -> IpAddr {
    match client {
        IpAddr::V4(_) => client,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let mut segments = v6.segments();
                segments[4..].fill(0);
                IpAddr::V6(segments.into())
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    #[test]
    fn blocks_after_a_burst_of_failures_and_recovers() {
        let limiter = RateLimiter::new();
        let start = Instant::now();
        let client = ip("192.0.2.1");
        for _ in 0..BURST {
            assert_eq!(limiter.check_at(client, start), None);
            limiter.record_failure_at(client, start);
        }
        let wait = limiter.check_at(client, start).expect("blocked");
        assert!(wait <= REFILL_INTERVAL, "{wait:?}");
        assert_eq!(limiter.check_at(ip("192.0.2.2"), start), None, "per client");

        let later = start + REFILL_INTERVAL;
        assert_eq!(limiter.check_at(client, later), None, "one token refilled");
        limiter.record_failure_at(client, later);
        assert!(limiter.check_at(client, later).is_some());
    }

    #[test]
    fn ipv6_clients_share_a_bucket_per_64() {
        let limiter = RateLimiter::new();
        let now = Instant::now();
        for index in 0..BURST {
            limiter.record_failure_at(ip(&format!("2001:db8::{index:x}")), now);
        }
        assert!(limiter.check_at(ip("2001:db8::ffff"), now).is_some());
        assert_eq!(limiter.check_at(ip("2001:db8:0:1::1"), now), None);
        assert_eq!(key(ip("::ffff:192.0.2.1")), ip("192.0.2.1"));
    }

    #[test]
    fn the_table_stays_bounded() {
        let limiter = RateLimiter::new();
        let now = Instant::now();
        for index in 0..u32::try_from(MAX_TRACKED).unwrap() + 10 {
            limiter.record_failure_at(IpAddr::V4(index.into()), now);
        }
        let later = now + REFILL_INTERVAL * BURST;
        limiter.record_failure_at(ip("198.51.100.1"), later);
        assert!(limiter.buckets.lock().unwrap().len() <= 2);
    }
}
