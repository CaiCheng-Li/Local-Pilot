//! Per-principal request rate and concurrency limits (plan section 40).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use parking_lot::Mutex;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

struct Bucket {
    tokens: f64,
    last: Instant,
}

#[derive(Default)]
pub struct RateLimiter {
    buckets: Mutex<HashMap<String, Bucket>>,
    concurrency: Mutex<HashMap<String, (usize, Arc<Semaphore>)>>,
}

pub enum Limit {
    Allowed(OwnedSemaphorePermit),
    RateLimited { retry_after_secs: u64 },
    TooManyConcurrent,
}

impl RateLimiter {
    /// Token bucket (`per_minute` capacity, continuous refill) plus a
    /// per-principal concurrency semaphore held for the request's duration.
    pub fn check(&self, key: &str, per_minute: u32, max_concurrent: usize) -> Limit {
        let per_minute = per_minute.max(1) as f64;
        {
            let mut b = self.buckets.lock();
            let now = Instant::now();
            let bucket = b.entry(key.to_string()).or_insert(Bucket {
                tokens: per_minute,
                last: now,
            });
            let elapsed = now.duration_since(bucket.last).as_secs_f64();
            bucket.tokens = (bucket.tokens + elapsed * per_minute / 60.0).min(per_minute);
            bucket.last = now;
            if bucket.tokens < 1.0 {
                let wait = ((1.0 - bucket.tokens) * 60.0 / per_minute).ceil() as u64;
                return Limit::RateLimited {
                    retry_after_secs: wait.max(1),
                };
            }
            bucket.tokens -= 1.0;
        }
        let sem = {
            let mut c = self.concurrency.lock();
            let entry = c.entry(key.to_string()).or_insert_with(|| {
                (
                    max_concurrent,
                    Arc::new(Semaphore::new(max_concurrent.max(1))),
                )
            });
            if entry.0 != max_concurrent {
                *entry = (
                    max_concurrent,
                    Arc::new(Semaphore::new(max_concurrent.max(1))),
                );
            }
            entry.1.clone()
        };
        match sem.try_acquire_owned() {
            Ok(p) => Limit::Allowed(p),
            Err(_) => Limit::TooManyConcurrent,
        }
    }

    /// Simple keyed limiter for unauthenticated endpoints (registration, authorize).
    pub fn check_anonymous(&self, key: &str, per_minute: u32) -> bool {
        let per_minute = per_minute.max(1) as f64;
        let mut b = self.buckets.lock();
        let now = Instant::now();
        let bucket = b.entry(format!("anon:{key}")).or_insert(Bucket {
            tokens: per_minute,
            last: now,
        });
        let elapsed = now.duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * per_minute / 60.0).min(per_minute);
        bucket.last = now;
        if bucket.tokens < 1.0 {
            return false;
        }
        bucket.tokens -= 1.0;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits() {
        let r = RateLimiter::default();
        let mut permits = Vec::new();
        for _ in 0..3 {
            match r.check("a", 5, 3) {
                Limit::Allowed(p) => permits.push(p),
                _ => panic!(),
            }
        }
        assert!(matches!(r.check("a", 5, 3), Limit::TooManyConcurrent));
        permits.clear();
        assert!(matches!(r.check("a", 5, 3), Limit::Allowed(_)));
        assert!(matches!(r.check("a", 5, 3), Limit::RateLimited { .. }));
        assert!(matches!(r.check("b", 5, 3), Limit::Allowed(_)));
    }
}
