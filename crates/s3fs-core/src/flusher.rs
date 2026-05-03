//! Concurrency control for the upload path.
//!
//! Today this is a thin wrapper around an `Arc<Semaphore>`: it bounds the
//! number of in-flight `UploadPart` and `UploadPartCopy` calls per `Fs`
//! instance, replacing the per-call `max_parallel_parts` knob with a
//! single shared cap. That alone fixes a real footgun — without it, many
//! concurrent `sync()` calls could each spin up `max_parallel_parts`
//! uploads in parallel and DOS the backend.
//!
//! The longer-term plan is for `Flusher` to own a long-running Tokio
//! worker that drains a queue of `FlushJob`s eagerly (so a part that
//! becomes fully dirty during sequential writes uploads in the
//! background, not at the next `sync` call). The current shape is
//! deliberately the smallest refactor that puts that design seam in
//! place without changing observable behavior.

use std::sync::Arc;

use tokio::sync::Semaphore;

use crate::config::Config;

/// Per-`Fs` concurrency limiter for backend uploads.
#[derive(Debug, Clone)]
pub struct Flusher {
    semaphore: Arc<Semaphore>,
}

impl Flusher {
    /// Build a flusher that allows at most `config.max_parallel_parts`
    /// concurrent backend upload operations.
    pub fn new(config: &Config) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(config.max_parallel_parts.max(1))),
        }
    }

    /// Acquire a permit for one upload operation. The returned guard
    /// releases the permit when dropped.
    pub async fn acquire(&self) -> tokio::sync::OwnedSemaphorePermit {
        self.semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore never closed")
    }

    /// Number of permits currently available (for tests/instrumentation).
    pub fn available_permits(&self) -> usize {
        self.semaphore.available_permits()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small_cfg(cap: usize) -> Config {
        Config::builder().max_parallel_parts(cap).build()
    }

    #[tokio::test]
    async fn acquire_bounds_concurrency() {
        let f = Flusher::new(&small_cfg(2));
        assert_eq!(f.available_permits(), 2);
        let _p1 = f.acquire().await;
        let _p2 = f.acquire().await;
        assert_eq!(f.available_permits(), 0);
    }

    #[tokio::test]
    async fn dropping_permit_releases() {
        let f = Flusher::new(&small_cfg(1));
        {
            let _p = f.acquire().await;
            assert_eq!(f.available_permits(), 0);
        }
        assert_eq!(f.available_permits(), 1);
    }

    #[tokio::test]
    async fn cap_is_at_least_one() {
        // Even if config says 0, we clamp to 1 so progress is possible.
        let f = Flusher::new(&small_cfg(0));
        assert_eq!(f.available_permits(), 1);
    }
}
