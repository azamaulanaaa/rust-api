//! Retry helper with exponential backoff for transient failures.
//!
//! The helper is generic over the operation and its error type. It is meant
//! for calls to an object store or another remote service where a transient
//! failure is expected to succeed on a later attempt.

use std::future::Future;
use std::time::Duration;

/// Calls `f` up to `attempts` times, sleeping with exponential backoff
/// between attempts.
///
/// The first attempt runs immediately. A failed attempt waits
/// `base_delay * 2^attempt` before the next attempt. The last error is
/// returned when every attempt fails. `attempts == 0` is not supported.
pub async fn retry_with_backoff<F, Fut, T, E>(
    attempts: usize,
    base_delay: Duration,
    mut f: F,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    let mut last_error: Option<E> = None;

    for attempt in 0..attempts {
        match f().await {
            Ok(value) => return Ok(value),
            Err(error) => {
                last_error = Some(error);
                if attempt + 1 < attempts {
                    let factor = 1u32 << attempt.min(31);
                    tokio::time::sleep(base_delay.saturating_mul(factor)).await;
                }
            }
        }
    }

    match last_error {
        Some(error) => Err(error),
        None => panic!("retry_with_backoff requires at least one attempt"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[tokio::test]
    async fn retries_until_success() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_closure = calls.clone();

        let result = retry_with_backoff(3, Duration::from_millis(1), move || {
            let calls = calls_for_closure.clone();
            async move {
                let n = calls.fetch_add(1, Ordering::SeqCst);
                if n < 2 { Err("transient") } else { Ok(42) }
            }
        })
        .await;

        assert_eq!(result, Ok(42));
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn returns_last_error_after_all_attempts() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_closure = calls.clone();

        let result: Result<i32, &'static str> =
            retry_with_backoff(2, Duration::from_millis(1), move || {
                let calls = calls_for_closure.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Err("boom")
                }
            })
            .await;

        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}
