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
/// `base_delay * 2^attempt` before the next attempt. The factor stops at
/// `2^31`. The last error is returned when every attempt fails.
///
/// # Examples
///
/// ```
/// # use std::time::Duration;
/// # use rust_api::retry::retry_with_backoff;
/// # async fn example() -> Result<i32, &'static str> {
/// let value = retry_with_backoff(3, Duration::from_millis(10), || async {
///     Ok::<i32, &'static str>(42)
/// })
/// .await?;
/// assert_eq!(value, 42);
/// # Ok(0)
/// # }
/// ```
///
/// # Panics
///
/// Panics if `attempts` is zero.
pub async fn retry_with_backoff<F, Fut, T, E>(
    attempts: usize,
    base_delay: Duration,
    mut f: F,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    assert!(attempts > 0, "attempts must be positive: got {attempts}");
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
        None => unreachable!("assert!(attempts > 0) already checked this"),
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

        assert_eq!(result, Err("boom"));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    #[should_panic(expected = "attempts must be positive: got 0")]
    async fn zero_attempts_panics_at_the_entry_point() {
        let _ = retry_with_backoff(0, Duration::ZERO, || async { Ok::<_, ()>(()) }).await;
    }
}
