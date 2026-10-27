//! A REST API server starter kit. It provides plug-in modules for OIDC
//! authentication, JWT session validation, and Casbin-based authorization.
//! The modules run on Actix Web.
//!
//! This crate has no business logic. An application composes
//! [`http::ApiModule`] implementations onto an [`http::ApiService`] to build
//! its own API surface on the shared auth and policy plumbing.

// Cargo.toml denies `unwrap_used` and `expect_used` for the whole package
// through [lints.clippy], so the level is set once and covers every target.
// This attribute only opens the test escape hatch. Each `#[cfg(test)]` module
// therefore needs no `#[allow]` of its own.
//
// Every public item needs a rustdoc comment. Cargo.toml enforces this rule
// in the same way, through [lints.rust].
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

/// HTTP server scaffolding. It has a service registry for modules and
/// request middleware. The middleware extracts the bearer token and
/// validates the JWT with JWKS.
pub mod http;

/// Audit logging for mutations. See [`audit::AuditEvent`] and
/// [`audit::AuditSink`].
pub mod audit;

/// OpenID Connect client and login/callback routes implementing the
/// authorization-code flow with PKCE, CSRF state, and nonce validation.
pub mod oidc;

/// Casbin RBAC policy engine. It uses OxKV stores on S3, with one prefix
/// scope per store. It also has management routes for permission rules and
/// group membership.
pub mod policy;

/// Object-store file storage via `object_store` (AmazonS3 for S3/MinIO/R2,
/// InMemory for tests) with multipart upload over REST.
pub mod fs;

/// Reactive scaffolding: a business-logic-free extension point for
/// applications to attach `oxkv` hooks and run background systems.
pub mod reactive;

#[cfg(test)]
mod test_support;

/// OpenAPI specification composed from all `utoipa::path` modules.
pub mod docs;

/// Per-user filtered replicas on stable OxKvStore prefixes.
pub mod sync;

/// Shared change feed vocabulary: [`FileRecord`](records::FileRecord),
/// [`WalOp`](records::WalOp), and the [`ChangeSink`](records::ChangeSink)
/// seam.
///
/// This module is the pivot between the two sides of the feed. `fs` and
/// `policy` emit changes. `sync` consumes them. Both sides depend on this
/// module, not on each other. This module depends on nothing else in the
/// crate.
pub mod records;

/// OxKV store factory. The factory is prefix-scoped inside the configured
/// S3 bucket. It also creates the single-writer lease that guards a
/// `[database].prefix` scope.
pub mod db;

/// Single-writer lease. It makes a second process on the same
/// `[database].prefix` visible at startup. It also prevents a silent
/// divergence.
pub mod lease;

/// Process-wide latch for a lost primary write session. It covers the
/// uncooperative case that the lease cannot see.
pub mod fencing;

/// Cost controls. This module has a request rate bucket and a concurrency
/// gate. They protect the endpoints whose work a single request does not
/// bound.
pub mod limits;

/// Retry helper with exponential backoff for transient failures.
pub mod retry;

/// Telemetry bootstrap: global [`tracing`] subscriber installation and
/// OpenTelemetry wiring.
pub mod telemetry;

/// Cancellation token for background tasks.
///
/// A task polls [`CancelToken::is_cancelled`] and stops when it returns
/// `true`. The token is cheap to clone, so one token can be handed to many
/// tasks.
pub trait CancelToken: Clone + Send + Sync + 'static {
    /// Returns `true` after cancellation has been requested.
    fn is_cancelled(&self) -> bool;
}

impl CancelToken for std::sync::Arc<std::sync::atomic::AtomicBool> {
    fn is_cancelled(&self) -> bool {
        self.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl CancelToken for tokio::sync::watch::Receiver<bool> {
    fn is_cancelled(&self) -> bool {
        *self.borrow()
    }
}

impl CancelToken for tokio_util::sync::CancellationToken {
    fn is_cancelled(&self) -> bool {
        tokio_util::sync::CancellationToken::is_cancelled(self)
    }
}

#[cfg(test)]
mod tests {
    /// Every advisory this project suppresses has a reason on purpose.
    ///
    /// The `[[advisories.ignore]]` entries in `deny.toml` are all cases
    /// where the fix is unreachable. An upstream crate may pin the
    /// dependency. No patched version may exist at all. In each case the
    /// only correct action is to record the blocker and continue.
    ///
    /// Such a list grows without anyone noticing. Each new entry turns the
    /// build green. Nothing records why the earlier entries were acceptable.
    ///
    /// So the test requires a reason. The test also requires the reason to
    /// be substantial. A bare `reason = "known"` passes this crate's
    /// reviewer and nothing else. A `TODO` or a link with no explanation
    /// fails.
    ///
    /// This test does not make the list complete. This test does not make
    /// the list correct. An unjustified suppression still passes when its
    /// prose is good. The test only makes the additions legible.
    #[test]
    fn every_ignore_is_justified() {
        let deny = std::fs::read_to_string("deny.toml").expect("deny.toml is readable");

        /// Splits `deny.toml` into `(id, reason)` pairs.
        ///
        /// This function is small by design. It recognises the
        /// `[[advisories.ignore]]` header and the two keys. It also handles
        /// the TOML `"""` multi-line form, because a real rationale does not
        /// fit on one line. A full TOML parser would add a dependency to a
        /// test that needs only these three shapes.
        fn parse(text: &str) -> Vec<(String, String)> {
            let mut entries: Vec<(String, String)> = Vec::new();
            let mut id: Option<String> = None;
            let mut reason: Option<String> = None;
            let mut in_block = false;

            let flush = |id: &mut Option<String>, reason: &mut Option<String>, out: &mut Vec<_>| {
                if let (Some(i), Some(r)) = (id.take(), reason.take()) {
                    out.push((i, r));
                }
            };

            for raw in text.lines() {
                let line = raw.trim();

                if in_block {
                    if line == "\"\"\"" {
                        in_block = false;
                    } else {
                        reason.get_or_insert_with(String::new).push(' ');
                        reason
                            .as_mut()
                            .expect("just inserted")
                            .push_str(&line.replace('\\', " "));
                    }
                    continue;
                }

                if line == "[[advisories.ignore]]" {
                    flush(&mut id, &mut reason, &mut entries);
                    continue;
                }
                if let Some(v) = line.strip_prefix("id = ") {
                    id = Some(v.trim().trim_matches('"').to_string());
                } else if let Some(v) = line.strip_prefix("reason = \"\"\"") {
                    // Opening line of a multi-line string. Text after the
                    // opening quotes counts.
                    let head = v.trim_end_matches('"').trim();
                    reason = Some(if head.is_empty() {
                        String::new()
                    } else {
                        format!("{head} ")
                    });
                    in_block = true;
                } else if let Some(v) = line.strip_prefix("reason = ") {
                    reason = Some(v.trim().trim_matches('"').to_string());
                }
            }
            flush(&mut id, &mut reason, &mut entries);
            entries
        }

        let entries = parse(&deny);
        assert!(
            !entries.is_empty(),
            "no [[advisories.ignore]] entries found; the parser is broken, not the config"
        );

        for (id, reason) in &entries {
            assert!(
                id.starts_with("RUSTSEC-") || id.starts_with("CVE-"),
                "advisory id looks wrong: {id:?}"
            );

            // A link is not a justification. Measure the prose with URLs
            // removed, so "see <link>" cannot satisfy the length check.
            let prose = strip_urls(reason);
            assert!(
                prose.split_whitespace().count() >= 20,
                "{id} is suppressed with {} words of prose. Say which crate, why the \
                 fix is unreachable, and what limits the exposure.",
                prose.split_whitespace().count()
            );
            assert!(
                !prose.contains("TODO") && !prose.contains("FIXME"),
                "{id} is suppressed with a TODO in its reason"
            );

            // The reason must say *why the fix is not taken*. Otherwise a
            // reader cannot tell "nobody has fixed it" from "we have not
            // started". Those cases are very different. The second one is a
            // bug.
            let lower = reason.to_lowercase();
            let unavailability = [
                "fixed in",           // a fix exists and something upstream blocks it
                "no patched version", // no fix exists at all
                "unmaintained",       // not a vulnerability, no fix coming
                "latest release",     // upstream has nothing newer
            ];
            assert!(
                unavailability.iter().any(|u| lower.contains(u)),
                "{id} does not say why the fix is unavailable (expected one of \
                 {unavailability:?})"
            );
        }
    }

    /// Removes `http(s)://...` runs so word counts measure prose.
    fn strip_urls(text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        while let Some(at) = rest.find("http") {
            out.push_str(&rest[..at]);
            let tail = &rest[at..];
            match tail.find(|c: char| c.is_whitespace()) {
                Some(end) => {
                    rest = &tail[end..];
                }
                None => {
                    rest = "";
                    break;
                }
            }
        }
        out.push_str(rest);
        out
    }
}
