//! A starter-kit REST API server providing pluggable modules for
//! OIDC authentication, JWT session validation, and Casbin-based
//! authorization, built on Actix Web.
//!
//! The crate is intentionally business-logic free: applications compose
//! [`http::ApiModule`] implementations onto an [`http::ApiService`]
//! to build their own API surface on top of the shared auth/policy plumbing.

// `unwrap_used`/`expect_used` are denied package-wide via [lints.clippy]
// in Cargo.toml, so the level is declared once and applies to every
// target. This attribute only opens the test escape hatch, which is why
// individual `#[cfg(test)]` modules do not need their own `#[allow]`.
//
// Public items must carry rustdoc comments; that lint is enforced the
// same way, via [lints.rust] in Cargo.toml.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

/// HTTP server scaffolding: modular service registry plus request
/// middleware (bearer-token extraction, JWKS-backed JWT validation).
pub mod http;

/// OpenID Connect client and login/callback routes implementing the
/// authorization-code flow with PKCE, CSRF state, and nonce validation.
pub mod oidc;

/// Casbin RBAC policy engine backed by prefix-scoped OxKV stores on S3,
/// with management routes for permission rules and group membership.
pub mod policy;

/// Object-store file storage via `object_store` (AmazonS3 for S3/MinIO/R2,
/// InMemory for tests) with multipart upload over REST.
pub mod fs;

/// OpenAPI specification composed from all `utoipa::path` modules.
pub mod docs;

/// Per-user filtered replicas on stable OxKvStore prefixes.
pub mod sync;

/// Shared change-feed vocabulary: [`FileRecord`](records::FileRecord),
/// [`WalOp`](records::WalOp), and the
/// [`ChangeSink`](records::ChangeSink) seam.
///
/// The pivot that lets `fs`/`policy` (which emit changes) and `sync`
/// (which consumes them) depend on this module instead of on each other.
/// Depends on nothing else in the crate.
pub mod records;

/// OxKV store factory (prefix-scoped inside configured S3 bucket) plus the
/// single-writer lease that guards a `[database].prefix` scope.
pub mod db;

/// Single-writer lease: makes a second process on the same
/// `[database].prefix` observable at startup instead of a silent
/// divergence.
pub mod lease;

/// Process-wide latch for a lost primary write session, covering the
/// uncooperative case the lease cannot see.
pub mod fencing;

/// Telemetry bootstrap: global [`tracing`] subscriber installation and
/// OpenTelemetry wiring.
pub mod telemetry;

#[cfg(test)]
mod tests {
    /// Every advisory this project suppresses is suppressed on purpose.
    ///
    /// The `[[advisories.ignore]]` entries in `deny.toml` are all cases
    /// where the fix is genuinely unreachable -- an upstream crate pins the
    /// dependency, or no patched version exists at all -- so the only honest
    /// move is to record the blocker and move on. That makes the list exactly
    /// the kind of thing that grows without anyone noticing: each addition
    /// turns the build green, and nothing records why the previous ones were
    /// acceptable.
    ///
    /// So the reason is required, and required to be substantial: a bare
    /// `reason = "known"` passes this crate's reviewer and nothing else. A
    /// `TODO` or a link with no explanation fails.
    ///
    /// Note what this does *not* do: it does not make the list exhaustive or
    /// correct. A suppression that is unjustified but well written still
    /// passes. It makes the additions legible, which is the part that
    /// mechanical checking can do.
    #[test]
    fn every_ignore_is_justified() {
        let deny = std::fs::read_to_string("deny.toml").expect("deny.toml is readable");

        /// Splits `deny.toml` into `(id, reason)` pairs.
        ///
        /// Minimal by design: it recognises `[[advisories.ignore]]` headers and
        /// the two keys, and handles TOML's `"""` multi-line form because a
        /// real rationale does not fit on one line. A full TOML parser would be
        /// a dependency for a test that only needs these three shapes.
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
                    // Opening line of a multi-line string; text after the
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

            // The reason has to say *why the fix is not taken*, or a reader
            // cannot tell "nobody has fixed it" from "we have not picked it up".
            // Those are very different: the second is a bug.
            let lower = reason.to_lowercase();
            let unavailability = [
                "fixed in",           // a fix exists; something upstream blocks it
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
