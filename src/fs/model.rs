//! Request/response DTOs and validation mirroring `MetadataUploadSchema.filter`.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Mirrors `MetadataUploadSchema` from `src/worker/fs/index.ts`.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct InitRequest {
    /// Total file size in bytes.
    pub file_size: u64,
    /// Chunk size in bytes.
    pub part_size: u64,
    /// Total number of parts.
    pub file_total_parts: u64,
}

/// Maximum parts in one multipart upload.
///
/// S3's own per-upload limit. Enforcing it at init matters three times
/// over: it turns what would otherwise be an S3 rejection at
/// `complete_upload` -- *after* the client has uploaded every part -- into
/// a 400 on the first call; and it bounds the per-session `etags` and
/// `checksums` vectors the engine allocates from this count, which is what
/// keeps a 70-byte request body from becoming a multi-terabyte allocation.
pub const MAX_MULTIPART_PARTS: u64 = 10_000;

impl InitRequest {
    /// Validates the same constraints as the TS `Schema.filter`, plus
    /// [`MAX_MULTIPART_PARTS`].
    pub fn validate(&self) -> Result<(), crate::fs::error::FsError> {
        use crate::fs::error::FsError;
        if self.file_size == 0 {
            return Err(FsError::BadRequest("file_size cannot be empty".into()));
        }
        if self.part_size == 0 {
            return Err(FsError::BadRequest("part_size cannot be zero".into()));
        }
        if self.file_total_parts == 0 {
            return Err(FsError::BadRequest("total_parts cannot be zero".into()));
        }

        if self.file_total_parts == 1 {
            if self.part_size != self.file_size {
                return Err(FsError::BadRequest(format!(
                    "For a single-part upload, part_size ({}) must be equal to the file_size ({})",
                    self.part_size, self.file_size
                )));
            }
            if self.file_size > 10 * 1024 * 1024 {
                return Err(FsError::BadRequest(
                    "For a single-part upload, cannot be bigger than 10 MB".into(),
                ));
            }
        } else {
            // Before the arithmetic checks, because a count this large is
            // the interesting error: `expected` would otherwise report
            // something like "must be exactly 18014398509481983 parts".
            if self.file_total_parts > MAX_MULTIPART_PARTS {
                return Err(FsError::BadRequest(format!(
                    "file_total_parts must be at most {MAX_MULTIPART_PARTS} (S3's per-upload part \
                     limit); got {}. Raise part_size (max 512 KB) to split a larger file.",
                    self.file_total_parts
                )));
            }
            let is_multiple_of_1kb = self.part_size.is_multiple_of(1024);
            let within_bounds = self.part_size <= 524288;
            if !is_multiple_of_1kb || !within_bounds {
                return Err(FsError::BadRequest(
                    "part_size must be a multiple of 1 KB up to 512 KB (e.g., 131072, 262144, 524288)".into(),
                ));
            }
            let expected = self.file_size.div_ceil(self.part_size);
            if self.file_total_parts != expected {
                return Err(FsError::BadRequest(format!(
                    "Inconsistent math: file_total_parts must be exactly {expected} for a file of this size split by {} bytes",
                    self.part_size
                )));
            }
            // `checked_mul` is a backstop, not the primary guard: the
            // `MAX_MULTIPART_PARTS` cap above already makes the product
            // unreachable-overflow (10,000 x 512 KB is ~5 GB). It stays
            // because the cost of being wrong here is a debug panic or a
            // silent release wrap, and the cost of the guard is one line.
            // `init_request_caps_parts_before_arithmetic` pins that the cap
            // is what actually rejects these inputs now.
            let product = self
                .file_total_parts
                .checked_mul(self.part_size)
                .ok_or_else(|| {
                    FsError::BadRequest("file_total_parts * part_size overflows u64".into())
                })?;
            if product != self.file_size {
                return Err(FsError::BadRequest(format!(
                    "Inconsistent math: file_total_parts ({}) * part_size ({}) must equal file_size ({})",
                    self.file_total_parts, self.part_size, self.file_size
                )));
            }
        }
        Ok(())
    }
}

/// Mirrors `FileMetadataSchema`.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct CompleteRequest {
    /// Human filename.
    pub name: String,
    /// MIME type.
    pub mimetype: String,
}

impl CompleteRequest {
    /// Validates `name` and `mimetype` are non-empty.
    pub fn validate(&self) -> Result<(), crate::fs::error::FsError> {
        use crate::fs::error::FsError;
        if self.name.trim().is_empty() {
            return Err(FsError::BadRequest("name cannot be empty".into()));
        }
        if self.mimetype.trim().is_empty() {
            return Err(FsError::BadRequest("mimetype cannot be empty".into()));
        }
        Ok(())
    }
}

/// Public file metadata (no S3 internals).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct FileMetadata {
    /// File identifier (uuidv7).
    pub id: String,
    /// Original filename.
    pub name: String,
    /// MIME type.
    pub mimetype: String,
    /// Size in bytes.
    pub size: u64,
}

/// Response for `POST /fs/uploads` (init).
#[derive(Debug, Serialize, ToSchema)]
pub struct InitResponse {
    /// Generated file identifier.
    pub file_id: String,
}

/// Progress response for client-driven polling: `GET /fs/uploads/{id}`.
#[derive(Debug, Serialize, ToSchema)]
pub struct ProgressResponse {
    /// File identifier.
    pub file_id: String,
    /// Total file size.
    pub file_size: u64,
    /// Part size.
    pub part_size: u64,
    /// Total parts declared at init.
    pub total_parts: u64,
    /// Indices of uploaded parts.
    pub uploaded_parts: Vec<u64>,
    /// Percentage completed (0-100).
    pub percent: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_bad(req: InitRequest, contains: &str) {
        let err = req.validate().unwrap_err().to_string();
        assert!(
            err.contains(contains),
            "expected '{contains}' in '{err}' for {req:?}"
        );
    }

    #[test]
    fn init_request_rejects_zero_fields() {
        assert_bad(
            InitRequest {
                file_size: 0,
                part_size: 1024,
                file_total_parts: 1,
            },
            "file_size",
        );
        assert_bad(
            InitRequest {
                file_size: 1024,
                part_size: 0,
                file_total_parts: 1,
            },
            "part_size",
        );
        assert_bad(
            InitRequest {
                file_size: 1024,
                part_size: 1024,
                file_total_parts: 0,
            },
            "total_parts",
        );
    }

    #[test]
    fn init_request_single_part_copy_paste_guards() {
        // Copy-paste risk: single-part branch must check part_size == file_size
        // and 10 MB cap — swapping into multi-part logic would silently pass.
        assert_bad(
            InitRequest {
                file_size: 1024,
                part_size: 512,
                file_total_parts: 1,
            },
            "must be equal",
        );
        assert_bad(
            InitRequest {
                file_size: 11 * 1024 * 1024,
                part_size: 11 * 1024 * 1024,
                file_total_parts: 1,
            },
            "10 MB",
        );
        // Valid single-part (boundary 10 MB)
        InitRequest {
            file_size: 10 * 1024 * 1024,
            part_size: 10 * 1024 * 1024,
            file_total_parts: 1,
        }
        .validate()
        .unwrap();
    }

    #[test]
    fn init_request_multi_part_copy_paste_guards() {
        // part_size must be 1KB multiple and <=512KB — easy to copy wrong bound.
        assert_bad(
            InitRequest {
                file_size: 2048,
                part_size: 1500,
                file_total_parts: 2,
            },
            "part_size",
        );
        assert_bad(
            InitRequest {
                file_size: 1024 * 1024,
                part_size: 600 * 1024,
                file_total_parts: 2,
            },
            "part_size",
        );
        // file_total_parts must equal ceil(file_size/part_size)
        assert_bad(
            InitRequest {
                file_size: 1024 * 1024,
                part_size: 262144,
                file_total_parts: 5,
            },
            "must be exactly",
        );
        // product must equal file_size (exact division required)
        assert_bad(
            InitRequest {
                file_size: 300 * 1024,
                part_size: 131072,
                file_total_parts: 3,
            },
            "must equal",
        );
        // Valid multi-part: 1 MB split by 256KB = 4 parts
        InitRequest {
            file_size: 1024 * 1024,
            part_size: 262144,
            file_total_parts: 4,
        }
        .validate()
        .unwrap();
    }

    /// `part_size` is constrained to a 1 KB multiple, not a power of two:
    /// the error message used to promise "power-of-two" while the check
    /// accepted any multiple. Pins the behavior the message now describes.
    #[test]
    fn init_request_multi_part_allows_any_1kb_multiple() {
        // 3 KiB is not a power of two but is a valid part size.
        InitRequest {
            file_size: 6144,
            part_size: 3072,
            file_total_parts: 2,
        }
        .validate()
        .unwrap();
        assert_bad(
            InitRequest {
                file_size: 6144,
                part_size: 3073,
                file_total_parts: 2,
            },
            "part_size",
        );
    }

    /// The part count used to be unbounded, and these two inputs are the
    /// ones that broke it. Both are arithmetically self-consistent
    /// (`file_total_parts == ceil(file_size / part_size)` and the product
    /// equals `file_size`), so they sailed through every check and reached
    /// `vec![None; n]` in the engine:
    ///
    /// - 2^54 parts: a 383 TiB allocation, which **aborts** the process.
    /// - 2^54 parts with an overflowing product: a debug panic / release
    ///   wrap.
    ///
    /// The `MAX_MULTIPART_PARTS` cap now rejects both, and it is checked
    /// before the arithmetic so the error names the real problem.
    #[test]
    fn init_request_caps_parts_before_arithmetic() {
        // The exact body from the abort: passes every arithmetic check.
        assert_bad(
            InitRequest {
                file_size: u64::MAX - 1023,
                part_size: 1024,
                // = ceil((2^64 - 1024) / 1024) = 2^54 - 1
                file_total_parts: (1u64 << 54) - 1,
            },
            "at most 10000",
        );
        // The one that used to overflow the product, also capped now.
        assert_bad(
            InitRequest {
                file_size: u64::MAX - 511,
                part_size: 1024,
                file_total_parts: 1u64 << 54,
            },
            "at most 10000",
        );
        // One over the limit, with math that also checks out.
        assert_bad(
            InitRequest {
                file_size: (MAX_MULTIPART_PARTS + 1) * 1024,
                part_size: 1024,
                file_total_parts: MAX_MULTIPART_PARTS + 1,
            },
            "at most 10000",
        );
        // The message has to tell the client what to do about it.
        let err = InitRequest {
            file_size: (MAX_MULTIPART_PARTS + 1) * 1024,
            part_size: 1024,
            file_total_parts: MAX_MULTIPART_PARTS + 1,
        }
        .validate()
        .unwrap_err()
        .to_string();
        assert!(err.contains("part_size"), "unhelpful message: {err}");
    }

    /// The cap is inclusive: exactly 10,000 parts is a legal upload.
    #[test]
    fn init_request_accepts_exactly_the_part_limit() {
        InitRequest {
            file_size: MAX_MULTIPART_PARTS * 1024,
            part_size: 1024,
            file_total_parts: MAX_MULTIPART_PARTS,
        }
        .validate()
        .expect("10,000 parts is S3's limit, not over it");
    }

    #[test]
    fn complete_request_rejects_empty_fields() {
        assert!(
            CompleteRequest {
                name: "   ".into(),
                mimetype: "text/plain".into()
            }
            .validate()
            .is_err()
        );
        assert!(
            CompleteRequest {
                name: "file.bin".into(),
                mimetype: "  ".into()
            }
            .validate()
            .is_err()
        );
        CompleteRequest {
            name: "file.bin".into(),
            mimetype: "application/octet-stream".into(),
        }
        .validate()
        .unwrap();
    }
}
