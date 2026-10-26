//! Request and response types for the FS module.
/// Their validation mirrors `MetadataUploadSchema.filter`.
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::http::validation::{Validate, ValidationError};

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

/// The maximum number of parts in one multipart upload.
///
/// This value is the S3 limit for one upload.
/// The engine enforces the limit when a client starts an upload.
/// The engine then rejects a larger count with a 400 on the first call.
/// Without the check, S3 would reject the upload at `complete_upload`,
/// after the client sent every part.
/// The check also bounds the per-session `etags` and `checksums` vectors.
/// Without the check, a 70-byte request body could ask for a
/// multi-terabyte allocation.
pub const MAX_MULTIPART_PARTS: u64 = 10_000;

impl InitRequest {
    /// Validates the same constraints as the TS `Schema.filter`, and also
    /// applies [`MAX_MULTIPART_PARTS`].
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
            // The engine runs this check before the arithmetic checks.
            // A count this large is the error that matters here.
            // Without this check, `expected` reports a message such as
            // "must be exactly 18014398509481983 parts".
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
            // `checked_mul` is a second guard, and not the main one.
            // The `MAX_MULTIPART_PARTS` cap above already prevents an
            // overflow of this product. 10,000 parts of 512 KB are about
            // 5 GB.
            // The code keeps `checked_mul` because a wrong result here is
            // a debug panic or a silent wrap in release mode. The guard
            // costs one line.
            // The test `init_request_caps_parts_before_arithmetic` proves
            // that the cap rejects these inputs now.
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

impl Validate for InitRequest {
    fn validate(&self) -> Result<(), ValidationError> {
        InitRequest::validate(self).map_err(|err| ValidationError::from(err.to_string()))
    }
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

impl Validate for CompleteRequest {
    fn validate(&self) -> Result<(), ValidationError> {
        CompleteRequest::validate(self).map_err(|err| ValidationError::from(err.to_string()))
    }
}

/// Public file metadata. It does not contain S3 internals.
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

/// The response for `POST /fs/uploads`. The call starts an upload.
#[derive(Debug, Serialize, ToSchema)]
pub struct InitResponse {
    /// Generated file identifier.
    pub file_id: String,
}

/// The progress response for a client poll. The client sends
/// `GET /fs/uploads/{id}`.
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
    fn init_request_single_part_checks_size_and_cap() {
        // A copy-paste error is the risk in this test.
        // The single-part branch must check that part_size == file_size.
        // The branch must also apply the 10 MB cap.
        // Without these checks, the multi-part logic accepts the input.
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
        // Valid single-part upload at the 10 MB boundary.
        InitRequest {
            file_size: 10 * 1024 * 1024,
            part_size: 10 * 1024 * 1024,
            file_total_parts: 1,
        }
        .validate()
        .unwrap();
    }

    #[test]
    fn init_request_multi_part_checks_size_and_count() {
        // The engine requires part_size to be a multiple of 1 KB and at
        // most 512 KB. A wrong bound is easy to copy into this test.
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
        // The product must equal file_size. The division must be exact.
        assert_bad(
            InitRequest {
                file_size: 300 * 1024,
                part_size: 131072,
                file_total_parts: 3,
            },
            "must equal",
        );
        // Valid multi-part upload. A 1 MB file with 256 KB parts has 4 parts.
        InitRequest {
            file_size: 1024 * 1024,
            part_size: 262144,
            file_total_parts: 4,
        }
        .validate()
        .unwrap();
    }

    /// `part_size` must be a multiple of 1 KB.
    /// It does not have to be a power of two.
    /// The error message used to promise "power-of-two", but the check
    /// accepted any multiple.
    /// This test pins the behaviour that the message now describes.
    #[test]
    fn init_request_multi_part_allows_any_1kb_multiple() {
        // 3 KiB is not a power of two, and it is a valid part size.
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

    /// The part count used to have no limit. These two inputs broke that.
    /// Both inputs are correct in arithmetic (`file_total_parts == ceil(file_size / part_size)` and the product equals `file_size`).
    /// Both inputs passed every check and reached `vec![None; n]` in the engine:
    ///
    /// - 2^54 parts: a 383 TiB allocation, which **aborts** the process.
    /// - 2^54 parts with an overflowing product: a debug panic or a silent
    ///   wrap in release mode.
    ///
    /// The `MAX_MULTIPART_PARTS` cap now rejects both inputs.
    /// The engine checks the cap before the arithmetic, so the error
    /// message names the real problem.
    #[test]
    fn init_request_caps_parts_before_arithmetic() {
        // This is the exact body from the abort. It passes every arithmetic check.
        assert_bad(
            InitRequest {
                file_size: u64::MAX - 1023,
                part_size: 1024,
                // = ceil((2^64 - 1024) / 1024) = 2^54 - 1
                file_total_parts: (1u64 << 54) - 1,
            },
            "at most 10000",
        );
        // This input used to overflow the product. The cap rejects it too.
        assert_bad(
            InitRequest {
                file_size: u64::MAX - 511,
                part_size: 1024,
                file_total_parts: 1u64 << 54,
            },
            "at most 10000",
        );
        // One part over the limit. The arithmetic also passes.
        assert_bad(
            InitRequest {
                file_size: (MAX_MULTIPART_PARTS + 1) * 1024,
                part_size: 1024,
                file_total_parts: MAX_MULTIPART_PARTS + 1,
            },
            "at most 10000",
        );
        // The message must tell the client what to do.
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

    /// The cap includes its limit. An upload of exactly 10,000 parts is
    /// valid.
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
