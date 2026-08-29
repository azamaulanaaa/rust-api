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

impl InitRequest {
    /// Validates the same constraints as the TS `Schema.filter`.
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
            let is_multiple_of_1kb = self.part_size.is_multiple_of(1024);
            let within_bounds = self.part_size <= 524288;
            if !is_multiple_of_1kb || !within_bounds {
                return Err(FsError::BadRequest(
                    "part_size must be a power-of-two multiple of 1 KB up to 512 KB (e.g., 131072, 262144, 524288)".into(),
                ));
            }
            let expected = self.file_size.div_ceil(self.part_size);
            if self.file_total_parts != expected {
                return Err(FsError::BadRequest(format!(
                    "Inconsistent math: file_total_parts must be exactly {expected} for a file of this size split by {} bytes",
                    self.part_size
                )));
            }
            let product = self.file_total_parts * self.part_size;
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
