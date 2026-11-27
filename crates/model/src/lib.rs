//! The shared wire contract for the rust-api server and the WASM client.
//!
//! The crate holds data types only. It has no I/O and no behavior.
//! [`domain`] holds the values that the server and the client share.
//! [`wire`] holds the request and response types.
//!
//! The default build needs `serde` only. The optional `openapi` feature
//! adds `utoipa` for the server. A client build must leave the feature off.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod domain;
pub mod wire;

pub use domain::{CommandKind, CommandKindError, JobState};
pub use wire::{
    CommandEnvelope, CommitReceipt, JobStatusView, ReplicaManifest, ReplicaObject, SyncCursor,
};
