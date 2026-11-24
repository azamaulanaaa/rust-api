//! Client job status modules.
//!
//! The `poll` module holds the guaranteed fallback transport. The `sse`
//! module holds the stream transport. This module holds the wiring that both
//! transports use. Neither transport has an implementation yet.
pub mod poll;
pub mod sse;
