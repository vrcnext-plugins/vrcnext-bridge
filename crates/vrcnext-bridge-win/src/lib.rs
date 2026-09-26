//! Native confirmation on Windows: a `MessageBoxW` the page cannot click.
//!
//! This crate is empty on every other platform. It is separate from the sinks so that the
//! workspace-wide `forbid(unsafe_code)` holds everywhere but the one FFI call that a Win32
//! message box is.

#[cfg(windows)]
mod message_box;

#[cfg(windows)]
pub use message_box::MessageBoxApprover;
