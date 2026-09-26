//! Plugin management for `vrcnext-bridge`: install, validate, compile, and keep the page's state.
//!
//! This is the crate that touches the filesystem and the network on the page's behalf. It is
//! split by the invariant each module protects:
//!
//! | Module | Protects |
//! | :--- | :--- |
//! | [`state`] | the page's data survives, atomically, within fixed bounds |
//!
//! Everything a caller can name — a namespace, a key, a plugin id, a URL — is validated in the
//! module that owns it before it is used, and never joined into a path or a command line.

pub mod fsutil;
pub mod state;

pub use state::{StateService, StateStore};
