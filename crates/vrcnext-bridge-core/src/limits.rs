//! Every hard bound in one place.
//!
//! These are a security control, not ergonomics. The daemon listens on loopback, which means any
//! local process — and, absent the CORS guard, any web page open in any browser — can reach it.
//! Unbounded strings would let a caller push megabytes into a VR overlay's text renderer, and
//! unbounded floats would let it pin a notification on screen forever.

/// Longest accepted request body, in bytes. Generous enough for a base64 icon, small enough that
/// a flood of concurrent requests cannot exhaust memory.
pub const MAX_BODY_BYTES: usize = 192 * 1024;

/// Longest notification title, in Unicode scalar values (not bytes).
pub const MAX_TITLE_CHARS: usize = 200;

/// Longest notification body, in Unicode scalar values.
pub const MAX_CONTENT_CHARS: usize = 2_000;

/// Longest `source_app` / application-name string.
pub const MAX_SOURCE_APP_CHARS: usize = 64;

/// Longest `icon` value. Covers both a short theme icon name and an inline base64 payload.
pub const MAX_ICON_CHARS: usize = 128 * 1024;

/// Longest `audio_path` value.
pub const MAX_AUDIO_PATH_CHARS: usize = 512;

/// Most sinks one request may name.
pub const MAX_REQUESTED_SINKS: usize = 8;

/// Longest sink name accepted from a request, so an unknown-sink error cannot echo a huge string.
pub const MAX_SINK_NAME_CHARS: usize = 32;

/// Inclusive range for `timeout_secs`. Zero means "sink default"; the ceiling stops a caller
/// parking a notification in the user's view indefinitely.
pub const TIMEOUT_SECS: (f32, f32) = (0.0, 60.0);

/// Inclusive range for `volume`.
pub const VOLUME: (f32, f32) = (0.0, 1.0);

/// Inclusive range for `opacity`.
pub const OPACITY: (f32, f32) = (0.0, 1.0);

/// Inclusive range for `height`, in the overlay's own units.
pub const HEIGHT: (f32, f32) = (16.0, 1_024.0);
