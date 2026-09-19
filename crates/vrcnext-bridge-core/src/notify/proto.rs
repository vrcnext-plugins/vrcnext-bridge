//! The `notify` service's wire types.
//!
//! Three layers, and the distinction between them is load-bearing:
//!
//! - [`NotifyRequest`] — whatever the caller sent. Untrusted.
//! - [`NotifyOverride`] — a per-target patch over that request, so one call can present itself
//!   differently in VR than on the desktop.
//! - [`Notification`] — the result of validating a request (or a request + patch). Every string is
//!   within bounds and free of stray control characters; every float is finite and in range.
//!
//! A `Notification` can only be produced by validation, so a sink author never has to re-check
//! anything. If they hold one, it is already safe to hand to a system service.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::limits;

/// How urgently the notification should be presented.
///
/// Maps onto the freedesktop urgency hint and onto XSOverlay-style `messageType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Urgency {
    /// Informational; may be presented quietly.
    Low,
    /// The default.
    #[default]
    Normal,
    /// Should interrupt.
    Critical,
}

/// An inbound `notify/send` request.
///
/// `deny_unknown_fields` is deliberate: a typo'd field is a bug in the calling plugin, and
/// silently ignoring it would present a notification that is subtly not what the author wrote.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NotifyRequest {
    /// Targets to deliver to, by sink name. `None` means every configured sink.
    ///
    /// This is how a plugin says "VR only": `"sinks": ["wayvr"]`.
    pub sinks: Option<Vec<String>>,

    /// Per-sink patches over the fields below, keyed by sink name.
    ///
    /// A sink named here that is not being delivered to is ignored rather than rejected, so a
    /// plugin can carry presentation for a target the user has not enabled without special-casing.
    pub overrides: Option<BTreeMap<String, NotifyOverride>>,

    /// Notification title. The only required field.
    pub title: String,
    /// Body text.
    #[serde(default)]
    pub content: String,
    /// Display duration in seconds. `0.0` or absent means the sink's own default.
    pub timeout_secs: Option<f32>,
    /// A freedesktop icon name, or base64 image data when `use_base64_icon` is set.
    pub icon: Option<String>,
    /// Whether `icon` carries base64 image data rather than a name.
    pub use_base64_icon: Option<bool>,
    /// Application name to attribute the notification to.
    pub source_app: Option<String>,
    /// Whether the receiver should play its notification sound.
    pub sound: Option<bool>,
    /// Sound volume, 0.0–1.0.
    pub volume: Option<f32>,
    /// Path to a sound file to play instead of the receiver's default.
    pub audio_path: Option<String>,
    /// Requested panel height, in the receiver's units.
    pub height: Option<f32>,
    /// Requested panel opacity, 0.0–1.0.
    pub opacity: Option<f32>,
    /// Urgency hint.
    pub urgency: Option<Urgency>,
    /// Ask an overlay to show this even while its dashboard is open.
    pub always_show: Option<bool>,
}

/// A patch applied over a [`NotifyRequest`] for one specific sink.
///
/// Every field mirrors [`NotifyRequest`] and every field is optional; `Some` replaces, `None`
/// inherits. The fields are spelled out rather than shared via `#[serde(flatten)]` because
/// flattening is incompatible with `deny_unknown_fields`, and catching a plugin author's typo is
/// worth more than saving a dozen lines here.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NotifyOverride {
    /// Replacement title.
    pub title: Option<String>,
    /// Replacement body text.
    pub content: Option<String>,
    /// Replacement display duration.
    pub timeout_secs: Option<f32>,
    /// Replacement icon.
    pub icon: Option<String>,
    /// Replacement base64-icon flag.
    pub use_base64_icon: Option<bool>,
    /// Replacement application name.
    pub source_app: Option<String>,
    /// Replacement sound flag.
    pub sound: Option<bool>,
    /// Replacement volume.
    pub volume: Option<f32>,
    /// Replacement sound file path.
    pub audio_path: Option<String>,
    /// Replacement panel height.
    pub height: Option<f32>,
    /// Replacement panel opacity.
    pub opacity: Option<f32>,
    /// Replacement urgency.
    pub urgency: Option<Urgency>,
    /// Replacement always-show flag.
    pub always_show: Option<bool>,
}

/// A validated notification. Construct only via [`NotifyRequest::validate`].
#[derive(Debug, Clone, PartialEq, Serialize)]
#[non_exhaustive]
pub struct Notification {
    /// Validated title.
    pub title: String,
    /// Validated body.
    pub content: String,
    /// Display duration, or `None` for the sink default.
    pub timeout_secs: Option<f32>,
    /// Validated icon name or base64 payload.
    pub icon: Option<String>,
    /// Whether `icon` is base64 image data.
    pub use_base64_icon: bool,
    /// Validated application name.
    pub source_app: String,
    /// Whether to play a sound.
    pub sound: bool,
    /// Sound volume, 0.0–1.0.
    pub volume: f32,
    /// Validated sound file path.
    pub audio_path: Option<String>,
    /// Panel height, or `None` for the sink default.
    pub height: Option<f32>,
    /// Panel opacity, 0.0–1.0.
    pub opacity: f32,
    /// Urgency hint.
    pub urgency: Urgency,
    /// Whether to show over an overlay dashboard.
    pub always_show: bool,
}

/// Why a request was refused.
///
/// Messages name the field and the bound but never echo the offending value: this text goes back
/// over HTTP, and reflecting caller-supplied bytes into a response is how a validation error turns
/// into an injection primitive.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum ValidationError {
    /// A required string was empty after trimming.
    #[error("`{field}` must not be empty")]
    Empty {
        /// Field name.
        field: &'static str,
    },
    /// A string exceeded its character bound.
    #[error("`{field}` exceeds the {max} character limit")]
    TooLong {
        /// Field name.
        field: &'static str,
        /// The bound that was exceeded.
        max: usize,
    },
    /// A string contained a control character not allowed in that field.
    #[error("`{field}` contains a disallowed control character")]
    ControlCharacter {
        /// Field name.
        field: &'static str,
    },
    /// A float was NaN or infinite.
    #[error("`{field}` must be a finite number")]
    NotFinite {
        /// Field name.
        field: &'static str,
    },
    /// A float was outside its permitted range.
    #[error("`{field}` must be between {min} and {max}")]
    OutOfRange {
        /// Field name.
        field: &'static str,
        /// Inclusive lower bound.
        min: f32,
        /// Inclusive upper bound.
        max: f32,
    },
    /// More sinks were named than the limit allows.
    #[error("at most {max} sinks may be named")]
    TooManySinks {
        /// The bound that was exceeded.
        max: usize,
    },
    /// A sink name was empty or over-long.
    #[error("sink names must be 1–{max} characters")]
    BadSinkName {
        /// The bound that was exceeded.
        max: usize,
    },
}

impl NotifyRequest {
    /// Bound every field, or explain which one failed.
    ///
    /// # Errors
    ///
    /// Returns the first [`ValidationError`] encountered. Fields are checked in declaration order,
    /// so a given bad request always produces the same message.
    pub fn validate(self) -> Result<Notification, ValidationError> {
        self.check_sink_names()?;

        let title = single_line("title", &self.title, limits::MAX_TITLE_CHARS)?;
        if title.is_empty() {
            return Err(ValidationError::Empty { field: "title" });
        }

        Ok(Notification {
            title,
            content: multi_line("content", self.content, limits::MAX_CONTENT_CHARS)?,
            timeout_secs: positive_or_none("timeoutSecs", self.timeout_secs, limits::TIMEOUT_SECS)?,
            icon: opt_single_line("icon", self.icon, limits::MAX_ICON_CHARS)?,
            use_base64_icon: self.use_base64_icon.unwrap_or(false),
            source_app: opt_single_line(
                "sourceApp",
                self.source_app,
                limits::MAX_SOURCE_APP_CHARS,
            )?
            .unwrap_or_else(|| "VRCNext".to_owned()),
            sound: self.sound.unwrap_or(false),
            volume: in_range("volume", self.volume, limits::VOLUME)?.unwrap_or(0.7),
            audio_path: opt_single_line(
                "audioPath",
                self.audio_path,
                limits::MAX_AUDIO_PATH_CHARS,
            )?,
            height: in_range("height", self.height, limits::HEIGHT)?,
            opacity: in_range("opacity", self.opacity, limits::OPACITY)?.unwrap_or(1.0),
            urgency: self.urgency.unwrap_or_default(),
            always_show: self.always_show.unwrap_or(false),
        })
    }

    /// Validate once per target, applying that target's [`NotifyOverride`] if it has one.
    ///
    /// # Errors
    ///
    /// As [`NotifyRequest::validate`]. A patch that pushes a field out of bounds is reported
    /// against that field exactly as an out-of-bounds base value would be.
    pub fn resolve(self, targets: &[&str]) -> Result<ResolvedNotify, ValidationError> {
        self.check_sink_names()?;
        let overrides = self.overrides.clone().unwrap_or_default();

        let mut per_sink = BTreeMap::new();
        for target in targets {
            let resolved = match overrides.get(*target) {
                Some(patch) => self.clone().patched(patch).validate()?,
                None => self.clone().validate()?,
            };
            per_sink.insert((*target).to_owned(), resolved);
        }

        Ok(ResolvedNotify {
            base: self.validate()?,
            per_sink,
        })
    }

    /// The sink names this request asked for, if any.
    #[must_use]
    pub fn requested_sinks(&self) -> Option<&[String]> {
        self.sinks.as_deref()
    }

    /// Bound the `sinks` list on its own, ahead of full validation.
    ///
    /// Separate from [`NotifyRequest::validate`] because sink names are consumed earlier than
    /// everything else — they choose the targets, and target selection has to happen before a
    /// per-target validation pass is even possible. Without this, an unbounded name would reach
    /// the unknown-sink error message.
    ///
    /// # Errors
    ///
    /// [`ValidationError::TooManySinks`] or [`ValidationError::BadSinkName`].
    pub fn check_sink_names(&self) -> Result<(), ValidationError> {
        let Some(sinks) = &self.sinks else {
            return Ok(());
        };
        if sinks.len() > limits::MAX_REQUESTED_SINKS {
            return Err(ValidationError::TooManySinks {
                max: limits::MAX_REQUESTED_SINKS,
            });
        }
        for name in sinks {
            let len = name.chars().count();
            if len == 0 || len > limits::MAX_SINK_NAME_CHARS {
                return Err(ValidationError::BadSinkName {
                    max: limits::MAX_SINK_NAME_CHARS,
                });
            }
        }
        Ok(())
    }

    /// Apply a per-sink patch. `Some` replaces, `None` inherits.
    fn patched(mut self, patch: &NotifyOverride) -> Self {
        if let Some(title) = patch.title.clone() {
            self.title = title;
        }
        if let Some(content) = patch.content.clone() {
            self.content = content;
        }
        self.timeout_secs = patch.timeout_secs.or(self.timeout_secs);
        self.icon = patch.icon.clone().or(self.icon);
        self.use_base64_icon = patch.use_base64_icon.or(self.use_base64_icon);
        self.source_app = patch.source_app.clone().or(self.source_app);
        self.sound = patch.sound.or(self.sound);
        self.volume = patch.volume.or(self.volume);
        self.audio_path = patch.audio_path.clone().or(self.audio_path);
        self.height = patch.height.or(self.height);
        self.opacity = patch.opacity.or(self.opacity);
        self.urgency = patch.urgency.or(self.urgency);
        self.always_show = patch.always_show.or(self.always_show);
        self
    }
}

/// One request, validated once per target.
#[derive(Debug, Clone)]
pub struct ResolvedNotify {
    /// The request with no patch applied. Used for logging and for targets added later.
    pub base: Notification,
    /// The per-target result, keyed by sink name.
    pub per_sink: BTreeMap<String, Notification>,
}

impl ResolvedNotify {
    /// What `sink` should deliver, falling back to the unpatched request.
    #[must_use]
    pub fn for_sink(&self, sink: &str) -> &Notification {
        self.per_sink.get(sink).unwrap_or(&self.base)
    }
}

/// Bound the length and reject every control character.
fn single_line(field: &'static str, value: &str, max: usize) -> Result<String, ValidationError> {
    check_len(field, value, max)?;
    if value.chars().any(char::is_control) {
        return Err(ValidationError::ControlCharacter { field });
    }
    Ok(value.trim().to_owned())
}

/// As [`single_line`], but newlines and tabs are legitimate in body text.
fn multi_line(field: &'static str, value: String, max: usize) -> Result<String, ValidationError> {
    check_len(field, &value, max)?;
    if value
        .chars()
        .any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t')
    {
        return Err(ValidationError::ControlCharacter { field });
    }
    Ok(value)
}

fn opt_single_line(
    field: &'static str,
    value: Option<String>,
    max: usize,
) -> Result<Option<String>, ValidationError> {
    match value {
        None => Ok(None),
        Some(raw) => {
            let cleaned = single_line(field, &raw, max)?;
            Ok(if cleaned.is_empty() {
                None
            } else {
                Some(cleaned)
            })
        }
    }
}

/// Bound on `chars()`, not `len()`: the limit should mean the same thing for a Japanese title as
/// for an English one.
fn check_len(field: &'static str, value: &str, max: usize) -> Result<(), ValidationError> {
    if value.chars().count() > max {
        return Err(ValidationError::TooLong { field, max });
    }
    Ok(())
}

fn in_range(
    field: &'static str,
    value: Option<f32>,
    (min, max): (f32, f32),
) -> Result<Option<f32>, ValidationError> {
    let Some(value) = value else { return Ok(None) };
    if !value.is_finite() {
        return Err(ValidationError::NotFinite { field });
    }
    if value < min || value > max {
        return Err(ValidationError::OutOfRange { field, min, max });
    }
    Ok(Some(value))
}

/// As [`in_range`], but an explicit `0.0` means "unset" — that is how both XSOverlay-style
/// receivers and freedesktop spell "use your default timeout".
fn positive_or_none(
    field: &'static str,
    value: Option<f32>,
    range: (f32, f32),
) -> Result<Option<f32>, ValidationError> {
    Ok(in_range(field, value, range)?.filter(|v| *v > 0.0))
}
