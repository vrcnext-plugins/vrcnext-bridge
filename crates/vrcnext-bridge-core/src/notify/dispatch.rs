//! Target selection and per-target delivery reporting.

use std::sync::Arc;

use serde_json::Value;

use crate::notify::proto::ResolvedNotify;
use crate::notify::sink::Sink;

/// The sinks this bridge instance was started with, in registration order.
#[derive(Default, Clone)]
pub struct SinkSet {
    sinks: Vec<Arc<dyn Sink>>,
}

impl SinkSet {
    /// An empty set. A bridge with no sinks answers `notify/send` with a 503 rather than
    /// pretending to have delivered.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a sink, replacing any previous sink with the same name.
    pub fn register(&mut self, sink: Arc<dyn Sink>) {
        self.sinks.retain(|existing| existing.name() != sink.name());
        self.sinks.push(sink);
    }

    /// Whether any sink is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sinks.is_empty()
    }

    /// Every registered sink.
    #[must_use]
    pub fn all(&self) -> &[Arc<dyn Sink>] {
        &self.sinks
    }

    /// Resolve a request's `sinks` field to concrete targets.
    ///
    /// `None` selects everything. An explicit list is order-preserving and deduplicated.
    ///
    /// # Errors
    ///
    /// Returns a caller-facing message naming the unknown sink and listing what does exist. The
    /// echoed name is safe to include because [`NotifyRequest::validate`] has already bounded it
    /// to a short string.
    ///
    /// [`NotifyRequest::validate`]: crate::notify::NotifyRequest::validate
    pub fn select(&self, requested: Option<&[String]>) -> Result<Vec<Arc<dyn Sink>>, String> {
        let Some(requested) = requested else {
            return Ok(self.sinks.clone());
        };

        let mut selected: Vec<Arc<dyn Sink>> = Vec::new();
        for name in requested {
            let found = self
                .sinks
                .iter()
                .find(|sink| sink.name() == name)
                .ok_or_else(|| {
                    format!(
                        "unknown sink `{}`; this bridge has: {}",
                        name.escape_debug(),
                        self.names().join(", ")
                    )
                })?;
            if !selected.iter().any(|sink| sink.name() == found.name()) {
                selected.push(Arc::clone(found));
            }
        }
        Ok(selected)
    }

    /// Deliver to each target, using that target's resolved variant of the notification.
    ///
    /// Every target is attempted even if an earlier one failed: a plugin asking for VR *and*
    /// desktop should still reach the desktop when the overlay is not running.
    #[must_use]
    pub fn dispatch(&self, targets: &[Arc<dyn Sink>], resolved: &ResolvedNotify) -> DispatchReport {
        let outcomes = targets
            .iter()
            .map(|sink| {
                let name = sink.name();
                match sink.deliver(resolved.for_sink(name)) {
                    Ok(()) => {
                        log::debug!("delivered to {name}");
                        DeliveryOutcome::delivered(name)
                    }
                    Err(error) => {
                        log::warn!("delivery to {name} failed: {error}");
                        DeliveryOutcome::failed(name, error.to_string())
                    }
                }
            })
            .collect();
        DispatchReport { outcomes }
    }

    /// Registered sink names, in order.
    #[must_use]
    pub fn names(&self) -> Vec<&'static str> {
        self.sinks.iter().map(|sink| sink.name()).collect()
    }

    /// Self-description of every sink, for `describe` and `notify/targets`.
    #[must_use]
    pub fn describe(&self) -> Value {
        Value::Array(
            self.sinks
                .iter()
                .map(|sink| {
                    serde_json::json!({
                        "name": sink.name(),
                        "description": sink.describe(),
                        "health": sink.health().as_str(),
                        "honours": sink.honours(),
                    })
                })
                .collect(),
        )
    }
}

/// What happened for one target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryOutcome {
    /// The sink's name.
    pub sink: &'static str,
    /// The failure message, or `None` on success.
    pub error: Option<String>,
}

impl DeliveryOutcome {
    const fn delivered(sink: &'static str) -> Self {
        Self { sink, error: None }
    }

    const fn failed(sink: &'static str, error: String) -> Self {
        Self {
            sink,
            error: Some(error),
        }
    }

    /// Whether this target accepted the notification.
    #[must_use]
    pub const fn is_delivered(&self) -> bool {
        self.error.is_none()
    }
}

/// The result of one `notify/send`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchReport {
    /// One entry per target, in target order.
    pub outcomes: Vec<DeliveryOutcome>,
}

impl DispatchReport {
    /// Whether every target accepted.
    #[must_use]
    pub fn all_delivered(&self) -> bool {
        self.outcomes.iter().all(DeliveryOutcome::is_delivered)
    }

    /// Whether at least one target accepted.
    #[must_use]
    pub fn any_delivered(&self) -> bool {
        self.outcomes.iter().any(DeliveryOutcome::is_delivered)
    }

    /// The response body for `notify/send`.
    ///
    /// Partial success is reported as success with a populated `failed` list rather than as an
    /// error, because that is what it is: the notification reached the user somewhere.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let delivered: Vec<&str> = self
            .outcomes
            .iter()
            .filter(|outcome| outcome.is_delivered())
            .map(|outcome| outcome.sink)
            .collect();
        let failed: Vec<Value> = self
            .outcomes
            .iter()
            .filter_map(|outcome| {
                outcome
                    .error
                    .as_ref()
                    .map(|error| serde_json::json!({ "sink": outcome.sink, "error": error }))
            })
            .collect();

        serde_json::json!({
            "ok": self.any_delivered(),
            "delivered": delivered,
            "failed": failed,
        })
    }
}
