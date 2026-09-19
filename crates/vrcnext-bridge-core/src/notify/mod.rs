//! The `notify` service: deliver a notification to one or more [`Sink`]s.
//!
//! ```text
//! POST /v1/notify/send      deliver, honouring `sinks` and `overrides`
//! POST /v1/notify/targets   list sinks, their health, and the fields each honours
//! ```
//!
//! Targeting is the point. A plugin that wants a big translucent panel in VR and nothing on the
//! desktop sends one call naming `wayvr`; a plugin that wants both, presented differently, sends
//! one call with an `overrides` entry per target. Delivery to one sink never blocks or fails
//! another — the response reports each target separately.

mod dispatch;
mod proto;
mod sink;

pub use dispatch::{DeliveryOutcome, DispatchReport, SinkSet};
pub use proto::{
    Notification, NotifyOverride, NotifyRequest, ResolvedNotify, Urgency, ValidationError,
};
pub use sink::{Sink, SinkError, SinkHealth};

use serde_json::Value;

use crate::service::{Service, ServiceError};

/// The notification capability, backed by whatever sinks were registered at startup.
pub struct NotifyService {
    sinks: SinkSet,
}

impl NotifyService {
    /// Wrap a sink set as a service.
    #[must_use]
    pub const fn new(sinks: SinkSet) -> Self {
        Self { sinks }
    }

    /// The sinks this service will deliver to.
    #[must_use]
    pub const fn sinks(&self) -> &SinkSet {
        &self.sinks
    }

    /// Validate and deliver.
    fn send(&self, params: Value) -> Result<Value, ServiceError> {
        let request: NotifyRequest = serde_json::from_value(params)
            .map_err(|error| ServiceError::BadRequest(error.to_string()))?;

        // Before selection, because selection consumes the names and its error message quotes
        // them. Everything else is validated later, once the targets are known.
        request
            .check_sink_names()
            .map_err(|error| ServiceError::BadRequest(error.to_string()))?;

        let targets = self
            .sinks
            .select(request.requested_sinks())
            .map_err(ServiceError::BadRequest)?;

        if targets.is_empty() {
            // Two different failures that would otherwise look identical: the caller asked for no
            // targets (their bug, 400), or this bridge has none configured (the operator's, 503).
            return Err(if request.requested_sinks().is_some() {
                ServiceError::BadRequest(
                    "`sinks` was empty; omit it to reach every target, or name at least one"
                        .to_owned(),
                )
            } else {
                ServiceError::Unavailable(
                    "no notification sinks are configured; start the bridge with at least one"
                        .to_owned(),
                )
            });
        }

        let names: Vec<&str> = targets.iter().map(|sink| sink.name()).collect();
        let resolved = request
            .resolve(&names)
            .map_err(|error| ServiceError::BadRequest(error.to_string()))?;

        Ok(self.sinks.dispatch(&targets, &resolved).to_json())
    }
}

impl Service for NotifyService {
    fn name(&self) -> &'static str {
        "notify"
    }

    fn summary(&self) -> &'static str {
        "Deliver notifications to VR overlays and the desktop, individually targetable."
    }

    fn describe(&self) -> Value {
        serde_json::json!({
            "methods": ["send", "targets"],
            "targets": self.sinks.describe(),
        })
    }

    fn call(&self, method: &str, params: Value) -> Result<Value, ServiceError> {
        match method {
            "send" => self.send(params),
            "targets" => Ok(serde_json::json!({ "targets": self.sinks.describe() })),
            other => Err(ServiceError::UnknownMethod {
                service: "notify",
                method: other.to_owned(),
            }),
        }
    }
}
