//! The bridge's extension point: a named capability with named methods.
//!
//! Everything the bridge can do for a plugin is a [`Service`]. The transport knows how to
//! authenticate a request, bound its size, rate-limit it and route it to
//! `<service>/<method>` — and nothing else. It has no notion of notifications, overlays or
//! sockets. Adding a capability is implementing this trait and calling
//! [`ServiceRegistry::register`].
//!
//! Methods take and return [`serde_json::Value`] rather than a generic parameter because services
//! are stored as trait objects. Each implementation deserialises its own typed request in one
//! place, which is also where its validation lives.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::Value;

/// Why a service call failed.
///
/// The variants map onto HTTP status codes via [`ServiceError::status`]. Messages are written for
/// a plugin author reading a console — they name what was wrong, and never echo caller-supplied
/// content back into the response body.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ServiceError {
    /// No service is registered under that name.
    #[error("unknown service `{0}`")]
    UnknownService(String),
    /// The service exists but has no such method.
    #[error("unknown method `{method}` on service `{service}`")]
    UnknownMethod {
        /// Service name.
        service: &'static str,
        /// The method that was requested.
        method: String,
    },
    /// The parameters were malformed or failed validation.
    #[error("{0}")]
    BadRequest(String),
    /// The capability exists but cannot be used in this environment right now.
    #[error("{0}")]
    Unavailable(String),
    /// The service failed for a reason that is not the caller's fault.
    #[error("{0}")]
    Internal(String),
}

impl ServiceError {
    /// The HTTP status this error should be reported as.
    #[must_use]
    pub const fn status(&self) -> u16 {
        match self {
            Self::UnknownService(_) | Self::UnknownMethod { .. } => 404,
            Self::BadRequest(_) => 400,
            Self::Unavailable(_) => 503,
            Self::Internal(_) => 500,
        }
    }

    /// A stable machine-readable code, so plugins can branch without parsing prose.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::UnknownService(_) => "unknown_service",
            Self::UnknownMethod { .. } => "unknown_method",
            Self::BadRequest(_) => "bad_request",
            Self::Unavailable(_) => "unavailable",
            Self::Internal(_) => "internal",
        }
    }
}

/// One capability the bridge offers.
///
/// Implementations are shared across worker threads behind an `Arc`, hence `Send + Sync` and the
/// `&self` receiver on [`Service::call`]. A service needing mutable state owns its own lock rather
/// than forcing the registry to serialise every request.
pub trait Service: Send + Sync {
    /// Stable name used in the URL path. Lowercase, no slashes.
    fn name(&self) -> &'static str;

    /// One sentence describing the capability, for `GET /v1/describe`.
    fn summary(&self) -> &'static str;

    /// Machine-readable self-description: methods, targets, current availability.
    ///
    /// Plugins call `GET /v1/describe` at startup and adapt, which is what lets a plugin written
    /// today keep working against a bridge that has grown new sinks or services.
    fn describe(&self) -> Value;

    /// Invoke a method.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError::UnknownMethod`] for an unrecognised method, and otherwise whatever
    /// the method itself rejects or fails with.
    fn call(&self, method: &str, params: Value) -> Result<Value, ServiceError>;
}

/// The set of services this bridge instance offers.
///
/// Ordered by name so `GET /v1/describe` and the startup banner are deterministic.
#[derive(Default)]
pub struct ServiceRegistry {
    services: BTreeMap<&'static str, Arc<dyn Service>>,
}

impl ServiceRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a service, replacing any previous registration under the same name.
    pub fn register(&mut self, service: Arc<dyn Service>) {
        self.services.insert(service.name(), service);
    }

    /// Registered services, ordered by name.
    pub fn services(&self) -> impl Iterator<Item = &Arc<dyn Service>> {
        self.services.values()
    }

    /// Whether anything is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.services.is_empty()
    }

    /// Route a call to `service`/`method`.
    ///
    /// # Errors
    ///
    /// [`ServiceError::UnknownService`] if nothing is registered under that name, otherwise
    /// whatever the service returns.
    pub fn call(&self, service: &str, method: &str, params: Value) -> Result<Value, ServiceError> {
        self.services
            .get(service)
            .ok_or_else(|| ServiceError::UnknownService(service.to_owned()))?
            .call(method, params)
    }

    /// The payload behind `GET /v1/describe`.
    #[must_use]
    pub fn describe(&self) -> Value {
        let services: serde_json::Map<String, Value> = self
            .services
            .values()
            .map(|service| {
                let mut entry = serde_json::Map::new();
                entry.insert("summary".to_owned(), Value::from(service.summary()));
                if let Value::Object(details) = service.describe() {
                    entry.extend(details);
                }
                (service.name().to_owned(), Value::Object(entry))
            })
            .collect();
        Value::Object(services)
    }
}
