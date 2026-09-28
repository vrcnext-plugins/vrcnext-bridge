//! What a caller sends, and what a received message looks like on the way back.
//!
//! OSC distinguishes an integer from a float and JSON does not, so a value may be given either
//! as a bare JSON value — the obvious reading, and what a plugin sending `true` or `0.5` wants —
//! or as `{ "kind": "float", "value": 1 }` when the distinction matters and the number happens
//! to be whole. VRChat rejects a parameter sent with the wrong type silently, so the explicit
//! form is the one a plugin reaches for once it has been bitten.

use rosc::OscType;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Longest OSC address accepted. VRChat's own are far shorter; this is a bound, not a target.
pub const MAX_ADDRESS: usize = 255;

/// Most arguments one message may carry.
pub const MAX_ARGS: usize = 32;

/// Why a request was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OscRequestError {
    /// The address was empty, too long, or not a legal OSC address pattern.
    #[error("{0}")]
    Address(String),
    /// An argument was of a kind OSC has no representation for.
    #[error("{0}")]
    Argument(String),
}

/// A message to send.
#[derive(Debug, Clone, Deserialize)]
pub struct SendRequest {
    /// Full OSC address, e.g. `/avatar/parameters/Seated` or `/chatbox/input`.
    pub address: String,
    /// Arguments, in order. Omitted means a message with no arguments, which is legal OSC.
    #[serde(default)]
    pub args: Vec<Value>,
    /// Where to send it. Omitted means VRChat's input port, which is what a plugin wants.
    pub port: Option<u16>,
}

/// One argument in the explicit form.
#[derive(Debug, Clone, Deserialize)]
struct TypedArg {
    kind: String,
    value: Value,
}

/// An OSC address as VRChat and the spec accept one.
///
/// Addresses arrive from a plugin, which is outside the trust boundary, and go straight into a
/// datagram. The characters excluded here are the ones OSC reserves for pattern matching, plus
/// anything non-printable — a stray NUL would truncate the address inside the packet.
///
/// # Errors
///
/// [`OscRequestError::Address`] when the address is empty, over [`MAX_ADDRESS`], does not start
/// with `/`, or contains a reserved or non-printable character.
pub fn check_address(address: &str) -> Result<(), OscRequestError> {
    if address.is_empty() || !address.starts_with('/') {
        return Err(OscRequestError::Address(
            "an OSC address must start with `/`".to_owned(),
        ));
    }
    if address.len() > MAX_ADDRESS {
        return Err(OscRequestError::Address(format!(
            "an OSC address may be at most {MAX_ADDRESS} bytes"
        )));
    }
    if let Some(bad) = address.chars().find(|c| {
        !c.is_ascii_graphic() || matches!(c, '#' | '*' | ',' | '?' | '[' | ']' | '{' | '}')
    }) {
        return Err(OscRequestError::Address(format!(
            "an OSC address may not contain `{bad}`"
        )));
    }
    Ok(())
}

/// Turn one JSON argument into its OSC type.
///
/// # Errors
///
/// [`OscRequestError::Argument`] for a kind OSC cannot carry, or an explicit `kind` that does
/// not match the value it was given.
pub fn to_osc(value: &Value) -> Result<OscType, OscRequestError> {
    if let Ok(typed) = serde_json::from_value::<TypedArg>(value.clone()) {
        return typed_to_osc(&typed);
    }
    match value {
        Value::Bool(flag) => Ok(OscType::Bool(*flag)),
        Value::String(text) => Ok(OscType::String(text.clone())),
        Value::Number(number) => Ok(number
            .as_i64()
            .and_then(|n| i32::try_from(n).ok())
            .map_or_else(|| OscType::Float(as_f32(value)), OscType::Int)),
        _ => Err(OscRequestError::Argument(
            "an OSC argument must be a boolean, a number, a string, or {kind, value}".to_owned(),
        )),
    }
}

/// `f64` to `f32` for the wire, which is what OSC's `f` tag carries.
#[expect(
    clippy::cast_possible_truncation,
    reason = "OSC's float type is 32-bit; the narrowing is the conversion, not an accident"
)]
fn as_f32(value: &Value) -> f32 {
    value.as_f64().unwrap_or(0.0) as f32
}

fn typed_to_osc(typed: &TypedArg) -> Result<OscType, OscRequestError> {
    match typed.kind.as_str() {
        "bool" => typed.value.as_bool().map(OscType::Bool),
        "int" => typed
            .value
            .as_i64()
            .and_then(|n| i32::try_from(n).ok())
            .map(OscType::Int),
        "float" => typed
            .value
            .as_f64()
            .map(|_| OscType::Float(as_f32(&typed.value))),
        "string" => typed
            .value
            .as_str()
            .map(|text| OscType::String(text.to_owned())),
        other => {
            return Err(OscRequestError::Argument(format!(
                "`{other}` is not an OSC kind; use bool, int, float or string"
            )));
        }
    }
    .ok_or_else(|| {
        OscRequestError::Argument(format!(
            "the value given does not fit the kind `{}`",
            typed.kind
        ))
    })
}

/// One received argument, as the page sees it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ReceivedArg {
    /// `bool`, `int`, `float`, `string`, or `other` for a type the page has no use for.
    pub kind: &'static str,
    /// The value, as the nearest JSON type.
    pub value: Value,
}

/// An OSC argument on its way to the page.
#[must_use]
pub fn from_osc(arg: &OscType) -> ReceivedArg {
    match arg {
        OscType::Bool(flag) => ReceivedArg {
            kind: "bool",
            value: Value::from(*flag),
        },
        OscType::Int(number) => ReceivedArg {
            kind: "int",
            value: Value::from(*number),
        },
        OscType::Float(number) => ReceivedArg {
            kind: "float",
            value: Value::from(*number),
        },
        OscType::Double(number) => ReceivedArg {
            kind: "float",
            value: Value::from(*number),
        },
        OscType::Long(number) => ReceivedArg {
            kind: "int",
            value: Value::from(*number),
        },
        OscType::String(text) => ReceivedArg {
            kind: "string",
            value: Value::from(text.clone()),
        },
        _ => ReceivedArg {
            kind: "other",
            value: Value::Null,
        },
    }
}

impl SendRequest {
    /// Validate the address and convert every argument.
    ///
    /// # Errors
    ///
    /// Whatever [`check_address`] or [`to_osc`] rejects, plus a message carrying more than
    /// [`MAX_ARGS`] arguments.
    pub fn into_message(self) -> Result<rosc::OscMessage, OscRequestError> {
        check_address(&self.address)?;
        if self.args.len() > MAX_ARGS {
            return Err(OscRequestError::Argument(format!(
                "a message may carry at most {MAX_ARGS} arguments"
            )));
        }
        let args = self
            .args
            .iter()
            .map(to_osc)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rosc::OscMessage {
            addr: self.address,
            args,
        })
    }
}
