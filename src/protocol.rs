use std::collections::BTreeSet;

use serde::{
    Deserialize, Deserializer, Serialize,
    de::{MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Value};
use std::{fmt, result::Result as StdResult};

use crate::error::ProtocolError;

pub const PERMISSION_REQUEST_EVENT: &str = "PermissionRequest";
pub const MAX_INPUT_BYTES: usize = 1024 * 1024;

#[derive(Debug, Deserialize, Serialize)]
pub struct HookInput {
    pub hook_event_name: Option<String>,
    pub session_id: Option<String>,
    pub cwd: Option<String>,
    pub tool_name: Option<String>,
    pub tool_input: Option<Value>,
    #[serde(rename = "turn_id")]
    pub _turn_id: Option<String>,
    #[serde(rename = "permission_mode")]
    pub _permission_mode: Option<String>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct AllowResponse {
    #[serde(rename = "hookSpecificOutput")]
    pub hook_specific_output: HookSpecificOutput,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct HookSpecificOutput {
    #[serde(rename = "hookEventName")]
    pub hook_event_name: &'static str,
    pub decision: AllowDecision,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct AllowDecision {
    pub behavior: &'static str,
}

pub fn parse(input: &[u8]) -> Result<HookInput, ProtocolError> {
    if input.len() > MAX_INPUT_BYTES {
        return Err(ProtocolError::InputTooLarge(MAX_INPUT_BYTES));
    }

    let value = parse_unique_object(input)?;

    Ok(serde_json::from_value(value)?)
}

/// Parse one top-level JSON object while rejecting duplicate field names and
/// trailing bytes. Nested values remain governed by serde_json's bounded
/// parser and are never used to broaden an allow decision.
pub fn parse_unique_object(input: &[u8]) -> Result<Value, ProtocolError> {
    if !input
        .iter()
        .find(|byte| !byte.is_ascii_whitespace())
        .is_some_and(|byte| *byte == b'{')
    {
        return Err(ProtocolError::NotAnObject);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let value = deserializer.deserialize_map(UniqueObjectVisitor)?;
    deserializer
        .end()
        .map_err(|_| ProtocolError::TrailingData)?;
    Ok(value)
}

struct UniqueObjectVisitor;

impl<'de> Visitor<'de> for UniqueObjectVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON object")
    }

    fn visit_map<M>(self, mut map: M) -> StdResult<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut object = Map::new();
        let mut fields = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !fields.insert(key.clone()) {
                return Err(serde::de::Error::custom("duplicate field"));
            }
            object.insert(key, map.next_value::<StrictValue>()?.0);
        }
        Ok(Value::Object(object))
    }
}

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> StdResult<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(StrictValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> StdResult<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(StrictValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> StdResult<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(StrictValue(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> StdResult<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(StrictValue(
            serde_json::Number::from_f64(value)
                .map(Value::Number)
                .unwrap_or(Value::Null),
        ))
    }

    fn visit_str<E>(self, value: &str) -> StdResult<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(StrictValue(Value::String(value.into())))
    }

    fn visit_string<E>(self, value: String) -> StdResult<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(StrictValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> StdResult<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(StrictValue(Value::Null))
    }

    fn visit_unit<E>(self) -> StdResult<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(StrictValue(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> StdResult<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<StrictValue>()? {
            values.push(value.0);
        }
        Ok(StrictValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> StdResult<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut object = Map::new();
        let mut fields = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !fields.insert(key.clone()) {
                return Err(serde::de::Error::custom("duplicate field"));
            }
            object.insert(key, map.next_value::<StrictValue>()?.0);
        }
        Ok(StrictValue(Value::Object(object)))
    }
}

pub fn allow_response() -> AllowResponse {
    AllowResponse {
        hook_specific_output: HookSpecificOutput {
            hook_event_name: PERMISSION_REQUEST_EVENT,
            decision: AllowDecision { behavior: "allow" },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> String {
        format!(
            r#"{{
                "session_id": "sess_test",
                "cwd": "/tmp/example-workspace",
                "hook_event_name": "PermissionRequest",
                "tool_name": "Bash",
                "tool_input": {{"command": "{}"}},
                "turn_id": "turn_test",
                "permission_mode": "default"
            }}"#,
            crate::compatibility::verification_probe_command()
        )
    }

    #[test]
    fn parses_documented_permission_request_fields() {
        let input = input();
        let input = parse(input.as_bytes()).expect("valid input");
        assert_eq!(
            input.hook_event_name.as_deref(),
            Some(PERMISSION_REQUEST_EVENT)
        );
        assert_eq!(input.tool_name.as_deref(), Some("Bash"));
        assert!(input.tool_input.is_some());
    }

    #[test]
    fn rejects_non_objects_and_oversized_input() {
        assert!(matches!(parse(b"[]"), Err(ProtocolError::NotAnObject)));
        assert!(matches!(
            parse(&vec![b' '; MAX_INPUT_BYTES + 1]),
            Err(ProtocolError::InputTooLarge(MAX_INPUT_BYTES))
        ));
    }

    #[test]
    fn rejects_duplicate_fields_and_trailing_data() {
        assert!(
            parse(br#"{"hook_event_name":"PermissionRequest","hook_event_name":"PreToolUse"}"#)
                .is_err()
        );
        assert!(parse(br#"{"hook_event_name":"PermissionRequest"} trailing"#).is_err());
        assert!(parse(br#"{"tool_input":{"command":"one","command":"two"}}"#).is_err());
    }

    #[test]
    fn renders_only_the_documented_allow_shape() {
        let rendered = serde_json::to_string(&allow_response()).expect("serializable");
        assert_eq!(
            rendered,
            r#"{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"allow"}}}"#
        );
    }
}
