use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::ProtocolError;

pub const PERMISSION_REQUEST_EVENT: &str = "PermissionRequest";
pub const MAX_INPUT_BYTES: usize = 1024 * 1024;

#[derive(Debug, Deserialize)]
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

    let value: Value = serde_json::from_slice(input)?;
    if !value.is_object() {
        return Err(ProtocolError::NotAnObject);
    }

    Ok(serde_json::from_value(value)?)
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

    const INPUT: &str = r#"{
        "session_id": "sess_test",
        "cwd": "/tmp/example-workspace",
        "hook_event_name": "PermissionRequest",
        "tool_name": "Bash",
        "tool_input": {"command": "curl -I https://example.com"},
        "turn_id": "turn_test",
        "permission_mode": "default"
    }"#;

    #[test]
    fn parses_documented_permission_request_fields() {
        let input = parse(INPUT.as_bytes()).expect("valid input");
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
    fn renders_only_the_documented_allow_shape() {
        let rendered = serde_json::to_string(&allow_response()).expect("serializable");
        assert_eq!(
            rendered,
            r#"{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"allow"}}}"#
        );
    }
}
