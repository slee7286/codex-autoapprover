use crate::{arming, protocol::HookInput};

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Decline(DeclineReason),
}

#[derive(Debug, PartialEq, Eq)]
pub enum DeclineReason {
    WrongEvent,
    MissingRequiredField,
    WorkingDirectoryMismatch,
    UnsupportedCodexCompatibility,
    UnsupportedToolType,
    UnexpectedVerificationAction,
}

#[derive(Clone, Copy)]
pub struct DecisionContext<'a> {
    pub codex_version: &'a str,
    pub expected_cwd: &'a str,
    pub expected_command: Option<&'a str>,
    pub expected_tool_name: Option<&'a str>,
}

pub fn decide(input: &HookInput, context: DecisionContext<'_>) -> Decision {
    if input.hook_event_name.as_deref() != Some(crate::protocol::PERMISSION_REQUEST_EVENT) {
        return Decision::Decline(DeclineReason::WrongEvent);
    }

    if input.session_id.as_deref().is_none_or(str::is_empty)
        || input.cwd.as_deref().is_none_or(str::is_empty)
        || input.tool_name.as_deref().is_none_or(str::is_empty)
        || input.tool_input.is_none()
    {
        return Decision::Decline(DeclineReason::MissingRequiredField);
    }

    if context
        .expected_tool_name
        .is_some_and(|expected| input.tool_name.as_deref() != Some(expected))
    {
        return Decision::Decline(DeclineReason::UnsupportedToolType);
    }

    match crate::compatibility::runtime_request_schema(
        context.codex_version,
        crate::compatibility::OperatingSystem::current(),
        crate::compatibility::Surface::LocalCliLauncher,
        arming::PROTOCOL_VERSION,
        input.tool_name.as_deref().unwrap_or_default(),
    ) {
        crate::compatibility::RuntimeSchemaStatus::Supported => {}
        crate::compatibility::RuntimeSchemaStatus::UnsupportedTool => {
            return Decision::Decline(DeclineReason::UnsupportedToolType);
        }
        crate::compatibility::RuntimeSchemaStatus::UnsupportedPlatform
        | crate::compatibility::RuntimeSchemaStatus::UnsupportedSurface
        | crate::compatibility::RuntimeSchemaStatus::UnsupportedProtocol
        | crate::compatibility::RuntimeSchemaStatus::UnsupportedVersion => {
            return Decision::Decline(DeclineReason::UnsupportedCodexCompatibility);
        }
    }

    let Some(tool_input) = input
        .tool_input
        .as_ref()
        .and_then(serde_json::Value::as_object)
    else {
        return Decision::Decline(DeclineReason::UnsupportedToolType);
    };
    let command_is_string = tool_input
        .get("command")
        .and_then(serde_json::Value::as_str)
        .is_some();
    let nested_fields_are_supported = tool_input.iter().all(|(key, value)| {
        (key == "command" && value.is_string()) || (key == "description" && value.is_string())
    });
    if !command_is_string || !nested_fields_are_supported {
        return Decision::Decline(DeclineReason::UnsupportedToolType);
    }

    if input.cwd.as_deref() != Some(context.expected_cwd) {
        return Decision::Decline(DeclineReason::WorkingDirectoryMismatch);
    }

    if let Some(expected_command) = context.expected_command {
        let expected_input = serde_json::json!({"command": expected_command});
        if input.tool_input.as_ref() != Some(&expected_input) {
            return Decision::Decline(DeclineReason::UnexpectedVerificationAction);
        }
    }

    Decision::Allow
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol;

    fn input() -> HookInput {
        protocol::parse(
            br#"{"session_id":"sess","cwd":"/tmp/work","hook_event_name":"PermissionRequest","tool_name":"Bash","tool_input":{"command":"true"}}"#,
        )
        .expect("valid fixture")
    }

    fn context() -> DecisionContext<'static> {
        DecisionContext {
            codex_version: if cfg!(windows) { "0.152.1" } else { "0.151.0" },
            expected_cwd: "/tmp/work",
            expected_command: None,
            expected_tool_name: None,
        }
    }

    #[cfg(unix)]
    #[test]
    fn allows_only_an_armed_permission_request_with_matching_cwd() {
        assert_eq!(decide(&input(), context()), Decision::Allow);
    }

    #[cfg(windows)]
    #[test]
    fn runtime_decision_accepts_a_candidate_only_after_the_launcher_arms_it() {
        let context = DecisionContext {
            codex_version: "0.152.1",
            expected_cwd: "/tmp/work",
            expected_command: None,
            expected_tool_name: None,
        };
        assert_eq!(decide(&input(), context), Decision::Allow);
    }

    #[cfg(windows)]
    #[test]
    fn verification_mode_allows_candidate_permission_request_with_matching_cwd() {
        assert_eq!(decide(&input(), context()), Decision::Allow);
    }

    #[test]
    fn declines_wrong_event_and_wrong_cwd() {
        let mut wrong_event = input();
        wrong_event.hook_event_name = Some("PreToolUse".into());
        assert_eq!(
            decide(&wrong_event, context()),
            Decision::Decline(DeclineReason::WrongEvent)
        );
        let mut wrong_cwd = input();
        wrong_cwd.cwd = Some("/tmp/other".into());
        assert_eq!(
            decide(&wrong_cwd, context()),
            Decision::Decline(DeclineReason::WorkingDirectoryMismatch)
        );
    }

    #[test]
    fn accepts_only_documented_optional_bash_input_fields() {
        let mut optional = input();
        optional.tool_input = Some(serde_json::json!({
            "command": "true",
            "description": "harmless fixture",
        }));
        assert_eq!(decide(&optional, context()), Decision::Allow);

        let mut unknown = input();
        unknown.tool_input = Some(serde_json::json!({
            "command": "true",
            "future_control": true,
        }));
        assert_eq!(
            decide(&unknown, context()),
            Decision::Decline(DeclineReason::UnsupportedToolType)
        );
    }

    #[test]
    fn verification_allows_only_the_exact_authorized_command() {
        let expected_command = crate::compatibility::verification_probe_command();
        let verification_context = DecisionContext {
            expected_command: Some(expected_command),
            expected_tool_name: None,
            ..context()
        };
        assert_eq!(
            decide(&input(), verification_context),
            Decision::Decline(DeclineReason::UnexpectedVerificationAction)
        );

        let exact = input_with_command(expected_command);
        assert_eq!(decide(&exact, verification_context), Decision::Allow);

        let alternate_executable = if cfg!(windows) {
            "curl -I https://example.com"
        } else {
            "curl.exe -I https://example.com"
        };
        for command in [
            format!("{expected_command} "),
            format!("{expected_command} --silent"),
            format!("{expected_command} && echo extra"),
            alternate_executable.to_string(),
            "Invoke-WebRequest -Uri https://example.com".to_string(),
        ] {
            let candidate = input_with_command(&command);
            assert_eq!(
                decide(&candidate, verification_context),
                Decision::Decline(DeclineReason::UnexpectedVerificationAction),
                "unexpectedly authorized {command:?}"
            );
        }
    }

    fn input_with_command(command: &str) -> HookInput {
        protocol::parse(
            serde_json::to_vec(&serde_json::json!({
                "session_id": "sess",
                "cwd": "/tmp/work",
                "hook_event_name": "PermissionRequest",
                "tool_name": "Bash",
                "tool_input": {"command": command},
            }))
            .expect("serialize verification fixture")
            .as_slice(),
        )
        .expect("valid verification fixture")
    }
}
