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
    pub verification_only: bool,
}

pub fn decide(input: &HookInput, context: DecisionContext<'_>) -> Decision {
    let supported = if context.verification_only {
        crate::compatibility::verified_or_candidate_hook_support_for(
            context.codex_version,
            crate::compatibility::OperatingSystem::current(),
            crate::compatibility::Surface::LocalCliLauncher,
            arming::PROTOCOL_VERSION,
        )
    } else {
        crate::compatibility::verified_hook_support_for(
            context.codex_version,
            crate::compatibility::OperatingSystem::current(),
            crate::compatibility::Surface::LocalCliLauncher,
            arming::PROTOCOL_VERSION,
        )
    };
    if !supported {
        return Decision::Decline(DeclineReason::UnsupportedCodexCompatibility);
    }

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

    if !crate::compatibility::observed_tool_supported(
        context.codex_version,
        crate::compatibility::OperatingSystem::current(),
        crate::compatibility::Surface::LocalCliLauncher,
        arming::PROTOCOL_VERSION,
        input.tool_name.as_deref().unwrap_or_default(),
    ) {
        return Decision::Decline(DeclineReason::UnsupportedToolType);
    }

    if input.cwd.as_deref() != Some(context.expected_cwd) {
        return Decision::Decline(DeclineReason::WorkingDirectoryMismatch);
    }

    if let Some(expected_command) = context.expected_command {
        let actual_command = input
            .tool_input
            .as_ref()
            .and_then(|value| value.get("command"))
            .and_then(serde_json::Value::as_str);
        if actual_command != Some(expected_command) {
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
            verification_only: cfg!(windows),
        }
    }

    #[cfg(unix)]
    #[test]
    fn allows_only_an_armed_permission_request_with_matching_cwd() {
        assert_eq!(decide(&input(), context()), Decision::Allow);
    }

    #[cfg(windows)]
    #[test]
    fn production_decision_declines_unverified_windows_candidate() {
        let context = DecisionContext {
            codex_version: "0.152.1",
            expected_cwd: "/tmp/work",
            expected_command: None,
            verification_only: false,
        };
        assert_eq!(
            decide(&input(), context),
            Decision::Decline(DeclineReason::UnsupportedCodexCompatibility)
        );
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
    fn verification_allows_only_the_exact_authorized_command() {
        let expected_command = if cfg!(windows) {
            "curl.exe -I https://example.com"
        } else {
            "curl -I https://example.com"
        };
        let verification_context = DecisionContext {
            expected_command: Some(expected_command),
            verification_only: true,
            ..context()
        };
        assert_eq!(
            decide(&input(), verification_context),
            Decision::Decline(DeclineReason::UnexpectedVerificationAction)
        );

        let exact = if cfg!(windows) {
            protocol::parse(
                br#"{"session_id":"sess","cwd":"/tmp/work","hook_event_name":"PermissionRequest","tool_name":"Bash","tool_input":{"command":"curl.exe -I https://example.com"}}"#,
            )
        } else {
            protocol::parse(
                br#"{"session_id":"sess","cwd":"/tmp/work","hook_event_name":"PermissionRequest","tool_name":"Bash","tool_input":{"command":"curl -I https://example.com"}}"#,
            )
        }
        .expect("exact verification fixture");
        assert_eq!(decide(&exact, verification_context), Decision::Allow);
    }
}
