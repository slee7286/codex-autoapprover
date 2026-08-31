use crate::{arming, protocol::HookInput};

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Decline(DeclineReason),
}

#[derive(Debug, PartialEq, Eq)]
pub enum DeclineReason {
    Unarmed,
    WrongEvent,
    MissingRequiredField,
    WorkingDirectoryMismatch,
    UnsupportedHookProtocol,
    UnsupportedCodexCompatibility,
    UnsupportedToolType,
    UnexpectedVerificationAction,
}

pub fn decide(input: &HookInput) -> Decision {
    if !arming::valid_token(std::env::var(arming::SESSION_TOKEN_ENV).ok().as_deref()) {
        return Decision::Decline(DeclineReason::Unarmed);
    }

    if std::env::var(arming::PROTOCOL_ENV).ok().as_deref() != Some(arming::PROTOCOL_VERSION) {
        return Decision::Decline(DeclineReason::UnsupportedHookProtocol);
    }

    let Some(version) = std::env::var(arming::CODEX_VERSION_ENV).ok() else {
        return Decision::Decline(DeclineReason::UnsupportedCodexCompatibility);
    };
    if std::env::var(arming::SURFACE_ENV).ok().as_deref()
        != Some(crate::compatibility::Surface::LocalCliLauncher.as_str())
        || !crate::compatibility::verified_hook_support_for(
            &version,
            crate::compatibility::OperatingSystem::current(),
            crate::compatibility::Surface::LocalCliLauncher,
            arming::PROTOCOL_VERSION,
        )
    {
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
        &version,
        crate::compatibility::OperatingSystem::current(),
        crate::compatibility::Surface::LocalCliLauncher,
        arming::PROTOCOL_VERSION,
        input.tool_name.as_deref().unwrap_or_default(),
    ) {
        return Decision::Decline(DeclineReason::UnsupportedToolType);
    }

    if std::env::var(arming::EXPECTED_CWD_ENV).ok().as_deref() != input.cwd.as_deref() {
        return Decision::Decline(DeclineReason::WorkingDirectoryMismatch);
    }

    if let Ok(expected_command) = std::env::var(arming::VERIFICATION_COMMAND_ENV) {
        let actual_command = input
            .tool_input
            .as_ref()
            .and_then(|value| value.get("command"))
            .and_then(serde_json::Value::as_str);
        if actual_command != Some(expected_command.as_str()) {
            return Decision::Decline(DeclineReason::UnexpectedVerificationAction);
        }
    }

    Decision::Allow
}

#[cfg(test)]
mod tests {
    use std::sync::{Mutex, OnceLock};

    use super::*;
    use crate::protocol;

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("env lock")
    }

    fn input() -> HookInput {
        protocol::parse(
            br#"{"session_id":"sess","cwd":"/tmp/work","hook_event_name":"PermissionRequest","tool_name":"Bash","tool_input":{"command":"true"}}"#,
        )
        .expect("valid fixture")
    }

    fn set_armed() {
        unsafe {
            std::env::set_var(crate::arming::SESSION_TOKEN_ENV, "a".repeat(64));
            std::env::set_var(crate::arming::PROTOCOL_ENV, crate::arming::PROTOCOL_VERSION);
            std::env::set_var(crate::arming::CODEX_VERSION_ENV, "0.151.0");
            std::env::set_var(
                crate::arming::SURFACE_ENV,
                crate::compatibility::Surface::LocalCliLauncher.as_str(),
            );
            std::env::set_var(crate::arming::EXPECTED_CWD_ENV, "/tmp/work");
        }
    }

    fn clear_env() {
        unsafe {
            std::env::remove_var(crate::arming::SESSION_TOKEN_ENV);
            std::env::remove_var(crate::arming::PROTOCOL_ENV);
            std::env::remove_var(crate::arming::CODEX_VERSION_ENV);
            std::env::remove_var(crate::arming::SURFACE_ENV);
            std::env::remove_var(crate::arming::EXPECTED_CWD_ENV);
            std::env::remove_var(crate::arming::VERIFICATION_COMMAND_ENV);
        }
    }

    #[test]
    fn allows_only_an_armed_permission_request_with_matching_cwd() {
        let _guard = env_lock();
        set_armed();
        assert_eq!(decide(&input()), Decision::Allow);
        clear_env();
    }

    #[test]
    fn declines_wrong_event_and_wrong_cwd() {
        let _guard = env_lock();
        set_armed();
        let mut wrong_event = input();
        wrong_event.hook_event_name = Some("PreToolUse".into());
        assert_eq!(
            decide(&wrong_event),
            Decision::Decline(DeclineReason::WrongEvent)
        );
        let mut wrong_cwd = input();
        wrong_cwd.cwd = Some("/tmp/other".into());
        assert_eq!(
            decide(&wrong_cwd),
            Decision::Decline(DeclineReason::WorkingDirectoryMismatch)
        );
        clear_env();
    }

    #[test]
    fn verification_allows_only_the_exact_authorized_command() {
        let _guard = env_lock();
        set_armed();
        unsafe {
            std::env::set_var(
                crate::arming::VERIFICATION_COMMAND_ENV,
                "curl -I https://example.com",
            );
        }
        assert_eq!(
            decide(&input()),
            Decision::Decline(DeclineReason::UnexpectedVerificationAction)
        );

        let exact = protocol::parse(
            br#"{"session_id":"sess","cwd":"/tmp/work","hook_event_name":"PermissionRequest","tool_name":"Bash","tool_input":{"command":"curl -I https://example.com"}}"#,
        )
        .expect("exact verification fixture");
        assert_eq!(decide(&exact), Decision::Allow);
        clear_env();
    }
}
