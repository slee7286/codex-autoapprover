//! Fixed-category compatibility observations for one launcher session.
//!
//! This module deliberately consumes only the private audit records emitted by
//! the hook/broker path. It never parses child stdout/stderr, command text,
//! hook payloads, credentials, or arbitrary error messages.

use std::{fs, io, path::Path};

use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAX_AUDIT_BYTES: usize = 64 * 1024;
pub const MAX_OUTCOME_COUNT: u32 = 64;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HookOutcome {
    NoHookInvocation,
    SuccessfulExchange,
    CompatibilityRejection,
    TransportFailure,
    ProtocolFailure,
}

impl HookOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoHookInvocation => "no_hook_invocation",
            Self::SuccessfulExchange => "successful_exchange",
            Self::CompatibilityRejection => "compatibility_rejection",
            Self::TransportFailure => "transport_failure",
            Self::ProtocolFailure => "protocol_failure",
        }
    }

    pub(crate) const fn audit_name(self) -> Option<&'static str> {
        match self {
            Self::NoHookInvocation => None,
            Self::SuccessfulExchange => Some("successful_exchange"),
            Self::CompatibilityRejection => Some("compatibility_rejection"),
            Self::TransportFailure => Some("transport_failure"),
            Self::ProtocolFailure => Some("protocol_failure"),
        }
    }

    pub(crate) fn from_audit_name(value: &str) -> Option<Self> {
        Some(match value {
            "successful_exchange" => Self::SuccessfulExchange,
            "compatibility_rejection" => Self::CompatibilityRejection,
            "transport_failure" => Self::TransportFailure,
            "protocol_failure" => Self::ProtocolFailure,
            _ => return None,
        })
    }
}

impl CommandOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandOutcome {
    Succeeded,
    Failed,
    Unknown,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HookOutcomeCounts {
    pub entry_count: u32,
    pub validated_request_count: u32,
    pub allow_count: u32,
    pub no_decision_count: u32,
    pub structured_emission_count: u32,
    pub stdout_error_count: u32,
    pub successful_exchange_count: u32,
    pub compatibility_rejection_count: u32,
    pub transport_failure_count: u32,
    pub protocol_failure_count: u32,
}

impl HookOutcomeCounts {
    pub(crate) fn validate(&self) -> Result<(), OutcomeError> {
        if [
            self.entry_count,
            self.validated_request_count,
            self.allow_count,
            self.no_decision_count,
            self.structured_emission_count,
            self.stdout_error_count,
            self.successful_exchange_count,
            self.compatibility_rejection_count,
            self.transport_failure_count,
            self.protocol_failure_count,
        ]
        .into_iter()
        .any(|count| count > MAX_OUTCOME_COUNT)
        {
            return Err(OutcomeError::TooManyRecords);
        }
        Ok(())
    }

    fn increment(value: &mut u32) -> Result<(), OutcomeError> {
        *value = value.checked_add(1).ok_or(OutcomeError::TooManyRecords)?;
        if *value > MAX_OUTCOME_COUNT {
            return Err(OutcomeError::TooManyRecords);
        }
        Ok(())
    }

    pub(crate) fn merge(&mut self, other: &Self) -> Result<(), OutcomeError> {
        for (left, right) in [
            (&mut self.entry_count, other.entry_count),
            (
                &mut self.validated_request_count,
                other.validated_request_count,
            ),
            (&mut self.allow_count, other.allow_count),
            (&mut self.no_decision_count, other.no_decision_count),
            (
                &mut self.structured_emission_count,
                other.structured_emission_count,
            ),
            (&mut self.stdout_error_count, other.stdout_error_count),
            (
                &mut self.successful_exchange_count,
                other.successful_exchange_count,
            ),
            (
                &mut self.compatibility_rejection_count,
                other.compatibility_rejection_count,
            ),
            (
                &mut self.transport_failure_count,
                other.transport_failure_count,
            ),
            (
                &mut self.protocol_failure_count,
                other.protocol_failure_count,
            ),
        ] {
            *left = left
                .checked_add(right)
                .ok_or(OutcomeError::TooManyRecords)?;
        }
        self.validate()
    }

    pub(crate) fn aggregate_hook_outcome(&self) -> HookOutcome {
        if self.protocol_failure_count > 0 {
            HookOutcome::ProtocolFailure
        } else if self.transport_failure_count > 0 {
            HookOutcome::TransportFailure
        } else if self.compatibility_rejection_count > 0 {
            HookOutcome::CompatibilityRejection
        } else if self.successful_exchange_count > 0 {
            HookOutcome::SuccessfulExchange
        } else if self.entry_count == 0 {
            HookOutcome::NoHookInvocation
        } else {
            HookOutcome::ProtocolFailure
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionOutcome {
    pub hook_outcome: HookOutcome,
    pub command_outcome: CommandOutcome,
    pub counts: HookOutcomeCounts,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SessionOutcomeAccumulator {
    counts: HookOutcomeCounts,
    command_outcome: Option<CommandOutcome>,
}

impl SessionOutcomeAccumulator {
    pub fn record_hook_outcome(&mut self, outcome: HookOutcome) -> Result<(), OutcomeError> {
        let field = match outcome {
            HookOutcome::NoHookInvocation => return Ok(()),
            HookOutcome::SuccessfulExchange => &mut self.counts.successful_exchange_count,
            HookOutcome::CompatibilityRejection => &mut self.counts.compatibility_rejection_count,
            HookOutcome::TransportFailure => &mut self.counts.transport_failure_count,
            HookOutcome::ProtocolFailure => &mut self.counts.protocol_failure_count,
        };
        HookOutcomeCounts::increment(field)
    }

    pub fn record_command_outcome(&mut self, outcome: CommandOutcome) {
        self.command_outcome = Some(match (self.command_outcome, outcome) {
            (Some(CommandOutcome::Failed), _) | (_, CommandOutcome::Failed) => {
                CommandOutcome::Failed
            }
            (Some(CommandOutcome::Unknown), _) | (_, CommandOutcome::Unknown) => {
                CommandOutcome::Unknown
            }
            _ => CommandOutcome::Succeeded,
        });
    }

    pub fn finish(self) -> SessionOutcome {
        SessionOutcome {
            hook_outcome: self.counts.aggregate_hook_outcome(),
            command_outcome: self.command_outcome.unwrap_or(CommandOutcome::Unknown),
            counts: self.counts,
        }
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum OutcomeError {
    #[error("compatibility outcome audit is too large or has too many records")]
    TooManyRecords,
    #[error("compatibility outcome audit is unavailable")]
    Unavailable,
    #[error("compatibility outcome audit is malformed")]
    Malformed,
}

pub fn read_audit(path: &Path) -> Result<SessionOutcomeAccumulator, OutcomeError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Default::default()),
        Err(_) => return Err(OutcomeError::Unavailable),
    };
    if bytes.len() > MAX_AUDIT_BYTES {
        return Err(OutcomeError::TooManyRecords);
    }
    let contents = String::from_utf8(bytes).map_err(|_| OutcomeError::Malformed)?;
    let mut accumulator = SessionOutcomeAccumulator::default();
    for line in contents.lines() {
        if line == "hook stage=entry" {
            HookOutcomeCounts::increment(&mut accumulator.counts.entry_count)?;
        } else if line.starts_with("request event=PermissionRequest ") {
            HookOutcomeCounts::increment(&mut accumulator.counts.validated_request_count)?;
        } else if line == "hook stage=broker_allow" {
            HookOutcomeCounts::increment(&mut accumulator.counts.allow_count)?;
        } else if line == "hook stage=broker_no_decision" {
            HookOutcomeCounts::increment(&mut accumulator.counts.no_decision_count)?;
        } else if line == "hook stage=stdout_written" {
            HookOutcomeCounts::increment(&mut accumulator.counts.structured_emission_count)?;
        } else if line == "hook stage=stdout_error" {
            HookOutcomeCounts::increment(&mut accumulator.counts.stdout_error_count)?;
        } else if let Some(value) = line.strip_prefix("hook outcome=") {
            let outcome = HookOutcome::from_audit_name(value).ok_or(OutcomeError::Malformed)?;
            accumulator.record_hook_outcome(outcome)?;
        }
    }
    Ok(accumulator)
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn aggregation_is_conservative_and_child_status_is_independent() {
        let mut accumulator = SessionOutcomeAccumulator::default();
        accumulator
            .record_hook_outcome(HookOutcome::SuccessfulExchange)
            .expect("successful exchange");
        accumulator.record_command_outcome(CommandOutcome::Failed);
        let outcome = accumulator.finish();
        assert_eq!(outcome.hook_outcome, HookOutcome::SuccessfulExchange);
        assert_eq!(outcome.command_outcome, CommandOutcome::Failed);

        let no_request = SessionOutcomeAccumulator::default().finish();
        assert_eq!(no_request.hook_outcome, HookOutcome::NoHookInvocation);
        assert_eq!(no_request.command_outcome, CommandOutcome::Unknown);
    }

    #[test]
    fn mixed_hook_outcomes_choose_the_most_conservative_fixed_category() {
        let mut accumulator = SessionOutcomeAccumulator::default();
        accumulator
            .record_hook_outcome(HookOutcome::SuccessfulExchange)
            .expect("success");
        accumulator
            .record_hook_outcome(HookOutcome::CompatibilityRejection)
            .expect("rejection");
        assert_eq!(
            accumulator.finish().hook_outcome,
            HookOutcome::CompatibilityRejection
        );

        let mut failed = SessionOutcomeAccumulator::default();
        failed
            .record_hook_outcome(HookOutcome::TransportFailure)
            .expect("transport");
        failed
            .record_hook_outcome(HookOutcome::ProtocolFailure)
            .expect("protocol");
        assert_eq!(failed.finish().hook_outcome, HookOutcome::ProtocolFailure);
    }

    #[test]
    fn audit_reader_accepts_only_bounded_fixed_categories() {
        let directory = TempDir::new().expect("temporary directory");
        let path = directory.path().join("outcome.log");
        std::fs::write(
            &path,
            "hook stage=entry\nrequest event=PermissionRequest tool_hash=abc\nhook stage=broker_allow\nhook stage=stdout_written\nhook outcome=successful_exchange\n",
        )
        .expect("audit");
        let outcome = read_audit(&path).expect("read audit").finish();
        assert_eq!(outcome.hook_outcome, HookOutcome::SuccessfulExchange);
        assert_eq!(outcome.counts.entry_count, 1);
        assert_eq!(outcome.counts.validated_request_count, 1);
        assert_eq!(outcome.counts.structured_emission_count, 1);

        std::fs::write(&path, "hook outcome=secret-command\n").expect("malformed audit");
        assert_eq!(read_audit(&path), Err(OutcomeError::Malformed));

        std::fs::write(
            &path,
            "hook stage=entry\nhook outcome=transport_failure\nhook outcome=protocol_failure\n",
        )
        .expect("failure audit");
        let failure = read_audit(&path).expect("read failure audit").finish();
        assert_eq!(failure.hook_outcome, HookOutcome::ProtocolFailure);
        assert_eq!(failure.counts.transport_failure_count, 1);
        assert_eq!(failure.counts.protocol_failure_count, 1);
    }

    #[test]
    fn an_entered_hook_without_a_terminal_outcome_is_protocol_failure() {
        let directory = TempDir::new().expect("temporary directory");
        let path = directory.path().join("outcome.log");
        std::fs::write(&path, "hook stage=entry\n").expect("audit");
        assert_eq!(
            read_audit(&path).expect("read audit").finish().hook_outcome,
            HookOutcome::ProtocolFailure
        );
    }
}
