use std::io::{self, Read, Write};

use anyhow::Result;

use crate::{audit, broker, protocol, update::outcome::HookOutcome};

pub fn run() -> Result<i32> {
    let _ = audit::hook_stage("entry");
    let input = match read_bounded_stdin() {
        Ok(input) => input,
        Err(error) => {
            let _ = audit::hook_outcome(HookOutcome::ProtocolFailure);
            return Err(error);
        }
    };
    let _ = audit::hook_stage("stdin_read");
    let parsed = match protocol::parse(&input) {
        Ok(value) => value,
        Err(error) => {
            let _ = audit::hook_stage("stdin_parse_error");
            let _ = audit::hook_outcome(HookOutcome::ProtocolFailure);
            eprintln!("codex-autoapprover hook: no decision ({error})");
            return Ok(0);
        }
    };
    let _ = audit::hook_stage("stdin_parsed");
    let arming_stage = if crate::arming::is_armed() {
        "arming_valid"
    } else {
        "arming_invalid"
    };
    let _ = audit::hook_stage(arming_stage);
    let _ = audit::hook_stage("broker_request");

    match broker::request(&parsed) {
        Ok(true) => {
            let _ = audit::hook_stage("broker_allow");
            let _ = audit::hook_outcome(HookOutcome::SuccessfulExchange);
            let response = serde_json::to_vec(&protocol::allow_response())?;
            if let Err(error) = (|| -> io::Result<()> {
                io::stdout().write_all(&response)?;
                io::stdout().write_all(b"\n")?;
                io::stdout().flush()
            })() {
                let _ = audit::hook_stage("stdout_error");
                let _ = audit::hook_outcome(HookOutcome::ProtocolFailure);
                return Err(error.into());
            }
            let _ = audit::hook_stage("stdout_written");
        }
        Ok(false) => {
            let _ = audit::hook_stage("broker_no_decision");
            let _ = audit::hook_outcome(HookOutcome::CompatibilityRejection);
        }
        Err(error) => {
            let _ = audit::hook_stage("broker_error");
            let outcome = match broker::request_failure_kind(&error) {
                broker::RequestFailureKind::Transport => HookOutcome::TransportFailure,
                broker::RequestFailureKind::Protocol => HookOutcome::ProtocolFailure,
            };
            let _ = audit::hook_outcome(outcome);
            eprintln!("codex-autoapprover hook: no decision ({error})");
        }
    }

    Ok(0)
}

fn read_bounded_stdin() -> Result<Vec<u8>> {
    let mut input = Vec::new();
    let mut limited = io::stdin().take((protocol::MAX_INPUT_BYTES + 1) as u64);
    limited.read_to_end(&mut input)?;
    Ok(input)
}
