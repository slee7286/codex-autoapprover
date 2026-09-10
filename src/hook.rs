use std::io::{self, Read, Write};

use anyhow::Result;

use crate::{audit, broker, protocol};

pub fn run() -> Result<i32> {
    let _ = audit::hook_stage("entry");
    let input = read_bounded_stdin()?;
    let _ = audit::hook_stage("stdin_read");
    let parsed = match protocol::parse(&input) {
        Ok(value) => value,
        Err(error) => {
            let _ = audit::hook_stage("stdin_parse_error");
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
            let response = serde_json::to_vec(&protocol::allow_response())?;
            if let Err(error) = (|| -> io::Result<()> {
                io::stdout().write_all(&response)?;
                io::stdout().write_all(b"\n")?;
                io::stdout().flush()
            })() {
                let _ = audit::hook_stage("stdout_error");
                return Err(error.into());
            }
            let _ = audit::hook_stage("stdout_written");
        }
        Ok(false) => {
            let _ = audit::hook_stage("broker_no_decision");
        }
        Err(error) => {
            let _ = audit::hook_stage("broker_error");
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
