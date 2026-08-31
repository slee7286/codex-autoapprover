use std::io::{self, Read, Write};

use anyhow::Result;

use crate::{audit, decision::Decision, protocol};

pub fn run() -> Result<i32> {
    let input = read_bounded_stdin()?;
    let parsed = match protocol::parse(&input) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("codex-autoapprover hook: no decision ({error})");
            return Ok(0);
        }
    };

    if let Err(error) = audit::hook_invoked(
        parsed.tool_name.as_deref(),
        parsed.hook_event_name.as_deref(),
    ) {
        eprintln!("codex-autoapprover hook: no decision (audit failure: {error})");
        return Ok(0);
    }

    if let Decision::Allow = crate::decision::decide(&parsed) {
        if let Err(error) = audit::hook_allow(
            parsed.tool_name.as_deref().unwrap_or("unknown"),
            parsed.tool_input.as_ref(),
        ) {
            eprintln!("codex-autoapprover hook: no decision (audit failure: {error})");
            return Ok(0);
        }
        let response = serde_json::to_vec(&protocol::allow_response())?;
        io::stdout().write_all(&response)?;
        io::stdout().write_all(b"\n")?;
        io::stdout().flush()?;
    }

    Ok(0)
}

fn read_bounded_stdin() -> Result<Vec<u8>> {
    let mut input = Vec::new();
    let mut limited = io::stdin().take((protocol::MAX_INPUT_BYTES + 1) as u64);
    limited.read_to_end(&mut input)?;
    Ok(input)
}
