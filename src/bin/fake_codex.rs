use std::{
    env, fs,
    io::{self, Read},
    process,
};

#[cfg(windows)]
use std::{
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
};

fn main() {
    let arguments: Vec<String> = env::args().skip(1).collect();
    if arguments.iter().any(|argument| argument == "--version") {
        println!("codex-cli 0.152.1");
        return;
    }

    if env::var_os("FAKE_CODEX_CAPABILITY_PROBE").is_some()
        && arguments
            .first()
            .is_some_and(|argument| argument == "--help")
    {
        println!("-c, --config");
        return;
    }
    if env::var_os("FAKE_CODEX_CAPABILITY_PROBE").is_some()
        && arguments.starts_with(&["features".into(), "list".into()])
    {
        println!("hooks stable true");
        return;
    }

    #[cfg(windows)]
    if env::var_os("FAKE_CODEX_INVOKE_HOOK").is_some() {
        invoke_generated_hook(&arguments);
        return;
    }

    let mut stdin = String::new();
    io::stdin()
        .read_to_string(&mut stdin)
        .expect("read fake Codex stdin");
    if let Some(path) = env::var_os("FAKE_CODEX_RESULT_FILE") {
        let mut result = arguments.join("\n");
        result.push_str("\n--stdin--\n");
        result.push_str(&stdin);
        fs::write(path, result).expect("write fake Codex result");
    }
    println!("fake-codex-stdout");
    eprintln!("fake-codex-stderr");
    let code = env::var("FAKE_CODEX_EXIT_CODE")
        .ok()
        .and_then(|value| value.parse::<i32>().ok())
        .unwrap_or(0);
    process::exit(code);
}

#[cfg(windows)]
fn invoke_generated_hook(arguments: &[String]) {
    let config = arguments
        .windows(2)
        .find(|pair| pair[0] == "-c")
        .map(|pair| pair[1].as_str())
        .expect("generated child-local hook configuration");
    let hook_command = decode_command_windows(config);
    let actual_cwd = env::current_dir().expect("fake Codex cwd");
    let request_cwd = env::var_os("FAKE_CODEX_REQUEST_CWD")
        .map(PathBuf::from)
        .unwrap_or_else(|| actual_cwd.clone());
    let permission_command =
        env::var("FAKE_CODEX_PERMISSION_COMMAND").unwrap_or_else(|_| "printf synthetic".into());
    let mut tool_input = serde_json::Map::new();
    tool_input.insert("command".into(), permission_command.into());
    if let Some(description) = env::var_os("FAKE_CODEX_PERMISSION_DESCRIPTION") {
        tool_input.insert(
            "description".into(),
            description.to_string_lossy().into_owned().into(),
        );
    }
    let request = serde_json::json!({
        "session_id": "fake-session",
        "cwd": request_cwd,
        "hook_event_name": "PermissionRequest",
        "tool_name": "Bash",
        "tool_input": tool_input,
    });

    let comspec = env::var_os("COMSPEC").unwrap_or_else(|| "cmd.exe".into());
    let mut hook = Command::new(comspec);
    hook.arg("/C")
        .arg(hook_command)
        .current_dir(actual_cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = hook.spawn().expect("spawn generated Windows hook command");
    child
        .stdin
        .take()
        .expect("hook stdin")
        .write_all(request.to_string().as_bytes())
        .expect("write generated hook stdin");
    let output = child
        .wait_with_output()
        .expect("wait for generated Windows hook command");
    print!("{}", String::from_utf8_lossy(&output.stdout));
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
    eprintln!(
        "fake Codex generated hook exit={}",
        output.status.code().unwrap_or(1)
    );
    process::exit(output.status.code().unwrap_or(1));
}

#[cfg(not(windows))]
fn invoke_generated_hook(_arguments: &[String]) {
    panic!("generated Windows hook fixture used on a non-Windows target");
}

#[cfg(windows)]
fn decode_command_windows(config: &str) -> String {
    let marker = "commandWindows=\"";
    let encoded = config
        .strip_prefix(
            "hooks.PermissionRequest=[{hooks=[{type=\"command\",command=\"\",commandWindows=\"",
        )
        .and_then(|value| value.strip_suffix("\"}]}]"))
        .or_else(|| {
            config
                .split_once(marker)
                .and_then(|(_, value)| value.strip_suffix("\"}]}]"))
        })
        .expect("commandWindows field");
    let mut decoded = String::new();
    let mut characters = encoded.chars();
    while let Some(character) = characters.next() {
        if character == '\\' {
            match characters.next().expect("complete TOML escape") {
                '\\' => decoded.push('\\'),
                '"' => decoded.push('"'),
                'n' => decoded.push('\n'),
                'r' => decoded.push('\r'),
                't' => decoded.push('\t'),
                escape => panic!("unsupported TOML escape {escape:?}"),
            }
        } else {
            decoded.push(character);
        }
    }
    decoded
}
