use std::env;

#[cfg(any(unix, windows))]
use std::{fs, path::Path};
#[cfg(unix)]
use std::{process::Stdio, thread, time::Duration};

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

const SESSION_TOKEN_ENV: &str = "CODEX_AUTOAPPROVER_SESSION_TOKEN";
const SESSION_SOCKET_ENV: &str = "CODEX_AUTOAPPROVER_SESSION_SOCKET";
const PROTOCOL_ENV: &str = "CODEX_AUTOAPPROVER_HOOK_PROTOCOL";
const PROTOCOL_VERSION: &str = "permission-request-v1";
const LOCAL_CLI_SURFACE: &str = "local CLI launcher";

fn hook_command() -> Command {
    let mut command = Command::cargo_bin("codex-autoapprover").expect("binary built");
    command
        .env_remove(SESSION_TOKEN_ENV)
        .env_remove(SESSION_SOCKET_ENV)
        .env_remove(PROTOCOL_ENV);
    command
}

fn permission_request(cwd: &str) -> String {
    format!(
        r#"{{"session_id":"sess_test","cwd":"{cwd}","hook_event_name":"PermissionRequest","tool_name":"Bash","tool_input":{{"command":"printf synthetic"}},"turn_id":"turn_test","permission_mode":"default"}}"#
    )
}

#[test]
fn unarmed_permission_request_receives_no_decision() {
    hook_command()
        .args(["hook"])
        .write_stdin(permission_request("/tmp/work"))
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

#[test]
fn inherited_environment_metadata_alone_cannot_authorize() {
    let cwd = env::current_dir().expect("current directory");
    let token = "a".repeat(64);
    hook_command()
        .args(["hook"])
        .env(SESSION_TOKEN_ENV, &token)
        .env(PROTOCOL_ENV, PROTOCOL_VERSION)
        .env(
            "CODEX_AUTOAPPROVER_EXPECTED_CWD",
            cwd.to_str().expect("utf-8 cwd"),
        )
        .env("CODEX_AUTOAPPROVER_CODEX_VERSION", "0.151.0")
        .env("CODEX_AUTOAPPROVER_SURFACE", "local CLI launcher")
        .write_stdin(permission_request(cwd.to_str().expect("utf-8 cwd")))
        .assert()
        .success()
        .stdout(predicate::eq(""))
        .stderr(predicate::str::contains("printf synthetic").not())
        .stderr(predicate::str::contains(&token).not());
}

#[test]
fn expanded_hook_fields_are_ignored_without_broadening_the_decision() {
    let cwd = env::current_dir().expect("current directory");
    let token = "a".repeat(64);
    let input = format!(
        r#"{{"session_id":"sess_test","cwd":"{}","hook_event_name":"PermissionRequest","tool_name":"Bash","tool_input":{{"command":"printf synthetic"}},"future_field":{{"unexpected":"value"}}}}"#,
        cwd.display()
    );
    hook_command()
        .args(["hook"])
        .env(SESSION_TOKEN_ENV, &token)
        .env(PROTOCOL_ENV, PROTOCOL_VERSION)
        .env(
            "CODEX_AUTOAPPROVER_EXPECTED_CWD",
            cwd.to_str().expect("utf-8 cwd"),
        )
        .env("CODEX_AUTOAPPROVER_CODEX_VERSION", "0.151.0")
        .env("CODEX_AUTOAPPROVER_SURFACE", "local CLI launcher")
        .write_stdin(input)
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

#[test]
fn unsupported_tool_type_version_surface_and_protocol_receive_no_decision() {
    let cwd = env::current_dir().expect("current directory");
    let token = "a".repeat(64);
    for (version, surface, protocol, tool) in [
        ("0.150.9", LOCAL_CLI_SURFACE, PROTOCOL_VERSION, "Bash"),
        ("0.152.0", LOCAL_CLI_SURFACE, PROTOCOL_VERSION, "Bash"),
        ("0.151.0", "VS Code/IDE", PROTOCOL_VERSION, "Bash"),
        (
            "0.151.0",
            LOCAL_CLI_SURFACE,
            "permission-request-v2",
            "Bash",
        ),
        ("0.151.0", LOCAL_CLI_SURFACE, PROTOCOL_VERSION, "Mcp"),
    ] {
        let input = format!(
            r#"{{"session_id":"sess_test","cwd":"{}","hook_event_name":"PermissionRequest","tool_name":"{}","tool_input":{{"command":"printf synthetic"}}}}"#,
            cwd.display(),
            tool
        );
        hook_command()
            .args(["hook"])
            .env(SESSION_TOKEN_ENV, &token)
            .env(PROTOCOL_ENV, protocol)
            .env(
                "CODEX_AUTOAPPROVER_EXPECTED_CWD",
                cwd.to_str().expect("utf-8 cwd"),
            )
            .env("CODEX_AUTOAPPROVER_CODEX_VERSION", version)
            .env("CODEX_AUTOAPPROVER_SURFACE", surface)
            .write_stdin(input)
            .assert()
            .success()
            .stdout(predicate::str::is_empty());
    }
}

#[test]
fn malformed_empty_oversized_and_wrong_events_fail_closed() {
    for input in [
        String::new(),
        "not json".to_string(),
        r#"{"hook_event_name":"PreToolUse","cwd":"/tmp/work","session_id":"s","tool_name":"Bash","tool_input":{}}"#.to_string(),
        " ".repeat(1024 * 1024 + 1),
    ] {
        hook_command()
            .args(["hook"])
            .write_stdin(input)
            .assert()
            .success()
            .stdout(predicate::str::is_empty());
    }
}

#[test]
fn verification_action_restriction_is_fail_closed() {
    let cwd = env::current_dir().expect("current directory");
    let token = "a".repeat(64);
    hook_command()
        .args(["hook"])
        .env(SESSION_TOKEN_ENV, &token)
        .env(PROTOCOL_ENV, PROTOCOL_VERSION)
        .env(
            "CODEX_AUTOAPPROVER_EXPECTED_CWD",
            cwd.to_str().expect("utf-8 cwd"),
        )
        .env("CODEX_AUTOAPPROVER_CODEX_VERSION", "0.151.0")
        .env("CODEX_AUTOAPPROVER_SURFACE", "local CLI launcher")
        .write_stdin(permission_request(cwd.to_str().expect("utf-8 cwd")))
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

#[test]
fn verification_mode_requires_a_real_interactive_confirmation() {
    Command::cargo_bin("codex-autoapprover")
        .expect("binary built")
        .args(["verify-local-hook"])
        .write_stdin("VERIFY CODEX 0.151.0 HOOK\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("requires an interactive terminal"));
}

#[cfg(unix)]
#[test]
fn production_configuration_is_refused_for_an_unverified_local_version() {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new().expect("temporary directory");
    let fake = temp.path().join("codex");
    fs::write(&fake, "#!/bin/sh\nprintf 'codex-cli 0.150.9\\n'\n").expect("fake codex");
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o700)).expect("executable fake codex");
    Command::cargo_bin("codex-autoapprover")
        .expect("binary built")
        .env("PATH", temp.path())
        .args(["print-hook-config"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "no locally verified PermissionRequest compatibility",
        ));
}

#[cfg(unix)]
#[test]
fn print_hook_config_succeeds_for_verified_linux_cli_without_writing_home_config() {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new().expect("temporary directory");
    let fake = temp.path().join("codex");
    let home = temp.path().join("home");
    fs::create_dir(&home).expect("home directory");
    fs::write(&fake, "#!/bin/sh\nprintf 'codex-cli 0.151.0\\n'\n").expect("fake codex");
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o700)).expect("executable fake codex");

    Command::cargo_bin("codex-autoapprover")
        .expect("binary built")
        .env("PATH", temp.path())
        .env("HOME", &home)
        .args(["print-hook-config"])
        .assert()
        .success()
        .stdout(predicate::str::contains("[[hooks.PermissionRequest]]"))
        .stdout(predicate::str::contains("type = \"command\""));
    assert!(!home.join(".codex/config.toml").exists());
}

#[cfg(unix)]
#[test]
fn production_run_arms_only_after_exact_compatibility_succeeds() {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new().expect("temporary directory");
    let fake = temp.path().join("codex");
    let home = temp.path().join("home");
    fs::create_dir(&home).expect("home directory");
    fs::write(
        &fake,
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf 'codex-cli 0.151.0\\n'; exit 0; fi\nprintf 'armed=%s\\n' \"${CODEX_AUTOAPPROVER_SESSION_TOKEN:+yes}\"\nprintf 'socket=%s\\n' \"${CODEX_AUTOAPPROVER_SESSION_SOCKET:+yes}\"\nprintf 'args=%s|%s|%s\\n' \"$1\" \"$2\" \"$3\"\nprintf '{\"session_id\":\"fake\",\"cwd\":\"%s\",\"hook_event_name\":\"PermissionRequest\",\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"printf synthetic\"}}\\n' \"$(pwd)\" | \"$FAKE_HOOK_BIN\" hook\nexit 17\n",
    )
    .expect("fake codex");
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o700)).expect("executable fake codex");

    Command::cargo_bin("codex-autoapprover")
        .expect("binary built")
        .env("PATH", temp.path())
        .env("HOME", &home)
        .env(
            "FAKE_HOOK_BIN",
            env::var_os("CARGO_BIN_EXE_codex-autoapprover").expect("launcher path"),
        )
        .args(["run", "--", "exec", "--model", "synthetic"])
        .assert()
        .code(17)
        .stdout(predicate::str::contains("armed=yes\n"))
        .stdout(predicate::str::contains("socket=yes\n"))
        .stdout(predicate::str::contains("{\"hookSpecificOutput\":{"))
        .stdout(predicate::str::contains("args=-c|hooks.PermissionRequest="));
    assert!(!home.join(".codex/config.toml").exists());
}

#[cfg(unix)]
#[test]
fn run_forwards_arguments_and_exit_status_without_arming_unverified_version() {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new().expect("temporary directory");
    let fake = temp.path().join("codex");
    fs::write(
        &fake,
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf 'codex-cli 0.150.9\\n'; exit 0; fi\nprintf 'inherited=%s\\n' \"$INHERITED_TEST_VALUE\"\nprintf 'token=%s\\n' \"$CODEX_AUTOAPPROVER_SESSION_TOKEN\"\nprintf '%s\\n' \"$@\"\nexit 23\n",
    )
    .expect("fake codex");
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o700)).expect("executable fake codex");

    let original_path = env::var_os("PATH").unwrap_or_default();
    let path = format!(
        "{}:{}",
        temp.path().display(),
        Path::new(&original_path).display()
    );

    let mut command = Command::cargo_bin("codex-autoapprover").expect("binary built");
    command
        .env("PATH", path)
        .env("INHERITED_TEST_VALUE", "present")
        .args(["run", "--", "exec", "--model", "synthetic", "prompt"])
        .assert()
        .code(23)
        .stdout(predicate::str::contains("inherited=present\n"))
        .stdout(predicate::str::contains("token=\n"))
        .stdout(predicate::str::contains(
            "exec\n--model\nsynthetic\nprompt\n",
        ))
        .stderr(predicate::str::contains("automatic approval is DISABLED"));
}

#[cfg(unix)]
#[test]
fn run_rejects_a_codex_path_that_resolves_to_the_launcher() {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new().expect("temporary directory");
    let fake = temp.path().join("codex");
    let launcher = env::var_os("CARGO_BIN_EXE_codex-autoapprover").expect("launcher path");
    std::os::unix::fs::symlink(launcher, &fake).expect("symlink launcher as codex");
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o700)).expect("executable fake codex");

    let mut command = Command::cargo_bin("codex-autoapprover").expect("binary built");
    command
        .env("PATH", temp.path())
        .args(["run", "--", "--version"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("refusing recursive launch"));
}

#[test]
fn run_reports_a_missing_codex_without_starting_a_child() {
    let temp = TempDir::new().expect("temporary directory");
    let mut command = Command::cargo_bin("codex-autoapprover").expect("binary built");
    command
        .env("PATH", temp.path())
        .args(["run"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "resolve the official `codex` executable",
        ));
}

#[cfg(windows)]
fn windows_fake_codex_fixture(form: &str) -> (TempDir, std::path::PathBuf, std::path::PathBuf) {
    let temp = TempDir::new().expect("temporary directory");
    let directory = temp.path().join("space & unicode-测试");
    fs::create_dir(&directory).expect("fixture directory");
    let helper = env::var_os("CARGO_BIN_EXE_fake_codex").expect("fake Codex helper");
    let helper_copy = directory.join("fake_codex.exe");
    fs::copy(helper, &helper_copy).expect("copy fake Codex helper");
    let codex = directory.join(format!("codex{form}"));
    match form {
        ".exe" => {
            fs::copy(&helper_copy, &codex).expect("copy executable shim");
        }
        ".cmd" => fs::write(
            &codex,
            "@echo off\r\n\"%~dp0fake_codex.exe\" %*\r\nexit /b %ERRORLEVEL%\r\n",
        )
        .expect("write cmd shim"),
        ".ps1" => fs::write(
            &codex,
            "if ($args -contains '--version') { Write-Output 'codex-cli 0.152.1'; exit 0 }\r\n& (Join-Path $PSScriptRoot 'fake_codex.exe') @args\r\nexit $LASTEXITCODE\r\n",
        )
        .expect("write PowerShell shim"),
        _ => panic!("unsupported fake Codex form"),
    }
    let result = directory.join("result.txt");
    (temp, directory, result)
}

#[cfg(windows)]
fn windows_fixture_path(directory: &Path) -> std::ffi::OsString {
    let mut paths = vec![directory.to_path_buf()];
    if let Some(original) = env::var_os("PATH") {
        paths.extend(env::split_paths(&original));
    }
    env::join_paths(paths).expect("fixture PATH")
}

#[cfg(windows)]
#[test]
fn fake_codex_exe_cmd_and_ps1_preserve_arguments_stdio_and_exit_status() {
    for form in [".exe", ".cmd", ".ps1"] {
        let (_temp, directory, result) = windows_fake_codex_fixture(form);
        let path = windows_fixture_path(&directory);
        let codex_home = directory.join("codex-home");
        let argument = "space & pipe | $()";
        Command::cargo_bin("codex-autoapprover")
            .expect("binary built")
            .env("PATH", path)
            .env("CODEX_HOME", &codex_home)
            .env("FAKE_CODEX_RESULT_FILE", &result)
            .env("FAKE_CODEX_EXIT_CODE", "37")
            .args(["run", "--", "prompt", argument])
            .write_stdin("input from stdin\n")
            .assert()
            .code(37)
            .stdout(predicate::str::contains("fake-codex-stdout\n"))
            .stderr(predicate::str::contains("fake-codex-stderr\n"))
            .stderr(predicate::str::contains("automatic approval is DISABLED"));
        let recorded = fs::read_to_string(&result).expect("fake Codex result");
        assert_eq!(
            recorded,
            format!("prompt\n{argument}\n--stdin--\ninput from stdin\n")
        );
        assert!(!codex_home.join("config.toml").exists());
    }
}

#[cfg(windows)]
#[test]
fn windows_candidate_diagnose_and_print_config_gate_are_preserved() {
    let (_temp, directory, _result) = windows_fake_codex_fixture(".exe");
    let path = windows_fixture_path(&directory);
    let codex_home = directory.join("codex-home");
    Command::cargo_bin("codex-autoapprover")
        .expect("binary built")
        .env("PATH", path.clone())
        .env("CODEX_HOME", &codex_home)
        .args(["diagnose"])
        .assert()
        .success()
        .stdout(predicate::str::contains("platform: windows"))
        .stdout(predicate::str::contains("installed Codex version: 0.152.1"))
        .stdout(predicate::str::contains("candidate/unverified"))
        .stdout(predicate::str::contains("current process armed: no"));
    Command::cargo_bin("codex-autoapprover")
        .expect("binary built")
        .env("PATH", path)
        .env("CODEX_HOME", &codex_home)
        .args(["print-hook-config"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "no locally verified PermissionRequest compatibility",
        ));
    assert!(!codex_home.join("config.toml").exists());
}

#[cfg(unix)]
#[test]
fn run_inherits_stdin_stdout_and_stderr() {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new().expect("temporary directory");
    let fake = temp.path().join("codex");
    fs::write(
        &fake,
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf 'codex-cli 0.151.0\\n'; exit 0; fi\nread line\nprintf 'stdin=%s\\n' \"$line\"\nprintf 'child stderr\\n' >&2\n",
    )
    .expect("fake codex");
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o700)).expect("executable fake codex");

    let original_path = env::var_os("PATH").unwrap_or_default();
    let path = format!(
        "{}:{}",
        temp.path().display(),
        Path::new(&original_path).display()
    );

    let mut command = Command::cargo_bin("codex-autoapprover").expect("binary built");
    command
        .env("PATH", path)
        .args(["run"])
        .write_stdin("hello from stdin\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("stdin=hello from stdin\n"))
        .stderr(predicate::str::contains("child stderr\n"));
}

#[cfg(unix)]
#[test]
fn unrelated_process_cannot_reuse_a_live_bound_session() {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new().expect("temporary directory");
    let fake = temp.path().join("codex");
    let binding = temp.path().join("binding");
    fs::write(
        &fake,
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf 'codex-cli 0.151.0\\n'; exit 0; fi\nprintf '%s\\n%s\\n' \"$CODEX_AUTOAPPROVER_SESSION_SOCKET\" \"$CODEX_AUTOAPPROVER_SESSION_TOKEN\" > \"$BINDING_FILE\"\n/bin/sleep 2\n",
    )
    .expect("fake codex");
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o700)).expect("fake executable");

    let binary = env::var_os("CARGO_BIN_EXE_codex-autoapprover").expect("launcher path");
    let child = std::process::Command::new(&binary)
        .env("PATH", temp.path())
        .env("BINDING_FILE", &binding)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .args(["run"])
        .spawn()
        .expect("spawn launcher");
    for _ in 0..100 {
        if binding.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let binding_data = fs::read_to_string(&binding).expect("live binding fixture");
    let mut lines = binding_data.lines();
    let socket = lines.next().expect("socket path");
    let secret = lines.next().expect("session secret");
    let cwd = env::current_dir().expect("cwd");
    let result = Command::cargo_bin("codex-autoapprover")
        .expect("binary built")
        .args(["hook"])
        .env(SESSION_SOCKET_ENV, socket)
        .env(SESSION_TOKEN_ENV, secret)
        .env(PROTOCOL_ENV, PROTOCOL_VERSION)
        .write_stdin(permission_request(cwd.to_str().expect("utf-8 cwd")))
        .output()
        .expect("run unrelated hook");
    assert!(result.status.success());
    assert!(result.stdout.is_empty());
    let launcher_output = child.wait_with_output().expect("wait fake Codex");
    assert!(
        launcher_output.status.success(),
        "launcher failed: {}",
        String::from_utf8_lossy(&launcher_output.stderr)
    );
}

#[cfg(unix)]
#[test]
fn stale_session_secret_and_socket_cannot_authorize_after_shutdown() {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new().expect("temporary directory");
    let fake = temp.path().join("codex");
    let binding = temp.path().join("binding");
    fs::write(
        &fake,
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf 'codex-cli 0.151.0\\n'; exit 0; fi\nprintf '%s\\n%s\\n' \"$CODEX_AUTOAPPROVER_SESSION_SOCKET\" \"$CODEX_AUTOAPPROVER_SESSION_TOKEN\" > \"$BINDING_FILE\"\n",
    )
    .expect("fake codex");
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o700)).expect("fake executable");
    let binary = env::var_os("CARGO_BIN_EXE_codex-autoapprover").expect("launcher path");
    let status = std::process::Command::new(&binary)
        .env("PATH", temp.path())
        .env("BINDING_FILE", &binding)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .args(["run"])
        .status()
        .expect("run launcher");
    assert!(status.success());
    let binding_data = fs::read_to_string(&binding).expect("stale binding fixture");
    let mut lines = binding_data.lines();
    let socket = lines.next().expect("socket path");
    let secret = lines.next().expect("session secret");
    let cwd = env::current_dir().expect("cwd");
    let result = Command::cargo_bin("codex-autoapprover")
        .expect("binary built")
        .args(["hook"])
        .env(SESSION_SOCKET_ENV, socket)
        .env(SESSION_TOKEN_ENV, secret)
        .env(PROTOCOL_ENV, PROTOCOL_VERSION)
        .write_stdin(permission_request(cwd.to_str().expect("utf-8 cwd")))
        .output()
        .expect("run stale hook");
    assert!(result.status.success());
    assert!(result.stdout.is_empty());
    assert!(!Path::new(socket).exists());
}
