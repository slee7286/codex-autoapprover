use std::{
    env, fs,
    io::{self, BufRead, IsTerminal, Write},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use tempfile::TempDir;

use crate::{
    arming, audit,
    broker::{self, Broker, BrokerConfig, Session},
    cli::RunArgs,
    codex, compatibility, interrupt, process,
};

const VERIFICATION_COMMAND_LINUX: &str = "curl -I https://example.com";
const VERIFICATION_COMMAND_WINDOWS: &str = "curl.exe -I https://example.com";
const VERIFICATION_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const VERIFICATION_FIXTURE: &str = "codex-autoapprover-fixture.txt";
const VERIFICATION_COMMIT_MESSAGE: &str = "verification baseline";
const VERIFICATION_GIT_NAME: &str = "codex-autoapprover verification";
const VERIFICATION_GIT_EMAIL: &str = "codex-autoapprover-verification@localhost";

pub fn run(args: &RunArgs) -> Result<i32> {
    let installation = codex::inspect()?;
    let launcher = env::current_exe().context("resolve current launcher executable")?;
    let cwd = env::current_dir().context("read current working directory")?;
    let hook_supported = compatibility::verified_hook_support_for(
        &installation.version,
        compatibility::OperatingSystem::current(),
        compatibility::Surface::LocalCliLauncher,
        arming::PROTOCOL_VERSION,
    );

    if !hook_supported {
        eprintln!(
            "codex-autoapprover: Codex {} has no locally verified PermissionRequest compatibility; automatic approval is DISABLED",
            installation.version
        );
        let mut command = Command::new(&installation.path);
        command
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .args(&args.codex_args);
        let status = command
            .status()
            .with_context(|| format!("launch official Codex at {}", installation.path.display()))?;
        return Ok(codex::status_code(status));
    }

    let session = Session::create()?;
    let broker = Broker::start(
        &session,
        BrokerConfig {
            codex_version: installation.version.clone(),
            expected_cwd: cwd,
            expected_command: None,
            audit_path: None,
            verification_only: false,
        },
    )?;
    let mut command = codex::build_codex_command(&installation);
    command
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .arg("-c")
        .arg(codex::hook_command_value(&launcher))
        .args(&args.codex_args);
    if let Err(error) = session.arm_child(&mut command) {
        let _ = broker.shutdown();
        let cleanup = session.cleanup();
        return Err(with_cleanup_error(error, cleanup));
    }
    eprintln!(
        "codex-autoapprover: automatic one-request approvals ARMED for this Codex child; press Ctrl-C to stop"
    );
    let mut child = match command
        .spawn()
        .with_context(|| format!("launch official Codex at {}", installation.path.display()))
    {
        Ok(child) => child,
        Err(error) => {
            let _ = broker.shutdown();
            let cleanup = session.cleanup();
            return Err(with_cleanup_error(error, cleanup));
        }
    };
    // Install the parent-only observer after fork/exec so the child retains
    // Codex's default terminal signal dispositions.
    let interrupted = match interrupt::register_interrupt_flag() {
        Ok(value) => value,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            let _ = broker.shutdown();
            let cleanup = session.cleanup();
            return Err(with_cleanup_error(error, cleanup));
        }
    };
    let identity = match process::current_process_identity(child.id()) {
        Ok(identity) => identity,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            broker.stop_accepting();
            let _ = broker.shutdown();
            let cleanup = session.cleanup();
            return Err(with_cleanup_error(
                anyhow::anyhow!("record exact Codex child process identity: {error}"),
                cleanup,
            ));
        }
    };
    if let Err(error) = broker.set_codex_identity(identity) {
        let _ = child.kill();
        let _ = child.wait();
        let _ = broker.shutdown();
        let cleanup = session.cleanup();
        return Err(with_cleanup_error(error, cleanup));
    }
    let status = wait_for_bound_child(&mut child, &broker, &interrupted.flag)
        .with_context(|| format!("wait for official Codex at {}", installation.path.display()));
    let broker_result = broker.shutdown();
    let cleanup = session.cleanup();
    let status = status.and_then(|status| {
        broker_result.context("stop decision broker")?;
        cleanup?;
        Ok(status)
    })?;
    Ok(codex::status_code(status))
}

pub fn diagnose() -> Result<i32> {
    println!("codex-autoapprover version: {}", env!("CARGO_PKG_VERSION"));
    println!("platform: {}", std::env::consts::OS);
    println!(
        "launcher platform status: {}",
        compatibility::OperatingSystem::current().as_str()
    );
    println!(
        "surface: {}",
        compatibility::Surface::LocalCliLauncher.as_str()
    );
    println!("hook protocol: {}", arming::PROTOCOL_VERSION);
    println!(
        "current process armed: {}",
        if arming::is_armed() { "yes" } else { "no" }
    );
    println!(
        "hook configuration installed: not checked; this milestone never installs live configuration"
    );

    match codex::inspect() {
        Ok(installation) => {
            println!("resolved codex path: {}", installation.path.display());
            println!("installed Codex version: {}", installation.version);
            println!(
                "PermissionRequest compatibility: {}",
                compatibility::status_for_version(&installation.version)
            );
        }
        Err(error) => {
            println!("resolved codex path: unavailable");
            println!("installed Codex version: unavailable ({error})");
            println!("PermissionRequest compatibility: unverified");
        }
    }

    Ok(0)
}

pub fn print_hook_config() -> Result<i32> {
    let installation = codex::inspect()?;
    if !compatibility::verified_hook_support_for(
        &installation.version,
        compatibility::OperatingSystem::current(),
        compatibility::Surface::LocalCliLauncher,
        arming::PROTOCOL_VERSION,
    ) {
        bail!(
            "Codex {} has no locally verified PermissionRequest compatibility; refusing to print a support configuration",
            installation.version
        )
    }

    let launcher = env::current_exe().context("resolve current launcher executable")?;
    print!("{}", codex::hook_config_snippet(&launcher));
    Ok(0)
}

pub fn verify_local_hook() -> Result<i32> {
    if compatibility::is_wsl_runtime() {
        bail!("verify-local-hook requires native Windows, not WSL")
    }
    if !(cfg!(target_os = "linux") || cfg!(windows)) {
        bail!(
            "verify-local-hook is limited to the verified Linux path or the Windows candidate path"
        )
    }
    if cfg!(windows) && !compatibility::is_native_windows_runtime() {
        bail!("verify-local-hook requires native Windows, not WSL or another hosted runtime")
    }
    if !io::stdin().is_terminal() {
        bail!("verify-local-hook requires an interactive terminal; no live test was started")
    }

    let installation = codex::inspect()?;
    let expected_version = installation.version.clone();
    if expected_version.is_empty() {
        bail!("the installed Codex version is empty; refusing verification")
    }
    let verification_target = compatibility::verification_target_for_current_platform();
    if expected_version != verification_target {
        bail!(
            "verify-local-hook is limited to Codex {verification_target}; found {expected_version}; refusing verification"
        )
    }

    eprintln!();
    eprintln!("!!! ISOLATED LOCAL HOOK VERIFICATION !!!");
    eprintln!("This starts the official Codex executable with a child-local hook override.");
    eprintln!("Automatic approval is armed only for this verification child.");
    eprintln!("No persistent Codex configuration will be written.");
    eprintln!("The only authorized action is: {}", verification_command());
    eprintln!(
        "The test prompt forbids all other commands, file changes, Git changes, installs, and full access."
    );
    eprintln!(
        "The Codex hook-trust bypass is used only to run this process-local hook; it is not sandbox or approval bypass."
    );
    eprintln!();
    eprint!(
        "Type exactly `{} ` followed by Enter to continue: ",
        confirmation_phrase(&expected_version)
    );
    io::stderr()
        .flush()
        .context("flush verification confirmation prompt")?;

    let confirmation_interrupt = interrupt::register_interrupt_flag()?;
    confirm_with_timeout(&expected_version, &confirmation_interrupt.flag)?;

    let current_version = codex::version(&installation.path)?;
    if !compatibility::verification_version_matches(&current_version, &expected_version) {
        bail!(
            "Codex version changed during verification (expected {expected_version}, found {current_version}); refusing to start"
        )
    }
    // Do not let the confirmation handler be inherited by the Codex child.
    drop(confirmation_interrupt);

    let launcher = env::current_exe().context("resolve current launcher executable")?;
    let state = VerificationState::new()?;
    let repo_path = state.repository_path.clone();
    let audit_path = state.audit_path.clone();
    let session = match Session::create() {
        Ok(session) => session,
        Err(error) => {
            let cleanup = state.cleanup();
            return Err(with_cleanup_error(error, cleanup));
        }
    };
    let broker = match Broker::start(
        &session,
        BrokerConfig {
            codex_version: expected_version.clone(),
            expected_cwd: repo_path.clone(),
            expected_command: Some(verification_command().into()),
            audit_path: Some(audit_path.clone()),
            verification_only: true,
        },
    ) {
        Ok(broker) => broker,
        Err(error) => {
            let session_cleanup = session.cleanup();
            let state_cleanup = state.cleanup();
            return Err(with_cleanup_error(
                error,
                combine_cleanup(session_cleanup, state_cleanup),
            ));
        }
    };
    let mut command = codex::build_codex_command(&installation);
    command
        .args(["-s", "workspace-write", "-a", "on-request"])
        .arg("--dangerously-bypass-hook-trust")
        .arg("-c")
        .arg(codex::hook_command_value(&launcher))
        .arg(verification_prompt())
        .current_dir(&repo_path)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    if let Err(error) = session.arm_child(&mut command) {
        let broker_cleanup = broker.shutdown();
        let session_cleanup = session.cleanup();
        let state_cleanup = state.cleanup();
        return Err(with_cleanup_error(
            error,
            combine_cleanup(
                combine_cleanup(broker_cleanup, session_cleanup),
                state_cleanup,
            ),
        ));
    }

    let baseline_status = match temporary_repository_status(&repo_path) {
        Ok(status) => status,
        Err(error) => {
            let message = error.context("read clean baseline status before Codex launch");
            let cleanup = cleanup_bound_verification(state, broker, session);
            return Err(with_cleanup_error(message, cleanup));
        }
    };
    let baseline_clean = baseline_status.is_clean();
    eprintln!(
        "verification evidence: baseline clean immediately before Codex launch: {}",
        if baseline_clean { "yes" } else { "no" }
    );
    if !baseline_clean {
        print_repository_diagnostics(
            "pre-existing harness state before Codex child session",
            &baseline_status,
        );
        let message =
            anyhow::anyhow!("temporary repository baseline was dirty; no Codex child was launched");
        let cleanup = cleanup_bound_verification(state, broker, session);
        return Err(with_cleanup_error(message, cleanup));
    }

    eprintln!(
        "codex-autoapprover: launching isolated verification child; do not approve any action other than the displayed curl request"
    );
    let mut child = match command.spawn().with_context(|| {
        format!(
            "launch official Codex {} for isolated verification",
            installation.path.display()
        )
    }) {
        Ok(child) => child,
        Err(error) => {
            let cleanup = cleanup_bound_verification(state, broker, session);
            return Err(with_cleanup_error(error, cleanup));
        }
    };
    let identity = match process::current_process_identity(child.id()) {
        Ok(identity) => identity,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            let cleanup = cleanup_bound_verification(state, broker, session);
            return Err(with_cleanup_error(
                anyhow::anyhow!("record exact Codex child process identity: {error}"),
                cleanup,
            ));
        }
    };
    if let Err(error) = broker.set_codex_identity(identity) {
        let _ = child.kill();
        let _ = child.wait();
        let cleanup = cleanup_bound_verification(state, broker, session);
        return Err(with_cleanup_error(error, cleanup));
    }
    let interrupted = match interrupt::register_interrupt_flag() {
        Ok(value) => value,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            let cleanup = cleanup_bound_verification(state, broker, session);
            return Err(with_cleanup_error(error, cleanup));
        }
    };
    let status = match wait_for_bound_child(&mut child, &broker, &interrupted.flag) {
        Ok(status) => status,
        Err(error) => {
            let cleanup = cleanup_bound_verification(state, broker, session);
            return Err(with_cleanup_error(error, cleanup));
        }
    };

    let invocation_count = match audit::invocation_count(&audit_path)
        .context("read temporary hook invocation audit")
    {
        Ok(count) => count,
        Err(error) => {
            let cleanup = cleanup_bound_verification(state, broker, session);
            return Err(with_cleanup_error(error, cleanup));
        }
    };
    let allow_count = match audit::allow_record_count(&audit_path)
        .context("read temporary redacted hook audit")
    {
        Ok(count) => count,
        Err(error) => {
            let cleanup = cleanup_bound_verification(state, broker, session);
            return Err(with_cleanup_error(error, cleanup));
        }
    };
    let post_status = match temporary_repository_status(&repo_path) {
        Ok(status) => status,
        Err(error) => {
            eprintln!("verification evidence: post-run repository status: unavailable");
            eprintln!("verification diagnostics: post-run Git status could not be read");
            let message = error.context("read temporary repository status after Codex exit");
            let cleanup = cleanup_bound_verification(state, broker, session);
            return Err(with_cleanup_error(message, cleanup));
        }
    };
    let repository_clean = post_status.is_clean();

    eprintln!("verification evidence: hook invocation count: {invocation_count}");
    eprintln!("verification evidence: allowed PermissionRequest count: {allow_count}");
    eprintln!(
        "verification evidence: Codex exit status: {}",
        codex::status_code(status)
    );
    eprintln!(
        "verification evidence: temporary repository clean: {}",
        if repository_clean { "yes" } else { "no" }
    );
    if !repository_clean {
        print_repository_diagnostics(
            "changes during Codex child session (post-run porcelain entries)",
            &post_status,
        );
    }

    let cleanup_result = cleanup_bound_verification(state, broker, session);
    let cleanup_completed = cleanup_result.is_ok();
    eprintln!(
        "verification evidence: temporary state cleanup completed: {}",
        if cleanup_completed { "yes" } else { "no" }
    );
    if let Err(error) = cleanup_result {
        eprintln!("verification diagnostics: temporary state cleanup failed");
        return Err(error);
    }
    eprintln!(
        "codex-autoapprover: Codex {expected_version} remains production-unsupported until this evidence is reviewed and the exact command result is confirmed."
    );

    if !baseline_clean {
        bail!("temporary repository baseline was dirty; compatibility was not promoted")
    }
    if invocation_count != 1 || allow_count != 1 {
        bail!(
            "expected exactly one hook invocation and exactly one allow, recorded {invocation_count} invocation(s) and {allow_count} allow(s); compatibility was not promoted"
        )
    }
    if !repository_clean {
        bail!("the temporary repository was modified; compatibility was not promoted")
    }
    if !status.success() {
        bail!("Codex verification child failed; compatibility was not promoted")
    }

    eprintln!(
        "verification completed, but no production compatibility promotion was performed automatically"
    );
    Ok(0)
}

fn verification_command() -> &'static str {
    if cfg!(windows) {
        VERIFICATION_COMMAND_WINDOWS
    } else {
        VERIFICATION_COMMAND_LINUX
    }
}

fn confirmation_phrase(version: &str) -> String {
    if cfg!(windows) {
        format!("VERIFY CODEX {version} WINDOWS HOOK")
    } else {
        format!("VERIFY CODEX {version} HOOK")
    }
}

fn confirm_with_timeout(version: &str, interrupted: &AtomicBool) -> Result<()> {
    let expected = confirmation_phrase(version);
    let (sender, receiver) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let mut line = String::new();
        let result = io::stdin()
            .lock()
            .read_line(&mut line)
            .map(|bytes| (bytes, line));
        let _ = sender.send(result);
    });

    let started = Instant::now();
    loop {
        if interrupted.load(Ordering::Relaxed) {
            bail!("verification cancelled before launch")
        }
        let remaining = VERIFICATION_TIMEOUT.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            bail!("verification confirmation timed out; no live test was started")
        }
        match receiver.recv_timeout(remaining.min(Duration::from_millis(100))) {
            Ok(Ok((0, _line))) => {
                bail!("confirmation input reached EOF; no live test was started")
            }
            Ok(Ok((_, line))) if confirmation_matches(&line, &expected) => return Ok(()),
            Ok(Ok(_)) => bail!("incorrect confirmation phrase; no live test was started"),
            Ok(Err(error)) => {
                bail!("could not read confirmation; no live test was started: {error}")
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                bail!("confirmation input closed; no live test was started")
            }
        }
    }
}

fn confirmation_matches(line: &str, expected: &str) -> bool {
    line.trim_end_matches(&['\r', '\n'][..]) == expected
}

fn wait_for_bound_child(
    child: &mut Child,
    broker: &broker::Broker,
    interrupted: &AtomicBool,
) -> Result<ExitStatus> {
    loop {
        if interrupted.load(Ordering::Relaxed) {
            broker.stop_accepting();
        }
        if let Some(status) = child.try_wait().context("wait for Codex child")? {
            return Ok(status);
        }
        thread::sleep(Duration::from_millis(25));
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct RepositoryStatus {
    entries: Vec<String>,
}

impl RepositoryStatus {
    fn is_clean(&self) -> bool {
        self.entries.is_empty()
    }
}

struct VerificationState {
    repository: TempDir,
    evidence: TempDir,
    repository_path: PathBuf,
    audit_path: PathBuf,
}

impl VerificationState {
    fn new() -> Result<Self> {
        let repository = TempDir::new().context("create isolated temporary repository")?;
        let evidence = match TempDir::new() {
            Ok(evidence) => evidence,
            Err(error) => {
                let cleanup = repository.close();
                let creation = anyhow::Error::new(error)
                    .context("create temporary verification evidence directory");
                return Err(with_cleanup_error(
                    creation,
                    cleanup.map_err(anyhow::Error::from),
                ));
            }
        };

        if let Err(error) = initialize_temporary_repository(repository.path()) {
            let cleanup = close_temp_dirs(repository, evidence);
            return Err(with_cleanup_error(error, cleanup));
        }

        let audit_path = evidence.path().join("hook-audit.log");
        if let Err(error) =
            audit::initialize(&audit_path).context("initialize temporary redacted hook audit")
        {
            let cleanup = close_temp_dirs(repository, evidence);
            return Err(with_cleanup_error(error, cleanup));
        }

        Ok(Self {
            repository_path: repository.path().to_path_buf(),
            audit_path,
            repository,
            evidence,
        })
    }

    fn cleanup(self) -> Result<()> {
        close_temp_dirs(self.repository, self.evidence)
    }
}

fn close_temp_dirs(repository: TempDir, evidence: TempDir) -> Result<()> {
    let repository_result = repository.close();
    let evidence_result = evidence.close();
    match (repository_result, evidence_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(repository), Ok(())) => {
            Err(repository).context("remove temporary verification repository")
        }
        (Ok(()), Err(evidence)) => Err(evidence).context("remove temporary verification evidence"),
        (Err(repository), Err(evidence)) => bail!(
            "remove temporary verification repository and evidence: repository cleanup failed: {repository}; evidence cleanup failed: {evidence}"
        ),
    }
}

fn with_cleanup_error(error: anyhow::Error, cleanup: Result<()>) -> anyhow::Error {
    match cleanup {
        Ok(()) => error,
        Err(cleanup) => error.context(format!(
            "temporary verification cleanup also failed: {cleanup:#}"
        )),
    }
}

fn combine_cleanup(first: Result<()>, second: Result<()>) -> Result<()> {
    match (first, second) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(first), Ok(())) => Err(first),
        (Ok(()), Err(second)) => Err(second),
        (Err(first), Err(second)) => Err(anyhow::anyhow!(
            "cleanup failed: {first:#}; additional cleanup failed: {second:#}"
        )),
    }
}

fn cleanup_bound_verification(
    state: VerificationState,
    broker: Broker,
    session: Session,
) -> Result<()> {
    combine_cleanup(
        combine_cleanup(broker.shutdown(), session.cleanup()),
        state.cleanup(),
    )
}

fn initialize_temporary_repository(path: &Path) -> Result<()> {
    let status = git_command(path)
        .args(["init", "--quiet"])
        .status()
        .context("initialize temporary Git repository")?;
    if !status.success() {
        bail!(
            "git init failed in temporary repository with {}",
            codex::status_code(status)
        )
    }

    fs::write(
        path.join(VERIFICATION_FIXTURE),
        b"harmless verification fixture\n",
    )
    .context("create harmless temporary Git fixture")?;

    let add_status = git_command(path)
        .args(["add", "--", VERIFICATION_FIXTURE])
        .status()
        .context("stage temporary Git fixture")?;
    if !add_status.success() {
        bail!(
            "git add failed in temporary repository with {}",
            codex::status_code(add_status)
        )
    }

    let commit_status = git_command(path)
        .args([
            "-c",
            &format!("user.name={VERIFICATION_GIT_NAME}"),
            "-c",
            &format!("user.email={VERIFICATION_GIT_EMAIL}"),
            "-c",
            "commit.gpgSign=false",
            "-c",
            "core.hooksPath=/dev/null",
            "commit",
            "--quiet",
            "--no-gpg-sign",
            "-m",
            VERIFICATION_COMMIT_MESSAGE,
        ])
        .status()
        .context("create temporary Git baseline commit")?;
    if !commit_status.success() {
        bail!(
            "temporary Git baseline commit failed with {}",
            codex::status_code(commit_status)
        )
    }

    verify_clean_baseline(path).context("verify temporary Git baseline after commit")?;
    Ok(())
}

fn git_command(path: &Path) -> Command {
    let mut command = Command::new("git");
    command
        .current_dir(path)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

fn temporary_repository_status(path: &Path) -> Result<RepositoryStatus> {
    let output = {
        let mut command = git_command(path);
        command
            .args([
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
                "--ignored",
            ])
            .stdout(Stdio::piped())
            .output()
    }
    .context("inspect temporary repository state")?;
    if !output.status.success() {
        bail!(
            "git status failed while inspecting temporary repository with {}",
            codex::status_code(output.status)
        )
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(RepositoryStatus {
        entries: stdout.lines().map(str::to_owned).collect(),
    })
}

fn verify_clean_baseline(path: &Path) -> Result<RepositoryStatus> {
    let status = temporary_repository_status(path)?;
    if !status.is_clean() {
        print_repository_diagnostics(
            "pre-existing harness state before Codex child session",
            &status,
        );
        bail!("temporary repository baseline is dirty")
    }
    Ok(status)
}

fn print_repository_diagnostics(label: &str, status: &RepositoryStatus) {
    eprint!("{}", format_repository_diagnostics(label, status));
}

fn format_repository_diagnostics(label: &str, status: &RepositoryStatus) -> String {
    let mut output = format!("verification diagnostics: {label}\n");
    if status.entries.is_empty() {
        output.push_str("  (none)\n");
    } else {
        for entry in &status.entries {
            output.push_str("  ");
            output.push_str(entry);
            output.push('\n');
        }
    }
    output
}

fn verification_prompt() -> &'static str {
    "Run exactly `curl -I https://example.com` and do nothing else. If sandboxed network access is blocked, request approval for that exact command. Do not substitute another command. Do not create or modify files, install software, alter Git state, use full access, or perform any other action. Report completion."
}

#[allow(dead_code)]
fn wait_for_verification_child(mut child: Child, interrupted: &AtomicBool) -> Result<ExitStatus> {
    let started = Instant::now();
    loop {
        if interrupted.load(Ordering::Relaxed) {
            let _ = child.kill();
            let _ = child.wait();
            bail!("verification interrupted; child stopped and temporary state will be cleaned up")
        }
        if started.elapsed() >= VERIFICATION_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            bail!("verification timed out; child stopped and temporary state will be cleaned up")
        }
        if let Some(status) = child.try_wait().context("wait for verification child")? {
            return Ok(status);
        }
        thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn confirmation_requires_the_exact_generated_phrase() {
        assert_eq!(confirmation_phrase("0.151.0"), "VERIFY CODEX 0.151.0 HOOK");
        assert!(confirmation_matches(
            "VERIFY CODEX 0.151.0 HOOK\n",
            "VERIFY CODEX 0.151.0 HOOK"
        ));
        assert!(!confirmation_matches("yes\n", "VERIFY CODEX 0.151.0 HOOK"));
    }

    #[test]
    fn clean_committed_baseline_is_detected() {
        let repository = TempDir::new().expect("temporary directory");
        initialize_temporary_repository(repository.path()).expect("create baseline");
        let status = verify_clean_baseline(repository.path()).expect("clean baseline");
        assert!(status.is_clean());
        assert!(repository.path().join(VERIFICATION_FIXTURE).is_file());
    }

    #[test]
    fn dirty_baseline_is_refused_and_reported_as_pre_existing_state() {
        let repository = TempDir::new().expect("temporary directory");
        initialize_temporary_repository(repository.path()).expect("create baseline");
        fs::write(repository.path().join("preexisting.txt"), "synthetic").expect("dirty fixture");

        let error = verify_clean_baseline(repository.path()).expect_err("dirty baseline");
        assert!(error.to_string().contains("baseline is dirty"));
        let status = temporary_repository_status(repository.path()).expect("status");
        assert_eq!(status.entries, vec!["?? preexisting.txt"]);
    }

    #[cfg(unix)]
    #[test]
    fn child_created_untracked_file_is_detected() {
        let repository = TempDir::new().expect("temporary directory");
        initialize_temporary_repository(repository.path()).expect("create baseline");
        run_fixture_child(repository.path(), "touch child-untracked.txt");
        assert_eq!(
            temporary_repository_status(repository.path())
                .expect("status")
                .entries,
            vec!["?? child-untracked.txt"]
        );
    }

    #[test]
    fn child_created_ignored_file_is_detected() {
        let repository = TempDir::new().expect("temporary directory");
        initialize_temporary_repository(repository.path()).expect("create baseline");
        fs::write(
            repository.path().join(".git/info/exclude"),
            "child-ignored.txt\n",
        )
        .expect("add local ignore rule");
        fs::write(repository.path().join("child-ignored.txt"), "synthetic")
            .expect("create ignored child file");
        assert_eq!(
            temporary_repository_status(repository.path())
                .expect("status")
                .entries,
            vec!["!! child-ignored.txt"]
        );
    }

    #[test]
    fn child_modified_tracked_file_is_detected() {
        let repository = TempDir::new().expect("temporary directory");
        initialize_temporary_repository(repository.path()).expect("create baseline");
        fs::write(
            repository.path().join(VERIFICATION_FIXTURE),
            "child changed\n",
        )
        .expect("modify tracked fixture");
        assert_eq!(
            temporary_repository_status(repository.path())
                .expect("status")
                .entries,
            vec![" M codex-autoapprover-fixture.txt"]
        );
    }

    #[test]
    fn child_deleted_tracked_file_is_detected() {
        let repository = TempDir::new().expect("temporary directory");
        initialize_temporary_repository(repository.path()).expect("create baseline");
        fs::remove_file(repository.path().join(VERIFICATION_FIXTURE)).expect("delete fixture");
        assert_eq!(
            temporary_repository_status(repository.path())
                .expect("status")
                .entries,
            vec![" D codex-autoapprover-fixture.txt"]
        );
    }

    #[test]
    fn evidence_files_are_outside_checked_repository() {
        let state = VerificationState::new().expect("temporary verification state");
        assert_ne!(state.repository_path, state.evidence.path());
        assert!(!state.audit_path.starts_with(&state.repository_path));
        assert!(
            verify_clean_baseline(&state.repository_path)
                .expect("baseline status")
                .is_clean()
        );
        state.cleanup().expect("cleanup state");
    }

    #[test]
    fn porcelain_diagnostics_are_readable_and_redacted() {
        let status = RepositoryStatus {
            entries: vec![
                "?? child-untracked.txt".into(),
                " M tracked.txt".into(),
                " D deleted.txt".into(),
            ],
        };
        let diagnostics = format_repository_diagnostics(
            "changes during Codex child session (post-run porcelain entries)",
            &status,
        );
        assert!(diagnostics.contains("?? child-untracked.txt"));
        assert!(diagnostics.contains(" M tracked.txt"));
        assert!(diagnostics.contains(" D deleted.txt"));
        assert!(!diagnostics.contains("file contents"));
        assert!(!diagnostics.contains("secret-token"));
    }

    #[test]
    fn git_status_command_failure_is_fail_closed() {
        let directory = TempDir::new().expect("temporary directory");
        let error = temporary_repository_status(directory.path()).expect_err("not a repository");
        assert!(error.to_string().contains("git status failed"));
    }

    #[test]
    fn verification_state_cleanup_removes_repository_and_evidence() {
        let state = VerificationState::new().expect("temporary verification state");
        let repository_path = state.repository_path.clone();
        let evidence_path = state.evidence.path().to_path_buf();
        state.cleanup().expect("cleanup state");
        assert!(!repository_path.exists());
        assert!(!evidence_path.exists());
    }

    #[test]
    fn verification_prompt_cannot_request_full_access() {
        assert!(!verification_prompt().contains("--yolo"));
        assert!(verification_prompt().contains("use full access"));
    }

    #[cfg(unix)]
    #[test]
    fn interrupted_verification_child_is_stopped() {
        let child = Command::new("sh")
            .args(["-c", "sleep 10"])
            .spawn()
            .expect("spawn interrupt fixture");
        let interrupted = AtomicBool::new(true);
        let error = wait_for_verification_child(child, &interrupted).expect_err("must stop child");
        assert!(error.to_string().contains("verification interrupted"));
    }

    #[cfg(unix)]
    fn run_fixture_child(path: &Path, script: &str) {
        assert!(
            Command::new("sh")
                .args(["-c", script])
                .current_dir(path)
                .status()
                .expect("run child fixture")
                .success()
        );
    }
}
