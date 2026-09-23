use std::{
    env,
    fs::{self, OpenOptions},
    io::{self, BufRead, IsTerminal, Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use crate::{
    arming, audit,
    broker::{self, Broker, BrokerConfig, Session},
    child_tree::ChildTree,
    cli::{COMPATIBILITY_ENV, CompatibilityMode, RunArgs},
    codex, compatibility, interrupt, process,
    verification_probe::VerificationProbe,
};

const VERIFICATION_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const VERIFICATION_FIXTURE: &str = "codex-autoapprover-fixture.txt";
const VERIFICATION_HOOKS_DIR: &str = ".codex-autoapprover-hooks";
const VERIFICATION_COMMIT_MESSAGE: &str = "verification baseline";
const VERIFICATION_GIT_NAME: &str = "codex-autoapprover verification";
const VERIFICATION_GIT_EMAIL: &str = "codex-autoapprover-verification@localhost";
const MAX_VERIFICATION_AUTH_BYTES: u64 = 1024 * 1024;

pub fn run(args: &RunArgs) -> Result<i32> {
    let installation = codex::inspect()?;
    let launcher = env::current_exe().context("resolve current launcher executable")?;
    let cwd = env::current_dir().context("read current working directory")?;
    let compatibility_mode = resolve_compatibility_mode(args)?;
    let _compatibility_mode = compatibility_mode;
    let admission = match crate::admission::Admission::inspect(
        &installation,
        args.sandbox_implementation.as_deref(),
        &args.codex_args,
    ) {
        Ok(admission) => admission,
        Err(error) => return launch_unarmed(&installation, args, &format!("{error:#}")),
    };

    let capability = codex::detect_hook_capability(&installation, &launcher);
    if !matches!(
        capability,
        codex::HookCapability::ReviewedLiveEvidence
            | codex::HookCapability::SupportedByConfigurationProbe
    ) {
        let reason = capability
            .reason()
            .unwrap_or("the hook capability check did not pass");
        return launch_unarmed(
            &installation,
            args,
            &format!(
                "eligible version, but hook/configuration capability is {} ({reason})",
                capability.as_str()
            ),
        );
    }

    if let Err(error) = admission.check_execution_health() {
        return launch_unarmed(&installation, args, &format!("{error:#}"));
    }
    if codex::version(&admission.executable.path).ok().as_deref()
        != Some(installation.version.as_str())
    {
        return launch_unarmed(
            &installation,
            args,
            "certified executable version recheck failed",
        );
    }
    admission.recheck()?;

    let session = Session::create()?;
    let broker = Broker::start(
        &session,
        BrokerConfig {
            admission: Some(admission.clone()),
            codex_version: installation.version.clone(),
            expected_cwd: cwd,
            expected_command: None,
            expected_tool_name: None,
            audit_path: None,
        },
    )?;
    let mut command = admission.executable.command();
    admission.configure_child(&mut command)?;
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
    if let Err(error) = admission.verify_process(child.id()) {
        let _ = child.kill();
        let _ = child.wait();
        let _ = broker.shutdown();
        return Err(with_cleanup_error(error, session.cleanup()));
    }
    if let Err(error) = broker.set_codex_identity(identity) {
        let _ = child.kill();
        let _ = child.wait();
        let _ = broker.shutdown();
        let cleanup = session.cleanup();
        return Err(with_cleanup_error(error, cleanup));
    }
    eprintln!(
        "codex-autoapprover: automatic one-request approvals ARMED for this certified Codex child; press Ctrl-C to stop"
    );
    let status = wait_for_bound_child(&mut child, &broker, &interrupted.flag, None)
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

fn resolve_compatibility_mode(args: &RunArgs) -> Result<CompatibilityMode> {
    if let Some(mode) = args.compatibility {
        if mode == CompatibilityMode::Automatic {
            eprintln!("codex-autoapprover: legacy automatic policy now uses verified tuples only");
        }
        return Ok(CompatibilityMode::Strict);
    }
    match env::var(COMPATIBILITY_ENV) {
        Ok(value) if value.eq_ignore_ascii_case("automatic") => {
            eprintln!("codex-autoapprover: legacy automatic policy now uses verified tuples only");
            Ok(CompatibilityMode::Strict)
        }
        Ok(value) if value.eq_ignore_ascii_case("strict") => Ok(CompatibilityMode::Strict),
        Ok(value) => {
            bail!("invalid {COMPATIBILITY_ENV} value `{value}`; expected `automatic` or `strict`")
        }
        Err(env::VarError::NotPresent) => Ok(CompatibilityMode::Strict),
        Err(env::VarError::NotUnicode(_)) => {
            bail!("{COMPATIBILITY_ENV} is not valid Unicode; refusing to arm")
        }
    }
}

fn launch_unarmed(installation: &codex::Installation, args: &RunArgs, reason: &str) -> Result<i32> {
    eprintln!(
        "codex-autoapprover: automatic approval is DISABLED; running Codex normally ({reason})"
    );
    let mut command = codex::build_codex_command(installation);
    command
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .args(&args.codex_args);
    arming::disarm_child(&mut command);
    let status = command
        .status()
        .with_context(|| format!("launch official Codex at {}", installation.path.display()))?;
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
        "requested surface: {}",
        compatibility::Surface::LocalCliLauncher.as_str()
    );
    println!("hook protocol: {}", arming::PROTOCOL_VERSION);
    println!(
        "current process armed: {}",
        if arming::is_armed() { "yes" } else { "no" }
    );
    let configured_mode = resolve_compatibility_mode(&RunArgs {
        compatibility: None,
        sandbox_implementation: None,
        codex_args: Vec::new(),
    });
    match &configured_mode {
        Ok(mode) => println!("compatibility policy: {}", mode.as_str()),
        Err(error) => println!("compatibility policy: invalid ({error})"),
    }
    println!(
        "persistent approval hook installation: not checked; this launcher does not install hooks"
    );

    match codex::inspect() {
        Ok(installation) => {
            println!("resolved codex path: {}", installation.path.display());
            println!("installed Codex version: {}", installation.version);
            println!(
                "version probe: {}",
                if installation.version_diagnostic.is_some() {
                    "inconclusive; version is treated as unknown"
                } else {
                    "recognized stable version"
                }
            );
            println!(
                "PermissionRequest compatibility: exact certification required; historical records do not arm"
            );
            match crate::artifact::Bundle::discover(&installation.path, &installation.version) {
                Ok(bundle) => {
                    println!("native executable SHA-256: {}", bundle.executable.sha256);
                    println!("native bundle SHA-256: {}", bundle.bundle_sha256);
                    println!(
                        "Codex launch artifact: {} ({})",
                        bundle.launch_kind, bundle.launch_sha256
                    );
                    println!(
                        "Codex launch package SHA-256: {}",
                        bundle.launch_package_sha256
                    );
                }
                Err(error) => println!("native artifact identity: unavailable ({error})"),
            }
            match crate::environment::observe() {
                Ok(host) => {
                    println!("observed surface: {}", host.surface);
                    println!("native architecture: {}", host.arch);
                    println!("exact OS release: {}", host.os_release);
                    println!("exact OS build: {}", host.os_build);
                }
                Err(error) => println!("native environment identity: inconclusive ({error})"),
            }
            println!(
                "certified targets in this build: {}",
                crate::certification::Manifest::embedded()?.entries.len()
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
    crate::admission::Admission::inspect(&installation, None, &[]).context(
        "no locally verified PermissionRequest compatibility; use a certified run instead",
    )?;

    let launcher = env::current_exe().context("resolve current launcher executable")?;
    print!("{}", codex::hook_config_snippet(&launcher));
    Ok(0)
}

pub fn verify_local_hook(
    verification_auth_home: &Path,
    diagnostic_dir: Option<&Path>,
) -> Result<i32> {
    if compatibility::is_wsl_runtime() {
        bail!("verify-local-hook requires native Windows, not WSL")
    }
    if !(cfg!(target_os = "linux") || cfg!(windows)) {
        bail!("verify-local-hook is limited to eligible native Linux/Windows local-CLI targets")
    }
    if cfg!(windows) && !compatibility::is_native_windows_runtime() {
        bail!("verify-local-hook requires native Windows, not WSL or another hosted runtime")
    }
    if !io::stdin().is_terminal() {
        bail!("verify-local-hook requires an interactive terminal; no live test was started")
    }
    if crate::environment::surface()? != "native-cli" {
        bail!("verify-local-hook requires an identifiable native foreground CLI environment")
    }
    if let Some(parent) = diagnostic_dir
        && !parent.is_dir()
    {
        bail!("verification diagnostic parent must be an existing directory")
    }
    let auth_source = verification_auth_source(verification_auth_home)?;

    let installation = codex::inspect()?;
    let verification_target = compatibility::resolved_verification_target(&installation.version)
        .context("the installed Codex version is not an eligible verification target")?;
    if installation.version != verification_target.version {
        bail!(
            "verify-local-hook target changed while resolving the installed version; refusing verification"
        )
    }
    let expected_version = verification_target.version.clone();
    let probe = VerificationProbe::start()?;
    let probe_command = probe.command().to_owned();

    eprintln!();
    eprintln!("!!! LOCAL HOOK VERIFICATION EXPERIMENT !!!");
    eprintln!("This starts the official Codex executable with a child-local hook override.");
    eprintln!("Automatic approval is armed only for this verification child.");
    eprintln!(
        "The child requests file-backed auth from a temporary home containing only the separate test login."
    );
    eprintln!("No persistent Codex configuration will be written.");
    eprintln!("The only authorized action is: {}", probe_command);
    eprintln!(
        "The test prompt forbids all other commands, file changes, Git changes, installs, and full access."
    );
    eprintln!("Codex must review and trust the exact temporary hook definition before it can run.");
    eprintln!();
    eprint!(
        "Type exactly `{} ` followed by Enter to continue: ",
        confirmation_phrase(&verification_target)
    );
    io::stderr()
        .flush()
        .context("flush verification confirmation prompt")?;

    let confirmation_interrupt = interrupt::register_interrupt_flag()?;
    confirm_with_timeout(&verification_target, &confirmation_interrupt.flag)?;

    let current_version = codex::version(&installation.path)?;
    if !compatibility::verification_version_matches(&current_version, &verification_target) {
        bail!(
            "Codex version changed during verification (expected {expected_version}, found {current_version}); refusing to start"
        )
    }
    // Do not let the confirmation handler be inherited by the Codex child.
    drop(confirmation_interrupt);

    let launcher = env::current_exe().context("resolve current launcher executable")?;
    let state = VerificationState::new()?;
    if let Err(error) = stage_verification_auth(&auth_source, state.codex_home.path()) {
        let cleanup = state.cleanup();
        return Err(with_cleanup_error(error, cleanup));
    }
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
            admission: None,
            codex_version: expected_version.clone(),
            expected_cwd: repo_path.clone(),
            expected_command: Some(probe_command.clone()),
            expected_tool_name: Some(verification_target.observed_tool_type.into()),
            audit_path: Some(audit_path.clone()),
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
        .arg("--no-daemon")
        .arg("--no-alt-screen")
        .arg("-c")
        .arg(codex::hook_command_value(&launcher))
        .arg("-c")
        .arg("cli_auth_credentials_store=\"file\"")
        .arg(verification_prompt(&probe_command))
        .current_dir(&repo_path)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    isolate_verification_child_environment(&mut command, state.codex_home.path());
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
        "codex-autoapprover: launching temporary-repository verification child; do not approve any action other than the displayed curl request"
    );
    let (mut child, tree) = match ChildTree::spawn(&mut command).with_context(|| {
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
            let cleanup = cleanup_child_then_verification(&mut child, tree, state, broker, session);
            return Err(with_cleanup_error(
                anyhow::anyhow!("record exact Codex child process identity: {error}"),
                cleanup,
            ));
        }
    };
    if let Err(error) = broker.set_codex_identity(identity) {
        let cleanup = cleanup_child_then_verification(&mut child, tree, state, broker, session);
        return Err(with_cleanup_error(error, cleanup));
    }
    let interrupted = match interrupt::register_interrupt_flag() {
        Ok(value) => value,
        Err(error) => {
            let cleanup = cleanup_child_then_verification(&mut child, tree, state, broker, session);
            return Err(with_cleanup_error(error, cleanup));
        }
    };
    let status = match wait_for_bound_child(
        &mut child,
        &broker,
        &interrupted.flag,
        Some((&tree, VERIFICATION_TIMEOUT)),
    ) {
        Ok(status) => status,
        Err(error) => {
            tree.close();
            let cleanup = cleanup_bound_verification(state, broker, session);
            return Err(with_cleanup_error(error, cleanup));
        }
    };
    // The parent can exit while its shell descendants remain alive.
    let stop = tree.stop().context("stop verification descendants");
    tree.close();
    if let Err(error) = stop {
        let cleanup = cleanup_bound_verification(state, broker, session);
        return Err(with_cleanup_error(error, cleanup));
    }
    // Freeze the audit before deriving counts or retaining a copy. A late
    // client must not change the log after the diagnostic summary is made.
    broker.stop_accepting();
    if let Err(error) = broker.shutdown() {
        let cleanup = cleanup_verification_state(state, session);
        return Err(with_cleanup_error(error, cleanup));
    }
    let observation = match probe.finish() {
        Ok(observation) => observation,
        Err(error) => {
            let cleanup = cleanup_verification_state(state, session);
            return Err(with_cleanup_error(error, cleanup));
        }
    };

    let attempt_count = match audit::broker_attempt_count(&audit_path)
        .context("read temporary broker connection audit")
    {
        Ok(count) => count,
        Err(error) => {
            let cleanup = cleanup_verification_state(state, session);
            return Err(with_cleanup_error(error, cleanup));
        }
    };
    let invocation_count = match audit::invocation_count(&audit_path)
        .context("read temporary hook invocation audit")
    {
        Ok(count) => count,
        Err(error) => {
            let cleanup = cleanup_verification_state(state, session);
            return Err(with_cleanup_error(error, cleanup));
        }
    };
    let allow_count = match audit::allow_record_count(&audit_path)
        .context("read temporary redacted hook audit")
    {
        Ok(count) => count,
        Err(error) => {
            let cleanup = cleanup_verification_state(state, session);
            return Err(with_cleanup_error(error, cleanup));
        }
    };
    let expected_input = serde_json::json!({"command": probe_command});
    let exact_request_count = match audit::exact_request_count(
        &audit_path,
        verification_target.observed_tool_type,
        &expected_input,
    )
    .context("read exact redacted PermissionRequest evidence")
    {
        Ok(count) => count,
        Err(error) => {
            let cleanup = cleanup_verification_state(state, session);
            return Err(with_cleanup_error(error, cleanup));
        }
    };
    let emitted_allow_count = match audit::emitted_allow_count(
        &audit_path,
        verification_target.observed_tool_type,
        &expected_input,
    )
    .context("read structured allow emission evidence")
    {
        Ok(count) => count,
        Err(error) => {
            let cleanup = cleanup_verification_state(state, session);
            return Err(with_cleanup_error(error, cleanup));
        }
    };
    let post_status = match temporary_repository_status(&repo_path) {
        Ok(status) => status,
        Err(error) => {
            eprintln!("verification evidence: post-run repository status: unavailable");
            eprintln!("verification diagnostics: post-run Git status could not be read");
            let message = error.context("read temporary repository status after Codex exit");
            let cleanup = cleanup_verification_state(state, session);
            return Err(with_cleanup_error(message, cleanup));
        }
    };
    let repository_clean = post_status.is_clean();

    eprintln!("verification evidence: broker connection count: {attempt_count}");
    eprintln!("verification evidence: parsed hook request count: {invocation_count}");
    eprintln!(
        "verification evidence: exact authorized request hash match count: {exact_request_count}"
    );
    eprintln!("verification evidence: allowed PermissionRequest count: {allow_count}");
    eprintln!("verification evidence: structured allow emission count: {emitted_allow_count}");
    eprintln!(
        "verification evidence: exact loopback HEAD requests observed: {}",
        observation.exact_head_requests
    );
    eprintln!(
        "verification evidence: unexpected loopback requests observed: {}",
        observation.unexpected_requests
    );
    eprintln!(
        "verification evidence: exact command result via Codex child exit status: {}",
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

    let retained = diagnostic_dir.map(|parent| {
        state.retain_diagnostic(
            parent,
            &VerificationDiagnostic {
                codex_version: &expected_version,
                command: &probe_command,
                child_exit_code: codex::status_code(status),
                baseline_clean,
                repository_clean,
                attempt_count,
                invocation_count,
                exact_request_count,
                allow_count,
                emitted_allow_count,
                exact_head_requests: observation.exact_head_requests,
                unexpected_requests: observation.unexpected_requests,
            },
        )
    });
    let cleanup_result = cleanup_verification_state(state, session);
    let cleanup_completed = cleanup_result.is_ok();
    eprintln!(
        "verification evidence: temporary state cleanup completed: {}",
        if cleanup_completed { "yes" } else { "no" }
    );
    if let Some(Ok(path)) = &retained {
        eprintln!("verification diagnostic retained at: {}", path.display());
    }
    if let Some(Err(error)) = retained {
        return Err(with_cleanup_error(error, cleanup_result));
    }
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
    if attempt_count != 1
        || invocation_count != 1
        || exact_request_count != 1
        || allow_count != 1
        || emitted_allow_count != 1
        || observation.exact_head_requests != 1
        || observation.unexpected_requests != 0
    {
        bail!(
            "expected exactly one broker connection, parsed hook request, exact hook request, allow record, structured allow emission, and witnessed HEAD request, with no unexpected loopback request; recorded {attempt_count} connection(s), {invocation_count} parsed request(s), {exact_request_count} exact request(s), {allow_count} allow record(s), {emitted_allow_count} emission(s), {} witnessed request(s), and {} unexpected request(s); compatibility was not promoted",
            observation.exact_head_requests,
            observation.unexpected_requests,
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

fn confirmation_phrase(target: &compatibility::VerificationTarget) -> String {
    if target.operating_system == compatibility::OperatingSystem::Windows {
        format!("VERIFY CODEX {} WINDOWS HOOK", target.version)
    } else {
        format!("VERIFY CODEX {} HOOK", target.version)
    }
}

fn confirm_with_timeout(
    target: &compatibility::VerificationTarget,
    interrupted: &AtomicBool,
) -> Result<()> {
    let expected = confirmation_phrase(target);
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
    verification: Option<(&ChildTree, Duration)>,
) -> Result<ExitStatus> {
    let started = Instant::now();
    loop {
        if interrupted.load(Ordering::Relaxed) {
            broker.stop_accepting();
            if let Some((tree, _)) = verification {
                let cleanup = stop_verification_child(child, tree);
                return Err(with_cleanup_error(
                    anyhow::anyhow!("verification interrupted; child stopped before cleanup"),
                    cleanup,
                ));
            }
        }
        if let Some((tree, _)) = verification.filter(|(_, limit)| started.elapsed() >= *limit) {
            broker.stop_accepting();
            let cleanup = stop_verification_child(child, tree);
            return Err(with_cleanup_error(
                anyhow::anyhow!("verification timed out; child stopped before cleanup"),
                cleanup,
            ));
        }
        let status = match child.try_wait() {
            Ok(status) => status,
            Err(error) => {
                let cleanup = verification
                    .map(|(tree, _)| stop_verification_child(child, tree))
                    .unwrap_or(Ok(()));
                return Err(with_cleanup_error(
                    anyhow::Error::from(error).context("wait for Codex child"),
                    cleanup,
                ));
            }
        };
        if let Some(status) = status {
            return Ok(status);
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn stop_verification_child(child: &mut Child, tree: &ChildTree) -> Result<()> {
    tree.stop_and_reap(child)
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

fn verification_auth_source(test_home: &Path) -> Result<PathBuf> {
    let default_home = env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
        .map(|home| PathBuf::from(home).join(".codex"));
    let configured_home = env::var_os("CODEX_HOME").map(PathBuf::from);
    let live_homes: Vec<_> = [default_home, configured_home]
        .into_iter()
        .flatten()
        .collect();
    verification_auth_source_with_live(test_home, &live_homes)
}

fn verification_auth_source_with_live(test_home: &Path, live_homes: &[PathBuf]) -> Result<PathBuf> {
    if !test_home.is_absolute() {
        bail!("the separate verification authentication home must be absolute")
    }
    crate::identity::check_trusted_directory_chain(test_home)
        .context("verify separate test login home ownership and permissions")?;
    let canonical = fs::canonicalize(test_home).context("resolve separate test login home")?;
    for live_home in live_homes {
        if fs::canonicalize(live_home).is_ok_and(|path| canonical.starts_with(path)) {
            bail!("verification authentication must use a separate login, not the live Codex home")
        }
    }
    Ok(canonical.join("auth.json"))
}

fn isolate_verification_child_environment(command: &mut Command, isolated_home: &Path) {
    command
        .env("CODEX_HOME", isolated_home)
        .env("HOME", isolated_home)
        .env("USERPROFILE", isolated_home);
    for variable in [
        "CODEX_SQLITE_HOME",
        "CODEX_ACCESS_TOKEN",
        "CODEX_API_KEY",
        "OPENAI_API_KEY",
        "OPENAI_FEDERATION_RULE_ID",
        "OPENAI_IDENTITY_TOKEN_FILE",
        "OPENAI_WORKLOAD_IDENTITY_CONTEXT",
        "OPENAI_BASE_URL",
        "OPENAI_ORGANIZATION",
        "OPENAI_PROJECT",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_STATE_HOME",
        "XDG_CACHE_HOME",
        "BASH_ENV",
        "ENV",
        "ZDOTDIR",
        "PROMPT_COMMAND",
        "RUST_LOG",
    ] {
        command.env_remove(variable);
    }
}

fn stage_verification_auth(source: &Path, isolated_home: &Path) -> Result<()> {
    if !source.is_absolute() || !isolated_home.is_absolute() {
        bail!("verification authentication paths must be absolute")
    }
    let metadata = fs::symlink_metadata(source).context(
        "read file-backed Codex auth.json; keyring-only login is not supported by this diagnostic",
    )?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_VERIFICATION_AUTH_BYTES
    {
        bail!("verification auth.json must be a regular, bounded file")
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("verification auth.json must be private to its owner")
        }
    }
    crate::identity::check_trusted_directory_chain(
        source
            .parent()
            .context("auth.json has no parent directory")?,
    )
    .context("verify original Codex authentication directory")?;
    let canonical = fs::canonicalize(source).context("resolve Codex authentication file")?;
    let bound = crate::identity::BoundFile::open_limited(&canonical, MAX_VERIFICATION_AUTH_BYTES)
        .context("hold exact file-backed Codex authentication bytes")?;
    let input = fs::File::open(&canonical).context("read Codex authentication file")?;
    #[cfg(windows)]
    crate::identity::check_trusted_file_acl(&input)
        .context("verify Codex authentication file ACL")?;
    let mut bytes = Vec::with_capacity(bound.size as usize);
    input
        .take(MAX_VERIFICATION_AUTH_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("read bounded Codex authentication file")?;
    if bytes.len() as u64 != bound.size || sha256_hex(&bytes) != bound.sha256 {
        bail!("Codex authentication file changed during isolated staging")
    }
    bound
        .recheck()
        .context("recheck original Codex authentication file")?;

    crate::identity::check_trusted_directory_chain(isolated_home)
        .context("verify temporary Codex home ownership and permissions")?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut output = options
        .open(isolated_home.join("auth.json"))
        .context("create private temporary Codex authentication file")?;
    #[cfg(windows)]
    crate::identity::check_trusted_file_acl(&output)
        .context("verify temporary Codex authentication file ACL")?;
    output
        .write_all(&bytes)
        .context("copy authentication into temporary Codex home")?;
    output
        .flush()
        .context("flush temporary Codex authentication")?;
    bytes.fill(0);
    bound
        .recheck()
        .context("recheck original Codex authentication after staging")?;
    Ok(())
}

struct VerificationState {
    repository: TempDir,
    evidence: TempDir,
    codex_home: TempDir,
    repository_path: PathBuf,
    audit_path: PathBuf,
}

struct VerificationDiagnostic<'a> {
    codex_version: &'a str,
    command: &'a str,
    child_exit_code: i32,
    baseline_clean: bool,
    repository_clean: bool,
    attempt_count: usize,
    invocation_count: usize,
    exact_request_count: usize,
    allow_count: usize,
    emitted_allow_count: usize,
    exact_head_requests: usize,
    unexpected_requests: usize,
}

fn private_verification_tempdir() -> Result<TempDir> {
    let directory = TempDir::new().context("create temporary verification directory")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .context("protect temporary verification directory")?;
    }
    crate::identity::check_trusted_directory_chain(directory.path())
        .context("verify temporary verification directory ownership and permissions")?;
    Ok(directory)
}

impl VerificationState {
    fn new() -> Result<Self> {
        let repository =
            private_verification_tempdir().context("create isolated temporary repository")?;
        let evidence = match private_verification_tempdir() {
            Ok(evidence) => evidence,
            Err(error) => {
                let cleanup = repository.close();
                let creation = error.context("create temporary verification evidence directory");
                return Err(with_cleanup_error(
                    creation,
                    cleanup.map_err(anyhow::Error::from),
                ));
            }
        };
        let codex_home = match private_verification_tempdir() {
            Ok(home) => home,
            Err(error) => {
                let cleanup = combine_cleanup(
                    repository.close().map_err(anyhow::Error::from),
                    evidence.close().map_err(anyhow::Error::from),
                );
                let creation = error.context("create temporary isolated Codex home");
                return Err(with_cleanup_error(creation, cleanup));
            }
        };

        if let Err(error) = initialize_temporary_repository(repository.path()) {
            let cleanup = close_temp_dirs(repository, evidence, codex_home);
            return Err(with_cleanup_error(error, cleanup));
        }

        let audit_path = evidence.path().join("hook-audit.log");
        if let Err(error) =
            audit::initialize(&audit_path).context("initialize temporary redacted hook audit")
        {
            let cleanup = close_temp_dirs(repository, evidence, codex_home);
            return Err(with_cleanup_error(error, cleanup));
        }

        Ok(Self {
            repository_path: repository.path().to_path_buf(),
            audit_path,
            repository,
            evidence,
            codex_home,
        })
    }

    fn retain_diagnostic(
        &self,
        parent: &Path,
        diagnostic: &VerificationDiagnostic<'_>,
    ) -> Result<PathBuf> {
        let output = tempfile::Builder::new()
            .prefix("codex-autoapprover-verification-")
            .tempdir_in(parent)
            .context("create unique verification diagnostic directory")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(output.path(), fs::Permissions::from_mode(0o700))
                .context("protect verification diagnostic directory")?;
        }
        let audit = fs::read(&self.audit_path).context("read final redacted broker audit")?;
        let audit_sha256 = sha256_hex(&audit);
        fs::write(output.path().join("hook-audit.log"), audit)
            .context("retain redacted broker audit")?;
        let report = serde_json::json!({
            "schema_version": 1,
            "status": "unqualified-verification-diagnostic",
            "note": "This diagnostic is not native certification or release-gate evidence.",
            "codex_version": diagnostic.codex_version,
            "operating_system": std::env::consts::OS,
            "probe_command_sha256": sha256_hex(diagnostic.command.as_bytes()),
            "child_exit_code": diagnostic.child_exit_code,
            "baseline_clean": diagnostic.baseline_clean,
            "repository_clean": diagnostic.repository_clean,
            "broker_connections": diagnostic.attempt_count,
            "parsed_hook_requests": diagnostic.invocation_count,
            "exact_permission_requests": diagnostic.exact_request_count,
            "allowed_permission_requests": diagnostic.allow_count,
            "structured_allow_emissions": diagnostic.emitted_allow_count,
            "witnessed_exact_head_requests": diagnostic.exact_head_requests,
            "unexpected_loopback_requests": diagnostic.unexpected_requests,
            "redacted_audit": "hook-audit.log",
            "redacted_audit_sha256": audit_sha256,
        });
        let mut report_bytes =
            serde_json::to_vec_pretty(&report).context("serialize verification diagnostic")?;
        report_bytes.push(b'\n');
        fs::write(output.path().join("diagnostic.json"), report_bytes)
            .context("retain verification diagnostic")?;
        Ok(output.keep())
    }

    fn cleanup(self) -> Result<()> {
        close_temp_dirs(self.repository, self.evidence, self.codex_home)
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn close_temp_dirs(repository: TempDir, evidence: TempDir, codex_home: TempDir) -> Result<()> {
    combine_cleanup(
        combine_cleanup(
            repository
                .close()
                .context("remove temporary verification repository"),
            evidence
                .close()
                .context("remove temporary verification evidence"),
        ),
        codex_home.close().context("remove temporary Codex home"),
    )
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

fn cleanup_verification_state(state: VerificationState, session: Session) -> Result<()> {
    combine_cleanup(session.cleanup(), state.cleanup())
}

fn cleanup_child_then_verification(
    child: &mut Child,
    tree: ChildTree,
    state: VerificationState,
    broker: Broker,
    session: Session,
) -> Result<()> {
    let stop = stop_verification_child(child, &tree);
    tree.close();
    combine_cleanup(stop, cleanup_bound_verification(state, broker, session))
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

    fs::create_dir(path.join(VERIFICATION_HOOKS_DIR))
        .context("create temporary Git hooks directory")?;

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
            &format!(
                "core.hooksPath={}",
                path.join(VERIFICATION_HOOKS_DIR).display()
            ),
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
        .env("GIT_CONFIG_GLOBAL", null_device_path())
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

#[cfg(windows)]
fn null_device_path() -> &'static str {
    "NUL"
}

#[cfg(not(windows))]
fn null_device_path() -> &'static str {
    "/dev/null"
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

fn verification_prompt(command: &str) -> String {
    format!(
        "Run exactly `{command}` and do nothing else. If sandboxed network access is blocked, request approval for that exact command. Do not substitute another command. Do not create or modify files, install software, alter Git state, use full access, or perform any other action. Report completion."
    )
}

#[cfg(all(test, unix))]
fn wait_for_verification_child(
    mut child: Child,
    tree: &ChildTree,
    interrupted: &AtomicBool,
) -> Result<ExitStatus> {
    let started = Instant::now();
    loop {
        if interrupted.load(Ordering::Relaxed) {
            let cleanup = stop_verification_child(&mut child, tree);
            return Err(with_cleanup_error(
                anyhow::anyhow!(
                    "verification interrupted; child stopped and temporary state will be cleaned up"
                ),
                cleanup,
            ));
        }
        if started.elapsed() >= VERIFICATION_TIMEOUT {
            let cleanup = stop_verification_child(&mut child, tree);
            return Err(with_cleanup_error(
                anyhow::anyhow!(
                    "verification timed out; child stopped and temporary state will be cleaned up"
                ),
                cleanup,
            ));
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
        if cfg!(unix) {
            let target = compatibility::resolved_verification_target("0.151.0")
                .expect("Linux verification target");
            assert_eq!(confirmation_phrase(&target), "VERIFY CODEX 0.151.0 HOOK");
            assert!(confirmation_matches(
                "VERIFY CODEX 0.151.0 HOOK\n",
                "VERIFY CODEX 0.151.0 HOOK"
            ));
            assert!(!confirmation_matches("yes\n", "VERIFY CODEX 0.151.0 HOOK"));
        } else {
            let target = compatibility::resolved_verification_target("0.152.1")
                .expect("Windows verification target");
            assert_eq!(
                confirmation_phrase(&target),
                "VERIFY CODEX 0.152.1 WINDOWS HOOK"
            );
            assert!(confirmation_matches(
                "VERIFY CODEX 0.152.1 WINDOWS HOOK\n",
                "VERIFY CODEX 0.152.1 WINDOWS HOOK"
            ));
            assert!(!confirmation_matches(
                "yes\n",
                "VERIFY CODEX 0.152.1 WINDOWS HOOK"
            ));
        }
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
        assert_ne!(state.repository_path, state.codex_home.path());
        assert!(!state.audit_path.starts_with(&state.repository_path));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for directory in [
                state.repository.path(),
                state.evidence.path(),
                state.codex_home.path(),
            ] {
                assert_eq!(
                    fs::metadata(directory).unwrap().permissions().mode() & 0o777,
                    0o700
                );
            }
        }
        assert!(
            verify_clean_baseline(&state.repository_path)
                .expect("baseline status")
                .is_clean()
        );
        state.cleanup().expect("cleanup state");
    }

    #[test]
    fn verification_child_environment_uses_only_temporary_state() {
        let home = TempDir::new().expect("temporary home");
        let mut child = Command::new("codex");
        child
            .env("CODEX_HOME", "live-home")
            .env("CODEX_SQLITE_HOME", "live-state")
            .env("CODEX_ACCESS_TOKEN", "synthetic-token")
            .env("BASH_ENV", "live-shell-startup");
        isolate_verification_child_environment(&mut child, home.path());
        let setting = |name: &str| {
            child
                .get_envs()
                .find(|(key, _)| key == &std::ffi::OsStr::new(name))
                .map(|(_, value)| value.map(std::ffi::OsStr::to_os_string))
        };
        assert_eq!(
            setting("CODEX_HOME"),
            Some(Some(home.path().as_os_str().to_os_string()))
        );
        assert_eq!(
            setting("HOME"),
            Some(Some(home.path().as_os_str().to_os_string()))
        );
        assert_eq!(
            setting("USERPROFILE"),
            Some(Some(home.path().as_os_str().to_os_string()))
        );
        for name in ["CODEX_SQLITE_HOME", "CODEX_ACCESS_TOKEN", "BASH_ENV"] {
            assert_eq!(setting(name), Some(None), "{name} must not reach the child");
        }
    }

    #[test]
    fn verification_child_receives_only_private_file_auth_from_separate_login_home() {
        let source = private_verification_tempdir().expect("source Codex home");
        assert!(
            verification_auth_source_with_live(source.path(), &[source.path().to_path_buf()])
                .is_err()
        );
        let nested = source.path().join("nested");
        fs::create_dir(&nested).expect("nested login fixture");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&nested, fs::Permissions::from_mode(0o700))
                .expect("private nested login fixture");
        }
        assert!(
            verification_auth_source_with_live(&nested, &[source.path().to_path_buf()]).is_err()
        );
        assert_eq!(
            verification_auth_source_with_live(source.path(), &[]).expect("separate login"),
            fs::canonicalize(source.path()).unwrap().join("auth.json")
        );
        let auth = source.path().join("auth.json");
        fs::write(&auth, b"synthetic authentication fixture").expect("auth fixture");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&auth, fs::Permissions::from_mode(0o600))
                .expect("private auth fixture");
        }
        fs::write(source.path().join("config.toml"), "[hooks]\n")
            .expect("user configuration fixture");
        fs::write(source.path().join("hooks.json"), "{}").expect("user hooks fixture");
        let state = VerificationState::new().expect("temporary verification state");
        let isolated_home = state.codex_home.path().to_path_buf();
        stage_verification_auth(&auth, &isolated_home).expect("copy isolated auth");
        let entries: Vec<_> = fs::read_dir(&isolated_home)
            .expect("read isolated home")
            .map(|entry| entry.expect("isolated entry").file_name())
            .collect();
        assert_eq!(entries, vec![std::ffi::OsString::from("auth.json")]);
        assert_eq!(
            fs::read(isolated_home.join("auth.json")).expect("isolated auth"),
            b"synthetic authentication fixture"
        );
        assert!(source.path().join("config.toml").exists());
        state.cleanup().expect("remove isolated home");
        assert!(!isolated_home.exists());
    }

    #[cfg(unix)]
    #[test]
    fn verification_auth_refuses_exposed_linked_or_oversized_sources() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let source = private_verification_tempdir().expect("source Codex home");
        let isolated = private_verification_tempdir().expect("isolated Codex home");
        let auth = source.path().join("auth.json");
        fs::write(&auth, b"fixture").expect("auth fixture");
        fs::set_permissions(&auth, fs::Permissions::from_mode(0o640)).expect("expose auth fixture");
        assert!(stage_verification_auth(&auth, isolated.path()).is_err());
        fs::set_permissions(&auth, fs::Permissions::from_mode(0o600))
            .expect("protect auth fixture");
        let hardlink = source.path().join("linked-auth.json");
        fs::hard_link(&auth, &hardlink).expect("hardlink auth fixture");
        assert!(stage_verification_auth(&auth, isolated.path()).is_err());
        fs::remove_file(hardlink).expect("remove hardlink fixture");
        let link = source.path().join("alias-auth.json");
        symlink(&auth, &link).expect("symlink auth fixture");
        assert!(stage_verification_auth(&link, isolated.path()).is_err());
        fs::write(&auth, vec![b'x'; MAX_VERIFICATION_AUTH_BYTES as usize + 1])
            .expect("oversized auth fixture");
        assert!(stage_verification_auth(&auth, isolated.path()).is_err());
        assert!(!isolated.path().join("auth.json").exists());
    }

    #[test]
    fn retained_verification_diagnostic_is_redacted_and_survives_cleanup() {
        let state = VerificationState::new().expect("temporary verification state");
        let parent = TempDir::new().expect("diagnostic parent");
        let secret_command = compatibility::verification_probe_command_fixture();
        let input = serde_json::json!({"command": secret_command});
        audit::broker_attempt_at(&state.audit_path).expect("audit connection");
        audit::hook_invoked_at(&state.audit_path, Some("Bash"), Some("PermissionRequest"))
            .expect("audit invocation");
        audit::hook_request_at(
            &state.audit_path,
            Some("Bash"),
            Some("PermissionRequest"),
            Some(&input),
        )
        .expect("audit request");
        let diagnostic = VerificationDiagnostic {
            codex_version: "0.156.0",
            command: secret_command,
            child_exit_code: 0,
            baseline_clean: true,
            repository_clean: true,
            attempt_count: 1,
            invocation_count: 1,
            exact_request_count: 1,
            allow_count: 0,
            emitted_allow_count: 0,
            exact_head_requests: 0,
            unexpected_requests: 0,
        };
        let retained = state
            .retain_diagnostic(parent.path(), &diagnostic)
            .expect("retain diagnostic");
        state.cleanup().expect("cleanup temporary state");
        assert!(retained.is_dir());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&retained).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        let audit_bytes = fs::read(retained.join("hook-audit.log")).expect("retained audit");
        let report_bytes = fs::read(retained.join("diagnostic.json")).expect("retained report");
        let report: serde_json::Value =
            serde_json::from_slice(&report_bytes).expect("parse diagnostic report");
        assert_eq!(report["status"], "unqualified-verification-diagnostic");
        assert_eq!(report["redacted_audit_sha256"], sha256_hex(&audit_bytes));
        assert_eq!(
            report["probe_command_sha256"],
            sha256_hex(secret_command.as_bytes())
        );
        assert_eq!(report["broker_connections"], 1);
        assert!(!String::from_utf8_lossy(&audit_bytes).contains(secret_command));
        assert!(!String::from_utf8_lossy(&report_bytes).contains(secret_command));
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
    fn verification_state_cleanup_removes_repository_evidence_and_codex_home() {
        let state = VerificationState::new().expect("temporary verification state");
        let repository_path = state.repository_path.clone();
        let evidence_path = state.evidence.path().to_path_buf();
        let codex_home_path = state.codex_home.path().to_path_buf();
        state.cleanup().expect("cleanup state");
        assert!(!repository_path.exists());
        assert!(!evidence_path.exists());
        assert!(!codex_home_path.exists());
    }

    #[test]
    fn verification_prompt_cannot_request_full_access() {
        let prompt = verification_prompt(compatibility::verification_probe_command_fixture());
        assert!(!prompt.contains("--yolo"));
        assert!(prompt.contains("use full access"));
    }

    #[cfg(unix)]
    #[test]
    fn interrupted_verification_child_is_stopped() {
        let mut command = Command::new("sh");
        command.args(["-c", "sleep 10"]);
        let (child, tree) = ChildTree::spawn(&mut command).expect("spawn interrupt fixture");
        let interrupted = AtomicBool::new(true);
        let error =
            wait_for_verification_child(child, &tree, &interrupted).expect_err("must stop child");
        assert!(error.to_string().contains("verification interrupted"));
    }

    #[cfg(unix)]
    #[test]
    fn verification_cleanup_stops_descendants_after_parent_exits() {
        let directory = TempDir::new().expect("temporary fixture directory");
        let marker = directory.path().join("descendant-survived");
        let started = directory.path().join("descendant-started");
        let mut command = Command::new("sh");
        command
            .args([
                "-c",
                "(printf ready > \"$VERIFICATION_STARTED\"; sleep 1; printf alive > \"$VERIFICATION_MARKER\") & while [ ! -f \"$VERIFICATION_STARTED\" ]; do sleep 0.01; done",
            ])
            .env("VERIFICATION_MARKER", &marker)
            .env("VERIFICATION_STARTED", &started);
        let (mut child, tree) = ChildTree::spawn(&mut command).expect("spawn fixture group");
        assert!(child.wait().expect("wait for group leader").success());
        assert!(started.exists(), "descendant did not start");
        tree.stop().expect("stop fixture group");
        thread::sleep(Duration::from_millis(1200));
        assert!(!marker.exists(), "descendant survived verifier cleanup");
    }

    #[cfg(windows)]
    #[test]
    fn verification_cleanup_stops_windows_descendants_after_parent_exits() {
        let directory = TempDir::new().expect("temporary fixture directory");
        let marker = directory.path().join("descendant-survived");
        let started = directory.path().join("descendant-started");
        let mut command = Command::new(env::current_exe().expect("test executable"));
        command
            .args([
                "--ignored",
                "--exact",
                "launcher::tests::windows_descendant_fixture",
            ])
            .env("AA_FIXTURE_ROLE", "parent")
            .env("AA_FIXTURE_MARKER", &marker)
            .env("AA_FIXTURE_STARTED", &started)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let (mut child, tree) = ChildTree::spawn(&mut command).expect("spawn fixture job");
        assert!(child.wait().expect("wait for job leader").success());
        assert!(started.exists(), "descendant did not start");
        tree.stop().expect("stop fixture job");
        thread::sleep(Duration::from_millis(1200));
        assert!(!marker.exists(), "descendant survived verifier cleanup");
    }

    #[cfg(windows)]
    #[test]
    #[ignore]
    #[allow(clippy::zombie_processes)] // The fixture parent must exit before its descendant.
    fn windows_descendant_fixture() {
        let role = env::var("AA_FIXTURE_ROLE").expect("fixture role");
        let marker = PathBuf::from(env::var_os("AA_FIXTURE_MARKER").expect("fixture marker"));
        let started = PathBuf::from(env::var_os("AA_FIXTURE_STARTED").expect("fixture started"));
        if role == "descendant" {
            fs::write(started, b"ready").expect("mark descendant started");
            thread::sleep(Duration::from_millis(900));
            fs::write(marker, b"survived").expect("mark descendant survived");
        } else {
            assert_eq!(role, "parent");
            Command::new(env::current_exe().expect("test executable"))
                .args([
                    "--ignored",
                    "--exact",
                    "launcher::tests::windows_descendant_fixture",
                ])
                .env("AA_FIXTURE_ROLE", "descendant")
                .env("AA_FIXTURE_MARKER", &marker)
                .env("AA_FIXTURE_STARTED", &started)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn descendant fixture");
            let deadline = Instant::now() + Duration::from_secs(5);
            while !started.exists() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(10));
            }
            assert!(started.exists(), "descendant fixture did not start");
        }
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
