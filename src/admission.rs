//! Full launch admission and per-request revalidation.
use crate::{
    artifact::Bundle,
    certification::{Manifest, Target},
    codex,
    environment::{self, Host},
    identity::Executable,
};
use anyhow::{Context, Result, bail};
use std::{
    ffi::OsString,
    process::{Command, Stdio},
};

#[derive(Debug, Clone)]
pub struct Admission {
    pub target: Target,
    pub executable: Executable,
    bundle: Bundle,
    host: Host,
}

impl Admission {
    pub fn inspect(
        installation: &codex::Installation,
        sandbox: Option<&str>,
        sandbox_mode: Option<&str>,
        args: &[OsString],
    ) -> Result<Self> {
        let manifest = Manifest::embedded()?;
        if !manifest
            .entries
            .iter()
            .any(|entry| entry.target.codex_version == installation.version)
        {
            bail!(
                "strict compatibility policy requires a reviewed exact tuple; this version has no current certification"
            )
        }
        validate_arguments(args)?;
        let host = environment::observe()?;
        if host.surface != "native-cli" {
            bail!("unsupported execution surface: {}", host.surface)
        }
        let sandbox = sandbox.context("select an explicitly certified --sandbox-implementation; existing Codex settings are preserved in manual mode")?;
        sandbox_overrides(sandbox)?;
        require_workspace_write(sandbox_mode)?;
        let bundle = Bundle::discover(&installation.path, &installation.version)?;
        let executable = bundle.executable.clone();
        let target = Target {
            codex_version: installation.version.clone(),
            os: host.os.clone(),
            arch: host.arch.clone(),
            os_release: host.os_release.clone(),
            os_build: host.os_build.clone(),
            sandbox: sandbox.into(),
            surface: host.surface.clone(),
            protocol: crate::arming::PROTOCOL_VERSION.into(),
            tool: "Bash".into(),
            codex_binary_sha256: executable.sha256.clone(),
            codex_bundle_sha256: bundle.bundle_sha256.clone(),
            launch_kind: bundle.launch_kind.clone(),
            launch_artifact_sha256: bundle.launch_sha256.clone(),
            launch_package_sha256: bundle.launch_package_sha256.clone(),
        };
        if !manifest.admits(&target) {
            bail!("the executable, host, sandbox and protocol do not equal a certified tuple")
        }
        Ok(Self {
            target,
            executable,
            bundle,
            host,
        })
    }

    pub fn recheck(&self) -> Result<()> {
        if !Manifest::embedded()?.admits(&self.target) || environment::observe()? != self.host {
            bail!("certified host or compatibility identity changed")
        }
        self.bundle.recheck()
    }

    pub fn verify_process(&self, pid: u32) -> Result<()> {
        self.recheck()?;
        self.executable.verify_process(pid)
    }

    pub fn configure_child(&self, command: &mut Command) -> Result<()> {
        // This admission adapter covers the local foreground CLI only. Remote,
        // IDE, daemon, config/profile overrides and other subcommands are manual.
        self.bundle.configure_child(command)?;
        command.args(["--no-daemon", "-s", "workspace-write", "-a", "on-request"]);
        for setting in sandbox_overrides(&self.target.sandbox)? {
            command.arg("-c").arg(setting);
        }
        Ok(())
    }

    pub fn check_execution_health(&self) -> Result<()> {
        self.recheck()?;
        // The user explicitly selected workspace-write for the armed child.
        // Resolve project and managed configuration from the same working
        // directory. If a managed policy rejects this mode, leave it unarmed.
        let cwd = std::env::current_dir()?;
        let directory = tempfile::Builder::new()
            .prefix(".autoapprover-health-")
            .tempdir_in(&cwd)
            .context("create disposable sandbox health directory")?;
        let nonce = crate::arming::new_secret()?;
        let file = directory.path().join("autoapprover-health.txt");
        let mut command = self.executable.command();
        self.bundle.configure_child(&mut command)?;
        command
            .args([
                "sandbox",
                "-c",
                "sandbox_mode=\"workspace-write\"",
                "-c",
                "approval_policy=\"on-request\"",
            ])
            .current_dir(&cwd)
            .stdin(Stdio::null());
        for setting in sandbox_overrides(&self.target.sandbox)? {
            command.arg("-c").arg(setting);
        }
        #[cfg(target_os = "linux")]
        command
            .args([
                "--",
                "/bin/sh",
                "-c",
                "printf '%s' \"$1\" > \"$2\" && cat \"$2\"",
                "autoapprover-health",
            ])
            .arg(&nonce)
            .arg(&file);
        #[cfg(windows)]
        {
            let script = directory.path().join("health.ps1");
            std::fs::write(
                &script,
                "param([string]$Nonce, [string]$Target)\n$ErrorActionPreference = 'Stop'\n[IO.File]::WriteAllText($Target, $Nonce)\n[Console]::Write([IO.File]::ReadAllText($Target))\n",
            )?;
            command
                .args([
                    "--",
                    "powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-File",
                ])
                .arg(&script)
                .arg(&nonce)
                .arg(&file);
        }
        let output = codex::bounded_output(command).context("sandbox shell/file health probe failed; inspect `codex doctor --json` for setup diagnostics")?;
        if !output.status.success()
            || output.stdout != nonce.as_bytes()
            || std::fs::read(&file).ok().as_deref() != Some(nonce.as_bytes())
        {
            bail!(
                "sandbox could not start a shell and edit a disposable file; automatic approval remains disabled; run `codex doctor --json` for setup diagnostics"
            )
        }
        self.recheck()
    }
}

fn sandbox_overrides(sandbox: &str) -> Result<Vec<&'static str>> {
    match sandbox {
        "linux-bwrap" if cfg!(target_os = "linux") => {
            Ok(vec!["features.use_legacy_landlock=false"])
        }
        "linux-landlock" if cfg!(target_os = "linux") => {
            Ok(vec!["features.use_legacy_landlock=true"])
        }
        "windows-elevated" if cfg!(windows) => Ok(vec!["windows.sandbox=\"elevated\""]),
        "windows-unelevated" if cfg!(windows) => Ok(vec!["windows.sandbox=\"unelevated\""]),
        _ => bail!("unknown or wrong-platform sandbox implementation"),
    }
}

fn require_workspace_write(mode: Option<&str>) -> Result<()> {
    if mode != Some("workspace-write") {
        bail!(
            "select --sandbox-mode workspace-write explicitly for a certified launch; otherwise Codex uses its configured permissions in manual mode"
        )
    }
    Ok(())
}

fn validate_arguments(arguments: &[OsString]) -> Result<()> {
    let mut values = arguments.iter();
    let mut prompt_seen = false;
    while let Some(arg) = values.next() {
        let arg = arg
            .to_str()
            .context("non-Unicode launch arguments are not certified")?;
        match arg {
            "--model" | "-m" | "--image" | "-i" => {
                values.next().context("missing Codex argument value")?;
            }
            "--search" | "--no-alt-screen" => {}
            value if value.starts_with('-') => {
                bail!("this CLI option is outside the certified foreground launch surface")
            }
            "exec" | "e" | "resume" | "fork" | "app-server" | "remote" | "cloud" | "login"
            | "logout" | "sandbox" | "mcp" | "doctor" | "features" | "review" | "apply"
            | "completion" | "debug" | "update" | "help" => {
                bail!("this Codex subcommand is outside the certified foreground launch surface")
            }
            _ if !prompt_seen => {
                prompt_seen = true;
            }
            _ => bail!("ambiguous Codex launch arguments"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certification_requires_an_explicit_workspace_write_choice() {
        assert!(require_workspace_write(None).is_err());
        assert!(require_workspace_write(Some("read-only")).is_err());
        assert!(require_workspace_write(Some("danger-full-access")).is_err());
        require_workspace_write(Some("workspace-write")).expect("explicit certified mode");
    }

    #[test]
    fn forwarded_arguments_cannot_replace_certified_sandbox_or_surface() {
        for args in [
            vec!["--config", "windows.sandbox=\"unelevated\""],
            vec!["-cfeatures.use_legacy_landlock=true"],
            vec!["--profile", "alternate"],
            vec!["--yolo"],
            vec!["--cd", "/tmp"],
            vec!["app-server"],
            vec!["--enable", "feature"],
            vec!["exec", "prompt"],
        ] {
            assert!(
                validate_arguments(&args.iter().map(OsString::from).collect::<Vec<_>>()).is_err()
            );
        }
        assert!(
            validate_arguments(
                &["--model", "model", "harmless prompt"]
                    .iter()
                    .map(OsString::from)
                    .collect::<Vec<_>>()
            )
            .is_ok()
        );
    }
}
