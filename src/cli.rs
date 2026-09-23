use std::ffi::OsString;

use clap::{Args, Parser, Subcommand, ValueEnum};

pub const COMPATIBILITY_ENV: &str = "CODEX_AUTOAPPROVER_COMPATIBILITY";

#[derive(Debug, Parser)]
#[command(
    name = "codex-autoapprover",
    version,
    about = "Run the official Codex CLI with an opt-in PermissionRequest hook"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the existing official Codex executable.
    Run(RunArgs),
    /// Print the embedded exact compatibility manifest as JSON.
    SupportMatrix,
    /// Verify an installer's manifest exactly equals the immutable embedded manifest.
    VerifyManifest {
        #[arg(long)]
        manifest: std::path::PathBuf,
    },
    /// Explicitly change Windows sandbox configuration with a backup.
    ConfigureWindowsSandbox {
        #[arg(long)]
        codex_home: std::path::PathBuf,
        #[arg(long, value_parser = ["elevated", "unelevated"])]
        mode: String,
    },
    /// Handle one Codex PermissionRequest hook invocation on stdin.
    Hook,
    /// Print non-sensitive local installation and compatibility facts.
    Diagnose,
    /// Print the hook configuration snippet without writing it.
    PrintHookConfig,
    /// Run one explicitly confirmed local hook diagnostic.
    VerifyLocalHook {
        /// Existing directory in which to retain an unqualified redacted diagnostic.
        #[arg(long)]
        diagnostic_dir: Option<std::path::PathBuf>,
    },
}

#[derive(Debug, Args)]
#[command(trailing_var_arg = true)]
pub struct RunArgs {
    /// Explicit sandbox selection for a certified foreground launch; otherwise use ordinary Codex.
    #[arg(long, value_parser = ["linux-bwrap", "linux-landlock", "windows-elevated", "windows-unelevated"])]
    pub sandbox_implementation: Option<String>,
    /// Only reviewed exact tuples may arm. The legacy automatic value is an alias for strict.
    #[arg(long, value_enum)]
    pub compatibility: Option<CompatibilityMode>,
    /// Arguments after `--` are forwarded to Codex in their original order.
    #[arg(allow_hyphen_values = true)]
    pub codex_args: Vec<OsString>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum CompatibilityMode {
    /// Deprecated alias for strict; never enables an unverified release.
    Automatic,
    /// Arm automatic approval only for reviewed exact compatibility entries.
    Strict,
}

impl CompatibilityMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Automatic => "automatic",
            Self::Strict => "strict",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compatibility_option_stops_at_the_codex_separator() {
        let cli = Cli::try_parse_from([
            "codex-autoapprover",
            "run",
            "--compatibility",
            "strict",
            "--",
            "--compatibility",
            "automatic",
        ])
        .expect("parse separated arguments");
        let Some(Command::Run(args)) = cli.command else {
            panic!("expected run command")
        };
        assert_eq!(args.compatibility, Some(CompatibilityMode::Strict));
        assert_eq!(
            args.codex_args,
            vec![
                OsString::from("--compatibility"),
                OsString::from("automatic")
            ]
        );
    }
}
