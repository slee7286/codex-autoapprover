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
    /// Handle one Codex PermissionRequest hook invocation on stdin.
    Hook,
    /// Print non-sensitive local installation and compatibility facts.
    Diagnose,
    /// Print the hook configuration snippet without writing it.
    PrintHookConfig,
    /// Run one explicitly confirmed, isolated local hook verification.
    VerifyLocalHook,
}

#[derive(Debug, Args)]
#[command(trailing_var_arg = true)]
pub struct RunArgs {
    /// Select automatic compatibility attempts (the default) or exact reviewed tuples only.
    #[arg(long, value_enum)]
    pub compatibility: Option<CompatibilityMode>,
    /// Arguments after `--` are forwarded to Codex in their original order.
    #[arg(allow_hyphen_values = true)]
    pub codex_args: Vec<OsString>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum CompatibilityMode {
    /// Try stable versions at or above the inspected platform adapter baseline.
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
