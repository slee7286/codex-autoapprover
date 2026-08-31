use std::ffi::OsString;

use clap::{Args, Parser, Subcommand};

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
    /// Arguments after `--` are forwarded to Codex in their original order.
    #[arg(allow_hyphen_values = true)]
    pub codex_args: Vec<OsString>,
}
