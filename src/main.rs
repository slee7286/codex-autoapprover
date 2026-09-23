mod admission;
mod arming;
mod artifact;
mod audit;
mod broker;
mod certification;
mod child_tree;
mod cli;
mod codex;
mod compatibility;
mod configure;
mod decision;
mod environment;
mod error;
mod hook;
mod identity;
mod interrupt;
mod launcher;
mod process;
mod protocol;
mod verification_probe;

use clap::Parser;

fn main() {
    let cli = cli::Cli::parse();
    let result = match cli.command.unwrap_or(cli::Command::Run(cli::RunArgs {
        compatibility: None,
        sandbox_implementation: None,
        codex_args: Vec::new(),
    })) {
        cli::Command::Run(args) => launcher::run(&args),
        cli::Command::ConfigureWindowsSandbox { codex_home, mode } => {
            configure::run(&codex_home, &mode)
        }
        cli::Command::SupportMatrix => certification::print_support_matrix(),
        cli::Command::VerifyManifest { manifest } => certification::verify_manifest_file(&manifest),
        cli::Command::Hook => hook::run(),
        cli::Command::Diagnose => launcher::diagnose(),
        cli::Command::PrintHookConfig => launcher::print_hook_config(),
        cli::Command::VerifyLocalHook => launcher::verify_local_hook(),
    };

    match result {
        Ok(exit_code) => std::process::exit(exit_code),
        Err(error) => {
            eprintln!("codex-autoapprover: {error:#}");
            std::process::exit(1);
        }
    }
}
