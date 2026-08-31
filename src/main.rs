mod arming;
mod audit;
mod cli;
mod codex;
mod compatibility;
mod decision;
mod error;
mod hook;
mod launcher;
mod protocol;

use clap::Parser;

fn main() {
    let cli = cli::Cli::parse();
    let result = match cli.command.unwrap_or(cli::Command::Run(cli::RunArgs {
        codex_args: Vec::new(),
    })) {
        cli::Command::Run(args) => launcher::run(&args),
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
