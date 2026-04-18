use clap::{CommandFactory, Parser};

#[derive(Debug, Parser)]
#[command(
    name = "agentenv",
    about = "Declarative environments for AI coding agents"
)]
struct Cli;

fn main() {
    let mut command = Cli::command();
    command = command.version(concat!("v", env!("CARGO_PKG_VERSION")));
    let _ = command.get_matches();
}
