use agentenv_credstore::{CredentialStore, SecretString};
use anyhow::{bail, Context, Result};
use clap::{Args, CommandFactory, Parser, Subcommand};
use tracing_subscriber::EnvFilter;

const SELF_ENV_SENTINEL: &str = "__self__";

#[derive(Debug, Parser)]
#[command(
    name = "agentenv",
    about = "Declarative environments for AI coding agents",
    version = concat!("v", env!("CARGO_PKG_VERSION"))
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Credentials(CredentialsArgs),
}

#[derive(Debug, Args)]
struct CredentialsArgs {
    #[command(subcommand)]
    command: CredentialCommand,
}

#[derive(Debug, Subcommand)]
enum CredentialCommand {
    /// Lists credential names only.
    List,
    /// Removes a credential from storage.
    Reset {
        /// Credential name, for example ANTHROPIC_API_KEY.
        name: String,
    },
    /// Stores a credential value (interactive by default).
    Set {
        /// Credential name, for example ANTHROPIC_API_KEY.
        name: String,
        /// Read the value from an environment variable.
        /// When omitted: prompts interactively.
        /// When passed without a value: uses <name> as the environment variable.
        #[arg(
            long,
            num_args = 0..=1,
            default_missing_value = SELF_ENV_SENTINEL,
            value_name = "ENV_VAR"
        )]
        from_env: Option<String>,
    },
    /// Reports which backend currently resolves a credential.
    Where {
        /// Credential name, for example ANTHROPIC_API_KEY.
        name: String,
    },
}

fn main() {
    init_tracing();
    if let Err(error) = run() {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .with_target(false)
        .with_writer(std::io::stderr)
        .try_init();
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Some(Commands::Credentials(command)) => run_credentials(command),
        None => {
            let mut command = Cli::command();
            command.print_help().context("print help output")?;
            println!();
            Ok(())
        }
    }
}

fn run_credentials(args: CredentialsArgs) -> Result<()> {
    let mut store = CredentialStore::from_default_paths().context("initialize credential store")?;
    for warning in store.startup_warnings() {
        eprintln!("warning: {warning}");
    }

    match args.command {
        CredentialCommand::List => {
            for name in store.list().context("list credentials")? {
                println!("{name}");
            }
            Ok(())
        }
        CredentialCommand::Reset { name } => {
            store
                .remove(&name)
                .with_context(|| format!("reset credential `{name}`"))?;
            println!("{name}");
            Ok(())
        }
        CredentialCommand::Set { name, from_env } => {
            if let Some(env_name) = from_env {
                let source_env = if env_name == SELF_ENV_SENTINEL {
                    name.clone()
                } else {
                    env_name
                };
                store.store_from_env(&name, &source_env).with_context(|| {
                    format!("store credential `{name}` from env `{source_env}`")
                })?;
            } else {
                let prompt = format!("Enter value for `{name}`: ");
                let value = rpassword::prompt_password(prompt)
                    .with_context(|| format!("prompt for credential `{name}`"))?;
                store
                    .store(&name, &SecretString::new(value))
                    .with_context(|| format!("store credential `{name}`"))?;
            }
            println!("{name}");
            Ok(())
        }
        CredentialCommand::Where { name } => match store
            .where_is(&name)
            .with_context(|| format!("lookup credential `{name}`"))?
        {
            Some(backend) => {
                println!("{backend}");
                Ok(())
            }
            None => bail!("credential `{name}` not found"),
        },
    }
}
