use std::{
    fs,
    path::{Path, PathBuf},
    process,
};

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
    VerifyBlueprint {
        file: PathBuf,
    },
    Freeze {
        env: String,
        #[arg(long, value_name = "FILE")]
        blueprint: Option<PathBuf>,
        #[arg(long, value_name = "PATH")]
        out: Option<PathBuf>,
    },
    Reproduce {
        lockfile: PathBuf,
    },
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
        process::exit(1);
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
        Some(Commands::VerifyBlueprint { file }) => verify_blueprint(&file),
        Some(Commands::Freeze {
            env,
            blueprint,
            out,
        }) => freeze(&env, blueprint.as_deref(), out.as_deref()),
        Some(Commands::Reproduce { lockfile }) => reproduce(&lockfile),
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

fn verify_blueprint(path: &Path) -> Result<()> {
    let blueprint_yaml = read_text_file(path, "blueprint")?;
    agentenv_core::lifecycle::verify_blueprint_yaml(&blueprint_yaml)
        .with_context(|| format!("failed to verify blueprint `{}`", path.display()))?;

    println!("Blueprint verified: {}", path.display());
    Ok(())
}

fn freeze(env: &str, blueprint: Option<&Path>, out: Option<&Path>) -> Result<()> {
    let cwd = std::env::current_dir().context("failed to determine current working directory")?;
    let lockfile = freeze_in_dir(env, blueprint, out, &cwd)?;

    if let Some(out_path) = out {
        println!(
            "Lockfile written for environment `{env}`: {}",
            out_path.display()
        );
        return Ok(());
    }

    print!("{lockfile}");
    Ok(())
}

fn reproduce(path: &Path) -> Result<()> {
    let lockfile_yaml = read_text_file(path, "lockfile")?;
    let env_name = derive_reproduced_env_name(path);
    let reproduced =
        agentenv_core::lifecycle::reproduce_from_lockfile(&env_name, &lockfile_yaml)
            .with_context(|| format!("failed to reproduce lockfile `{}`", path.display()))?;

    println!(
        "Lockfile reproduced successfully for environment `{env_name}`: {} (blueprint hash {})",
        path.display(),
        reproduced.describe().blueprint_hash
    );
    Ok(())
}

fn resolve_blueprint_path_in_dir(explicit: Option<&Path>, cwd: &Path) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path.to_path_buf());
    }

    let default_path = cwd.join("agentenv.yaml");
    if default_path.is_file() {
        return Ok(default_path);
    }

    bail!(
        "no blueprint provided. Pass `--blueprint <file>` or create `{}` in the current directory",
        default_path.display()
    );
}

fn freeze_in_dir(
    env: &str,
    blueprint: Option<&Path>,
    out: Option<&Path>,
    cwd: &Path,
) -> Result<String> {
    let blueprint_path = resolve_blueprint_path_in_dir(blueprint, cwd)?;
    let blueprint_yaml = read_text_file(&blueprint_path, "blueprint")?;
    let env_state = agentenv_core::lifecycle::create_from_blueprint_yaml(env, &blueprint_yaml)
        .with_context(|| {
            format!(
                "failed to create environment `{env}` from blueprint `{}`",
                blueprint_path.display()
            )
        })?;
    let lockfile = agentenv_core::lifecycle::freeze_env(&env_state)
        .with_context(|| format!("failed to freeze environment `{env}`"))?;

    if let Some(out_path) = out {
        fs::write(out_path, &lockfile)
            .with_context(|| format!("failed to write lockfile to `{}`", out_path.display()))?;
    }

    Ok(lockfile)
}

fn derive_reproduced_env_name(path: &Path) -> String {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    for suffix in [".lock.yaml", ".lock.yml", ".yaml", ".yml", ".lock"] {
        if let Some(stripped) = file_name.strip_suffix(suffix) {
            if !stripped.is_empty() {
                return stripped.to_string();
            }
        }
    }

    path.file_stem()
        .and_then(|stem| stem.to_str())
        .filter(|stem| !stem.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| "reproduced-env".to_string())
}

fn read_text_file(path: &Path, description: &str) -> Result<String> {
    fs::read_to_string(path)
        .with_context(|| format!("failed to read {description} file `{}`", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentenv_core::lockfile::Lockfile;
    use std::{
        env,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn cli_includes_commands() {
        let command = Cli::command();
        let subcommands = command
            .get_subcommands()
            .map(|subcommand| subcommand.get_name().to_string())
            .collect::<Vec<_>>();

        assert_eq!(
            subcommands,
            vec![
                "credentials".to_string(),
                "verify-blueprint".to_string(),
                "freeze".to_string(),
                "reproduce".to_string(),
            ]
        );
    }

    #[test]
    fn freeze_default_path_failure_when_blueprint_missing() {
        let temp_dir = make_temp_dir("freeze-missing-blueprint");

        let err = freeze_in_dir("demo", None, None, &temp_dir).unwrap_err();

        assert!(
            err.to_string().contains("no blueprint provided"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn freeze_success_with_blueprint_writes_lockfile() {
        let temp_dir = make_temp_dir("freeze-success");
        let out_path = temp_dir.join("demo.lock.yaml");

        freeze_in_dir(
            "demo",
            Some(&fixture_blueprint()),
            Some(&out_path),
            &temp_dir,
        )
        .unwrap();

        let rendered = fs::read_to_string(&out_path).unwrap();
        let lockfile = Lockfile::from_yaml(&rendered).unwrap();
        assert_eq!(rendered, lockfile.to_yaml_deterministic().unwrap());

        assert_eq!(lockfile.version, "0.1.0");
        assert_eq!(lockfile.protocol_version, "0.1");
        assert!(!lockfile.blueprint_hash.is_empty());
    }

    #[test]
    fn reproduce_success_from_generated_lockfile() {
        let temp_dir = make_temp_dir("reproduce-success");
        let out_path = temp_dir.join("demo.lock.yaml");

        freeze_in_dir(
            "demo",
            Some(&fixture_blueprint()),
            Some(&out_path),
            &temp_dir,
        )
        .unwrap();

        reproduce(&out_path).unwrap();
    }

    #[test]
    fn reproduce_env_name_comes_from_lockfile_path() {
        assert_eq!(
            derive_reproduced_env_name(Path::new("/tmp/demo.lock.yaml")),
            "demo"
        );
        assert_eq!(
            derive_reproduced_env_name(Path::new("/tmp/agentenv.lock")),
            "agentenv"
        );
    }

    fn fixture_blueprint() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../blueprints/claude+filesystem+openshell.yaml")
    }

    fn make_temp_dir(prefix: &str) -> PathBuf {
        let unique = format!(
            "{prefix}-{}-{}",
            process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let path = env::temp_dir().join(unique);
        fs::create_dir_all(&path).unwrap();
        path
    }
}
