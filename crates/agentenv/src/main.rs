use std::{
    fs,
    path::{Path, PathBuf},
    process,
};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "agentenv",
    about = "Declarative environments for AI coding agents",
    version = concat!("v", env!("CARGO_PKG_VERSION"))
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
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

fn main() {
    if let Err(err) = run(Cli::parse()) {
        eprintln!("error: {err:#}");
        process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::VerifyBlueprint { file } => verify_blueprint(&file),
        Commands::Freeze {
            env,
            blueprint,
            out,
        } => freeze(&env, blueprint.as_deref(), out.as_deref()),
        Commands::Reproduce { lockfile } => reproduce(&lockfile),
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
    let blueprint_path = resolve_blueprint_path(blueprint)?;
    let blueprint_yaml = read_text_file(&blueprint_path, "blueprint")?;
    let lockfile = agentenv_core::lifecycle::freeze_from_blueprint_yaml(&blueprint_yaml)
        .with_context(|| {
            format!(
                "failed to freeze blueprint `{}` for environment `{env}`",
                blueprint_path.display()
            )
        })?;

    if let Some(out_path) = out {
        fs::write(out_path, lockfile)
            .with_context(|| format!("failed to write lockfile to `{}`", out_path.display()))?;
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
    let reproduced =
        agentenv_core::lifecycle::reproduce_from_lockfile("reproduced-env", &lockfile_yaml)
            .with_context(|| format!("failed to reproduce lockfile `{}`", path.display()))?;

    println!(
        "Lockfile reproduced successfully: {} (blueprint hash {})",
        path.display(),
        reproduced.describe().blueprint_hash
    );
    Ok(())
}

fn resolve_blueprint_path(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path.to_path_buf());
    }

    let default_path = PathBuf::from("agentenv.yaml");
    if default_path.is_file() {
        return Ok(default_path);
    }

    bail!(
        "no blueprint provided. Pass `--blueprint <file>` or create `{}` in the current directory",
        default_path.display()
    );
}

fn read_text_file(path: &Path, description: &str) -> Result<String> {
    fs::read_to_string(path)
        .with_context(|| format!("failed to read {description} file `{}`", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_includes_m1_3_commands() {
        let command = Cli::command();
        let subcommands = command
            .get_subcommands()
            .map(|subcommand| subcommand.get_name().to_string())
            .collect::<Vec<_>>();

        assert_eq!(
            subcommands,
            vec![
                "verify-blueprint".to_string(),
                "freeze".to_string(),
                "reproduce".to_string(),
            ]
        );
    }
}
