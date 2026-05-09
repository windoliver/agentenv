use std::{path::PathBuf, sync::Arc};

use agentenv_core::skills::{
    execute_skill_prune, load_project_skills_config, load_skill_trust_keys,
    load_user_skills_config, merge_skills_config, plan_skill_prune, rebuild_skill_index,
    verify_all_installed_skills, InstalledSkill, InstalledSkillSelector, SkillAddRequest,
    SkillCacheLayout, SkillError, SkillPublishRequest, SkillSearchHit, SkillService,
    SkillVerifyOptions, SkillVerifyStatus, SkillsConfig, SkillsConfigOverride,
};
use agentenv_credstore::{CredentialStore, CredentialStoreError};
use agentenv_proto::{CredentialKind, CredentialRequirement};
use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use serde::Serialize;

#[derive(Debug, Args)]
pub struct SkillsArgs {
    #[command(subcommand)]
    pub command: SkillsCommand,
}

#[derive(Debug, Subcommand)]
pub enum SkillsCommand {
    Search(SkillsSearchArgs),
    Add(SkillsAddArgs),
    Install(SkillsInstallArgs),
    List(SkillsListArgs),
    Info(SkillsInfoArgs),
    Remove(SkillsRemoveArgs),
    Publish(SkillsPublishArgs),
    Verify(SkillsVerifyArgs),
    Prune(SkillsPruneArgs),
}

#[derive(Debug, Args)]
pub struct SkillsSearchArgs {
    pub query: String,
    #[arg(long)]
    pub registry: Option<String>,
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct SkillsAddArgs {
    pub handle: String,
    #[arg(long)]
    pub registry: Option<String>,
    #[arg(long)]
    pub allow_unsigned: bool,
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct SkillsInstallArgs {
    #[arg(long = "from", value_name = "PATH")]
    pub from: PathBuf,
    #[arg(long)]
    pub allow_unsigned: bool,
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct SkillsListArgs {
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct SkillsInfoArgs {
    pub name: String,
    #[arg(long)]
    pub version: Option<String>,
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct SkillsRemoveArgs {
    pub name: String,
    #[arg(long)]
    pub version: Option<String>,
    #[arg(long)]
    pub yes: bool,
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct SkillsPublishArgs {
    pub path: PathBuf,
    #[arg(long)]
    pub registry: Option<String>,
    #[arg(long)]
    pub allow_unsigned: bool,
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct SkillsVerifyArgs {
    pub name: Option<String>,
    #[arg(long)]
    pub version: Option<String>,
    #[arg(long)]
    pub all: bool,
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct SkillsPruneArgs {
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Serialize)]
struct SkillsListJson {
    skills: Vec<InstalledSkill>,
}

#[derive(Debug, Serialize)]
struct SkillsSearchJson {
    skills: Vec<SkillSearchHit>,
}

pub async fn run_skills(args: SkillsArgs) -> Result<()> {
    let home = dirs::home_dir().context("home directory is unavailable")?;
    let root = home.join(".agentenv");
    let registry_override = registry_override_for_command(&args.command);
    let config = load_effective_config(registry_override)?;
    let service = SkillService::new(root.clone(), config)
        .with_credential_resolver(Arc::new(resolve_skill_credential));
    dispatch(args.command, service, root).await
}

async fn dispatch(command: SkillsCommand, service: SkillService, root: PathBuf) -> Result<()> {
    match command {
        SkillsCommand::Search(args) => {
            let hits = service.search(&args.query).await?;
            if args.json {
                print_json(&SkillsSearchJson { skills: hits })
            } else {
                print_search_hits(&hits);
                Ok(())
            }
        }
        SkillsCommand::Add(args) => {
            let installed = service
                .add(SkillAddRequest {
                    handle: args.handle,
                    registry: None,
                    allow_unsigned: args.allow_unsigned,
                })
                .await?;
            print_installed_result(&installed, args.json)
        }
        SkillsCommand::Install(args) => {
            let installed = service.install_from_path(
                &args.from,
                args.allow_unsigned,
                format!("local:{}", args.from.display()),
            )?;
            print_installed_result(&installed, args.json)
        }
        SkillsCommand::List(args) => {
            let skills = service.list()?;
            if args.json {
                print_json(&SkillsListJson { skills })
            } else {
                print_installed_table(&skills);
                Ok(())
            }
        }
        SkillsCommand::Info(args) => {
            let installed = service.info(selector(args.name, args.version))?;
            if args.json {
                print_json(&installed)
            } else {
                print_installed_info(&installed);
                Ok(())
            }
        }
        SkillsCommand::Remove(args) => {
            if !args.yes {
                bail!("refusing to remove a skill without --yes");
            }
            let removed = service.remove(selector(args.name, args.version))?;
            print_installed_result(&removed, args.json)
        }
        SkillsCommand::Publish(args) => {
            let hit = service
                .publish(SkillPublishRequest {
                    bundle_path: args.path,
                    registry: None,
                    allow_unsigned: args.allow_unsigned,
                })
                .await?;
            if args.json {
                print_json(&hit)
            } else {
                println!(
                    "{} {} {}",
                    hit.name,
                    hit.version,
                    hit.digest.as_deref().unwrap_or("unknown")
                );
                Ok(())
            }
        }
        SkillsCommand::Verify(args) => {
            if args.all {
                run_verify_all(&root, args.json)
            } else {
                let name = args.name.ok_or_else(|| {
                    anyhow::anyhow!("`agentenv skills verify` requires a skill name or `--all`")
                })?;
                let installed = service.verify(selector(name, args.version))?;
                print_installed_result(&installed, args.json)
            }
        }
        SkillsCommand::Prune(args) => run_prune(&root, args),
    }
}

fn registry_override_for_command(command: &SkillsCommand) -> Option<String> {
    match command {
        SkillsCommand::Search(args) => args.registry.clone(),
        SkillsCommand::Add(args) => args.registry.clone(),
        SkillsCommand::Publish(args) => args.registry.clone(),
        SkillsCommand::Install(_)
        | SkillsCommand::List(_)
        | SkillsCommand::Info(_)
        | SkillsCommand::Remove(_)
        | SkillsCommand::Verify(_)
        | SkillsCommand::Prune(_) => None,
    }
}

fn run_verify_all(root: &std::path::Path, json: bool) -> Result<()> {
    if json {
        bail!("`agentenv skills verify --all --json` is not supported yet");
    }

    let layout = SkillCacheLayout::new(root);
    let trust_keys = load_skill_trust_keys(&layout).context("failed to load skill trust keys")?;
    let report = verify_all_installed_skills(
        &layout,
        SkillVerifyOptions {
            trust_keys,
            ..Default::default()
        },
    )
    .context("failed to verify installed skills")?;

    for skill in &report.skills {
        match skill.status {
            SkillVerifyStatus::Passed => {
                println!("verified {} {}", skill.name, skill.version);
            }
            SkillVerifyStatus::Failed => {
                eprintln!("failed {} {}", skill.name, skill.version);
                for error in &skill.errors {
                    eprintln!("  error: {error}");
                }
            }
        }
        for warning in &skill.warnings {
            eprintln!("  warning: {warning}");
        }
    }

    if !report.is_ok() {
        bail!("skill verification failed");
    }
    Ok(())
}

fn run_prune(root: &std::path::Path, args: SkillsPruneArgs) -> Result<()> {
    let layout = SkillCacheLayout::new(root);
    let plan = plan_skill_prune(&layout).context("failed to plan skill prune")?;

    if args.dry_run {
        for path in &plan.removed_archives {
            println!("would remove {}", path.display());
        }
        println!(
            "{} archive(s) would be removed",
            plan.removed_archives.len()
        );
        return Ok(());
    }

    execute_skill_prune(&plan).context("failed to prune skill cache")?;
    rebuild_skill_index(&layout).context("failed to rebuild skill index")?;
    println!("removed {} archive(s)", plan.removed_archives.len());
    Ok(())
}

fn load_effective_config(registry_override: Option<String>) -> Result<SkillsConfig> {
    let user = match dirs::home_dir() {
        Some(home) => {
            let path = home.join(".config/agentenv/config.toml");
            if path.is_file() {
                load_user_skills_config(
                    &std::fs::read_to_string(&path)
                        .with_context(|| format!("read `{}`", path.display()))?,
                )
                .with_context(|| format!("load skills config `{}`", path.display()))?
            } else {
                SkillsConfig::default()
            }
        }
        None => SkillsConfig::default(),
    };

    let project_path = std::env::current_dir()
        .context("read current directory")?
        .join("agentenv.yaml");
    let project = if project_path.is_file() {
        Some(
            load_project_skills_config(
                &std::fs::read_to_string(&project_path)
                    .with_context(|| format!("read `{}`", project_path.display()))?,
            )
            .with_context(|| format!("load project skills config `{}`", project_path.display()))?,
        )
    } else {
        None
    };

    merge_skills_config(
        user,
        project,
        SkillsConfigOverride {
            registry: registry_override,
        },
    )
    .context("merge skills config")
}

fn resolve_skill_credential(name: &str) -> std::result::Result<Option<String>, SkillError> {
    let store =
        CredentialStore::from_default_paths().map_err(|error| SkillError::InvalidConfig {
            message: format!("initialize credential store: {error}"),
        })?;
    let requirement = CredentialRequirement {
        name: name.to_owned(),
        kind: CredentialKind::ApiKey,
        required: false,
        description: "skill registry bearer token".to_owned(),
        validator: None,
    };
    match store.resolve(name, &requirement) {
        Ok(secret) => Ok(Some(secret.expose_secret().to_owned())),
        Err(CredentialStoreError::MissingCredential { .. }) => Ok(None),
        Err(error) => Err(SkillError::InvalidConfig {
            message: format!("resolve credential `{name}`: {error}"),
        }),
    }
}

fn selector(name: String, version: Option<String>) -> InstalledSkillSelector {
    match version {
        Some(version) => InstalledSkillSelector::NameVersion { name, version },
        None => InstalledSkillSelector::Name(name),
    }
}

fn print_json<T: Serialize>(value: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn print_installed_result(installed: &InstalledSkill, json: bool) -> Result<()> {
    if json {
        print_json(installed)
    } else {
        println!(
            "{} {} {}",
            installed.name, installed.version, installed.digest
        );
        Ok(())
    }
}

fn print_search_hits(hits: &[SkillSearchHit]) {
    println!("NAME VERSION REGISTRY DIGEST");
    for hit in hits {
        println!(
            "{} {} {} {}",
            hit.name,
            hit.version,
            hit.registry,
            hit.digest.as_deref().unwrap_or("unknown")
        );
    }
}

fn print_installed_table(skills: &[InstalledSkill]) {
    println!("NAME VERSION SOURCE DIGEST");
    for skill in skills {
        println!(
            "{} {} {} {}",
            skill.name, skill.version, skill.source_type, skill.digest
        );
    }
}

fn print_installed_info(installed: &InstalledSkill) {
    println!("name: {}", installed.name);
    println!("version: {}", installed.version);
    println!("source_type: {}", installed.source_type);
    println!("source_label: {}", installed.source_label);
    println!("digest: {}", installed.digest);
    println!("signature_status: {}", installed.signature_status);
    println!("entry: {}", installed.entry.display());
    println!("installed_at: {}", installed.installed_at);
    println!("path: {}", installed.path.display());
}
