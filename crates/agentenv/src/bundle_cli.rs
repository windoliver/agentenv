use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use agentenv_core::bundle::{
    emit_skill_bundle, BundleSource, ReferenceDocument, SkillBundleInput, SkillBundleMetadata,
};
use agentenv_core::skills::validate_skill_name;
use anyhow::{bail, Context, Result};
use clap::Args;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

#[derive(Debug, Args)]
pub(crate) struct BundleArgs {
    pub(crate) source: String,
    #[arg(long = "as-skill")]
    pub(crate) as_skill: bool,
    #[arg(long, value_name = "DIR")]
    pub(crate) out: Option<PathBuf>,
    #[arg(long)]
    pub(crate) env: Option<String>,
    #[arg(long)]
    pub(crate) name: Option<String>,
    #[arg(long)]
    pub(crate) version: Option<String>,
    #[arg(long)]
    pub(crate) description: Option<String>,
    #[arg(long)]
    pub(crate) author: Option<String>,
    #[arg(long)]
    pub(crate) license: Option<String>,
    #[arg(long = "tag")]
    pub(crate) tags: Vec<String>,
    #[arg(long)]
    pub(crate) json: bool,
}

pub(crate) fn run_bundle(args: BundleArgs) -> Result<()> {
    if !args.as_skill {
        bail!("bundle currently supports only --as-skill");
    }
    let output_dir = args
        .out
        .clone()
        .context("bundle --as-skill requires --out <dir>")?;

    let source = resolve_source(&args)?;
    let reference_document = load_reference_document(source.project_path.as_deref())?;
    let options = crate::runtime_options(true)?;
    let frozen = agentenv_core::runtime::freeze_env_for_bundle(&options, &source.env_name)
        .with_context(|| format!("failed to freeze environment `{}`", source.env_name))?;
    let driver_artifacts = crate::discover_runtime_driver_artifacts(&options)?;

    let skill_name = args.name.clone().unwrap_or_else(|| frozen.env_name.clone());
    validate_skill_name(&skill_name)
        .with_context(|| format!("invalid skill name `{skill_name}`"))?;

    let metadata = build_metadata(&args, source.project_path.as_deref(), &skill_name)?;
    let created_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .context("failed to format bundle creation timestamp")?;

    let output = emit_skill_bundle(SkillBundleInput {
        source,
        metadata,
        blueprint_yaml: frozen.blueprint_yaml,
        lockfile_yaml: frozen.lockfile_yaml,
        reference_document,
        output_dir,
        agentenv_version: env!("CARGO_PKG_VERSION").to_owned(),
        created_at,
        driver_artifacts,
    })
    .context("failed to emit skill bundle")?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("Skill bundle written: {}", output.output_dir.display());
        println!("bundle digest: {}", output.bundle_digest);
        println!("blueprint digest: {}", output.blueprint_digest);
        println!("lockfile digest: {}", output.lockfile_digest);
    }

    Ok(())
}

fn resolve_source(args: &BundleArgs) -> Result<BundleSource> {
    let source_path = PathBuf::from(&args.source);
    let project_path = if source_path.is_dir() {
        Some(source_path.canonicalize().with_context(|| {
            format!("failed to resolve project path `{}`", source_path.display())
        })?)
    } else {
        None
    };
    let env_name = match (&args.env, &project_path) {
        (Some(env), _) => env.clone(),
        (None, Some(path)) => path
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty())
            .map(str::to_owned)
            .with_context(|| {
                format!(
                    "failed to derive environment name from project path `{}`",
                    path.display()
                )
            })?,
        (None, None) => args.source.clone(),
    };

    let (git_commit, git_dirty) = project_path
        .as_deref()
        .map(|path| (detect_git_commit(path), detect_git_dirty(path)))
        .unwrap_or((None, None));

    Ok(BundleSource {
        env_name,
        project_path,
        git_commit,
        git_dirty,
    })
}

fn build_metadata(
    args: &BundleArgs,
    project_path: Option<&Path>,
    skill_name: &str,
) -> Result<SkillBundleMetadata> {
    let version = args.version.as_deref().unwrap_or("1.0.0");
    Ok(SkillBundleMetadata {
        name: skill_name.to_owned(),
        version: version
            .parse()
            .with_context(|| format!("invalid skill version `{version}`"))?,
        description: args
            .description
            .clone()
            .unwrap_or_else(|| format!("Reproducible dev env for {skill_name}")),
        author: args
            .author
            .clone()
            .or_else(|| project_path.and_then(detect_git_author)),
        license: args
            .license
            .clone()
            .or_else(|| project_path.and_then(detect_license)),
        tags: if args.tags.is_empty() {
            vec!["dev-env".to_owned()]
        } else {
            args.tags.clone()
        },
    })
}

fn load_reference_document(project_path: Option<&Path>) -> Result<Option<ReferenceDocument>> {
    let Some(project_path) = project_path else {
        return Ok(None);
    };

    for relative in ["docs/ARCHITECTURE.md", "ARCHITECTURE.md", "README.md"] {
        let path = project_path.join(relative);
        if is_regular_file_without_following_symlinks(&path)? {
            let content = fs::read_to_string(&path).with_context(|| {
                format!("failed to read reference document `{}`", path.display())
            })?;
            return Ok(Some(ReferenceDocument {
                source_relative_path: relative.to_owned(),
                content,
            }));
        }
    }

    Ok(None)
}

fn is_regular_file_without_following_symlinks(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.file_type().is_file()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(source)
            .with_context(|| format!("failed to inspect reference document `{}`", path.display())),
    }
}

fn detect_git_author(project_path: &Path) -> Option<String> {
    git_stdout(project_path, ["config", "--local", "user.name"])
}

fn detect_git_commit(project_path: &Path) -> Option<String> {
    git_stdout(project_path, ["rev-parse", "HEAD"])
}

fn detect_git_dirty(project_path: &Path) -> Option<bool> {
    let output = Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(project_path)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    Some(!output.stdout.is_empty())
}

fn git_stdout<const N: usize>(project_path: &Path, args: [&str; N]) -> Option<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(project_path)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let value = String::from_utf8(output.stdout).ok()?.trim().to_owned();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn detect_license(project_path: &Path) -> Option<String> {
    detect_cargo_license(project_path).or_else(|| detect_license_file(project_path))
}

fn detect_cargo_license(project_path: &Path) -> Option<String> {
    let cargo_toml = fs::read_to_string(project_path.join("Cargo.toml")).ok()?;
    let value: toml::Value = toml::from_str(&cargo_toml).ok()?;
    value
        .get("package")
        .and_then(|package| package.get("license"))
        .and_then(toml::Value::as_str)
        .or_else(|| {
            value
                .get("workspace")
                .and_then(|workspace| workspace.get("package"))
                .and_then(|package| package.get("license"))
                .and_then(toml::Value::as_str)
        })
        .map(str::to_owned)
}

fn detect_license_file(project_path: &Path) -> Option<String> {
    for file_name in [
        "LICENSE-MIT",
        "LICENSE-APACHE",
        "LICENSE-APACHE-2.0",
        "LICENSE",
        "LICENSE.md",
        "LICENSE.txt",
        "COPYING",
        "COPYING.md",
        "COPYING.txt",
    ] {
        let path = project_path.join(file_name);
        if !path.is_file() {
            continue;
        }
        if let Some(license) = license_from_file_name(file_name) {
            return Some(license.to_owned());
        }
        if let Ok(contents) = fs::read_to_string(path) {
            if let Some(license) = license_from_contents(&contents) {
                return Some(license.to_owned());
            }
        }
    }
    None
}

fn license_from_file_name(file_name: &str) -> Option<&'static str> {
    match file_name {
        "LICENSE-MIT" => Some("MIT"),
        "LICENSE-APACHE" | "LICENSE-APACHE-2.0" => Some("Apache-2.0"),
        _ => None,
    }
}

fn license_from_contents(contents: &str) -> Option<&'static str> {
    if contents.contains("MIT License") {
        Some("MIT")
    } else if contents.contains("Apache License") && contents.contains("Version 2.0") {
        Some("Apache-2.0")
    } else if contents.contains("Mozilla Public License") && contents.contains("Version 2.0") {
        Some("MPL-2.0")
    } else if contents.contains("GNU GENERAL PUBLIC LICENSE") && contents.contains("Version 3") {
        Some("GPL-3.0")
    } else if contents.contains("BSD 3-Clause License") {
        Some("BSD-3-Clause")
    } else if contents.contains("BSD 2-Clause License") {
        Some("BSD-2-Clause")
    } else {
        None
    }
}
