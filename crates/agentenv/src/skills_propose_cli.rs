use std::{
    fs,
    path::{Path, PathBuf},
};

use agentenv_core::skills::propose::{
    ProposalEmitOutput, ProposeRunInput, ProposedSkillService, SkillGeneralization,
    SkillGeneralizationRequest, SkillGeneralizer,
};
use agentenv_events::{SqliteEventStore, TraceQuery};
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use clap::Args;
use serde::Serialize;
use sha2::{Digest, Sha256};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

#[derive(Debug, Args, Clone)]
pub struct SkillsProposeArgs {
    #[arg(long)]
    pub from_traces: bool,
    #[arg(long, value_name = "FILE")]
    pub blueprint: Option<PathBuf>,
    #[arg(long, value_name = "FILE")]
    pub events_db: Option<PathBuf>,
    #[arg(long)]
    pub env: Option<String>,
    #[arg(long, default_value_t = 3)]
    pub min_occurrences: usize,
    #[arg(long, default_value_t = 0.6)]
    pub min_novelty: f32,
    #[arg(long, default_value_t = 0.8)]
    pub min_self_test_score: f32,
    #[arg(long)]
    pub llm_provider: Option<String>,
    #[arg(long, default_value = "local")]
    pub semantic_backend: String,
    #[arg(long, value_name = "DIR")]
    pub out: Option<PathBuf>,
    #[arg(long)]
    pub json: bool,
    #[arg(long)]
    pub open_pr: bool,
    #[arg(long)]
    pub repo: Option<String>,
}

#[derive(Debug, Serialize)]
struct SkillsProposeJson {
    proposals: Vec<ProposalEmitOutput>,
    warnings: Vec<String>,
}

struct FixtureGeneralizer {
    value: SkillGeneralization,
}

#[async_trait]
impl SkillGeneralizer for FixtureGeneralizer {
    async fn generalize(
        &self,
        _request: SkillGeneralizationRequest,
    ) -> Result<SkillGeneralization, agentenv_core::skills::SkillError> {
        Ok(self.value.clone())
    }
}

pub async fn run_skills_propose(args: SkillsProposeArgs) -> Result<()> {
    validate_args(&args)?;
    let blueprint = args
        .blueprint
        .as_deref()
        .context("`agentenv skills propose` requires --blueprint <path>")?;
    let blueprint_id = blueprint_id_for_path(blueprint)?;
    let events_db = args
        .events_db
        .clone()
        .unwrap_or_else(default_events_db_path);
    let store = SqliteEventStore::open(&events_db)
        .with_context(|| format!("open events database `{}`", events_db.display()))?;
    let traces = store
        .query_trace_runs(TraceQuery {
            blueprint_id: blueprint_id.clone(),
            env: args.env.clone(),
            limit: 10_000,
        })
        .with_context(|| format!("query traces from `{}`", events_db.display()))?;
    let output_root = args.out.clone().unwrap_or_else(default_proposed_dir);
    let generalizer = generalizer_for_args(&args)?;
    let created_at = now_event_ts();
    let output = ProposedSkillService::new(generalizer)
        .run(ProposeRunInput {
            traces,
            output_root,
            blueprint_id,
            min_occurrences: args.min_occurrences,
            min_novelty: args.min_novelty,
            min_self_test_score: args.min_self_test_score,
            existing_skills: Vec::new(),
            agentenv_version: env!("CARGO_PKG_VERSION").to_owned(),
            created_at,
        })
        .await
        .context("run skill proposal service")?;

    if args.json {
        let rendered = serde_json::to_string_pretty(&SkillsProposeJson {
            proposals: output.proposals,
            warnings: output.warnings,
        })
        .context("serialize skill proposal JSON")?;
        println!("{rendered}");
    } else {
        for proposal in &output.proposals {
            println!(
                "{} {} {}",
                proposal.name,
                proposal.novelty,
                proposal.path.display()
            );
        }
        for warning in &output.warnings {
            eprintln!("warning: {warning}");
        }
    }
    Ok(())
}

pub fn validate_args(args: &SkillsProposeArgs) -> Result<()> {
    if !args.from_traces {
        bail!("`agentenv skills propose` requires --from-traces");
    }
    if args.blueprint.is_none() {
        bail!("`agentenv skills propose` requires --blueprint <path>");
    }
    if args.min_occurrences < 2 {
        bail!("--min-occurrences must be at least 2");
    }
    if !(0.0..=1.0).contains(&args.min_novelty) {
        bail!("--min-novelty must be between 0.0 and 1.0");
    }
    if !(0.0..=1.0).contains(&args.min_self_test_score) {
        bail!("--min-self-test-score must be between 0.0 and 1.0");
    }
    if args.open_pr && args.repo.is_none() {
        bail!("--open-pr requires --repo owner/repo");
    }
    if let Some(repo) = &args.repo {
        validate_repo(repo)?;
    }
    Ok(())
}

fn validate_repo(repo: &str) -> Result<()> {
    let Some((owner, name)) = repo.split_once('/') else {
        bail!("--repo must be in owner/repo format");
    };
    if owner.is_empty() || name.is_empty() || name.contains('/') {
        bail!("--repo must be in owner/repo format");
    }
    if !owner.chars().all(is_repo_component_char) || !name.chars().all(is_repo_component_char) {
        bail!("--repo must be in owner/repo format");
    }
    Ok(())
}

fn is_repo_component_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.')
}

fn generalizer_for_args(args: &SkillsProposeArgs) -> Result<Box<dyn SkillGeneralizer>> {
    if args.llm_provider.as_deref() == Some("fixture") {
        let raw = std::env::var("AGENTENV_SKILL_PROPOSER_FIXTURE_JSON")
            .context("AGENTENV_SKILL_PROPOSER_FIXTURE_JSON is required for fixture provider")?;
        let value = serde_json::from_str(&raw).context("parse fixture generalization JSON")?;
        return Ok(Box::new(FixtureGeneralizer { value }));
    }
    bail!("skill proposal LLM provider is not configured")
}

fn default_events_db_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".agentenv/events.db")
}

fn default_proposed_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".agentenv/skills/proposed")
}

fn blueprint_id_for_path(path: &Path) -> Result<String> {
    let bytes = fs::read(path).with_context(|| format!("read blueprint `{}`", path.display()))?;
    let digest = Sha256::digest(&bytes);
    Ok(format!("sha256:{}", hex::encode(digest)))
}

fn now_event_ts() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
}
