use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::Args;

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

pub async fn run_skills_propose(args: SkillsProposeArgs) -> Result<()> {
    validate_args(&args)?;
    println!("no proposals emitted");
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
    Ok(())
}
