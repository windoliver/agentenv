use std::{
    fs,
    path::{Path, PathBuf},
};

use agentenv_core::skills::{
    load_project_skills_config, load_user_skills_config, merge_skills_config,
    propose::{
        ProposalEmitOutput, ProposeRunInput, ProposeRunOutput, ProposedSkillService,
        SkillGeneralization, SkillGeneralizationRequest, SkillGeneralizer,
    },
    SkillError, SkillsConfig, SkillsConfigOverride,
};
use agentenv_credstore::{CredentialStore, CredentialStoreError};
use agentenv_events::{SqliteEventStore, TraceQuery};
use agentenv_proto::{CredentialKind, CredentialRequirement};
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use clap::Args;
use reqwest::Client;
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

struct HttpGeneralizer {
    endpoint: String,
    model: String,
    bearer: String,
    client: Client,
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

#[async_trait]
impl SkillGeneralizer for HttpGeneralizer {
    async fn generalize(
        &self,
        request: SkillGeneralizationRequest,
    ) -> Result<SkillGeneralization, SkillError> {
        let request_json =
            serde_json::to_string(&request).map_err(|source| SkillError::InvalidConfig {
                message: format!("skill proposal LLM request failed to serialize: {source}"),
            })?;
        let response = self
            .client
            .post(&self.endpoint)
            .bearer_auth(&self.bearer)
            .json(&serde_json::json!({
                "model": self.model,
                "response_format": {"type": "json_object"},
                "messages": [
                    {"role": "system", "content": "Return only JSON for an agentenv skill proposal."},
                    {"role": "user", "content": request_json}
                ]
            }))
            .send()
            .await
            .map_err(|source| SkillError::InvalidConfig {
                message: format!("skill proposal LLM request failed: {source}"),
            })?;
        let status = response.status();
        if !status.is_success() {
            let body = http_error_body(response).await;
            return Err(SkillError::InvalidConfig {
                message: format!("skill proposal LLM request failed with status {status}: {body}"),
            });
        }
        let value: serde_json::Value =
            response
                .json()
                .await
                .map_err(|source| SkillError::InvalidConfig {
                    message: format!("skill proposal LLM response was not JSON: {source}"),
                })?;
        let content = value
            .pointer("/choices/0/message/content")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| SkillError::InvalidConfig {
                message: "skill proposal LLM response missing choices[0].message.content"
                    .to_owned(),
            })?;
        serde_json::from_str(content).map_err(|source| SkillError::InvalidConfig {
            message: format!("skill proposal LLM content failed schema validation: {source}"),
        })
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
    if args.events_db.is_some() && !events_db.is_file() {
        bail!("events DB `{}` does not exist", events_db.display());
    }
    let store = SqliteEventStore::open(&events_db)
        .with_context(|| format!("open events database `{}`", events_db.display()))?;
    let traces = store
        .query_trace_runs(TraceQuery {
            blueprint_id: blueprint_id.clone(),
            env: args.env.clone(),
            limit: 10_000,
        })
        .with_context(|| format!("query traces from `{}`", events_db.display()))?;
    if traces.is_empty() {
        return print_skills_propose_output(
            args.json,
            ProposeRunOutput {
                proposals: Vec::new(),
                warnings: vec![no_matching_traces_warning(
                    &blueprint_id,
                    args.env.as_deref(),
                )],
            },
        );
    }
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

    print_skills_propose_output(args.json, output)
}

fn print_skills_propose_output(json: bool, output: ProposeRunOutput) -> Result<()> {
    if json {
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

fn no_matching_traces_warning(blueprint_id: &str, env: Option<&str>) -> String {
    match env {
        Some(env) => {
            format!("No traces matched blueprint `{blueprint_id}` and env `{env}` in the events DB")
        }
        None => format!("No traces matched blueprint `{blueprint_id}` in the events DB"),
    }
}

fn generalizer_for_args(args: &SkillsProposeArgs) -> Result<Box<dyn SkillGeneralizer>> {
    if args.llm_provider.as_deref() == Some("fixture") {
        let raw = std::env::var("AGENTENV_SKILL_PROPOSER_FIXTURE_JSON")
            .context("AGENTENV_SKILL_PROPOSER_FIXTURE_JSON is required for fixture provider")?;
        let value = serde_json::from_str(&raw).context("parse fixture generalization JSON")?;
        return Ok(Box::new(FixtureGeneralizer { value }));
    }

    let config = load_effective_skills_config()?;
    let llm = config
        .proposal
        .and_then(|proposal| proposal.llm)
        .ok_or_else(|| anyhow::anyhow!("skill proposal LLM provider is not configured"))?;
    if let Some(provider) = &args.llm_provider {
        if provider != &llm.provider {
            bail!(
                "skill proposal LLM provider `{provider}` does not match configured provider `{}`",
                llm.provider
            );
        }
    }
    if llm.provider != "openai-compatible" {
        bail!(
            "unsupported skill proposal LLM provider `{}`; expected `openai-compatible`",
            llm.provider
        );
    }
    let bearer = resolve_llm_bearer(&llm.credential)?;

    Ok(Box::new(HttpGeneralizer {
        endpoint: llm.endpoint,
        model: llm.model,
        bearer,
        client: Client::new(),
    }))
}

async fn http_error_body(response: reqwest::Response) -> String {
    match response.text().await {
        Ok(body) => body,
        Err(error) => format!("<failed to read response body: {error}>"),
    }
}

fn load_effective_skills_config() -> Result<SkillsConfig> {
    let user = match dirs::home_dir() {
        Some(home) => {
            let path = home.join(".config/agentenv/config.toml");
            if path.is_file() {
                load_user_skills_config(
                    &fs::read_to_string(&path)
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
                &fs::read_to_string(&project_path)
                    .with_context(|| format!("read `{}`", project_path.display()))?,
            )
            .with_context(|| format!("load project skills config `{}`", project_path.display()))?,
        )
    } else {
        None
    };

    merge_skills_config(user, project, SkillsConfigOverride { registry: None })
        .context("merge skills config")
}

fn resolve_llm_bearer(name: &str) -> Result<String> {
    let store = CredentialStore::from_default_paths().context("initialize credential store")?;
    let requirement = CredentialRequirement {
        name: name.to_owned(),
        kind: CredentialKind::ApiKey,
        required: true,
        description: "skill proposal LLM bearer token".to_owned(),
        validator: None,
    };
    store
        .resolve(name, &requirement)
        .map(|secret| secret.expose_secret().to_owned())
        .map_err(|error| match error {
            CredentialStoreError::MissingCredential { .. } => {
                anyhow::anyhow!("skill proposal LLM credential `{name}` is not configured")
            }
            error => anyhow::anyhow!("resolve skill proposal LLM credential `{name}`: {error}"),
        })
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
