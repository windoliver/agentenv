use std::{
    ffi::OsStr,
    fs,
    net::SocketAddr,
    path::{Component, Path, PathBuf},
    time::Duration,
};

use agentenv_core::{
    security::ssrf::{validate_outbound, SsrfOptions, ValidatedUrl},
    skills::{
        load_project_skills_config, load_user_skills_config, merge_skills_config,
        propose::{
            ProposalEmitOutput, ProposeRunInput, ProposeRunOutput, ProposedSkillService,
            SkillGeneralization, SkillGeneralizationRequest, SkillGeneralizer,
        },
        SkillError, SkillsConfig, SkillsConfigOverride,
    },
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
use url::Url;

const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(60);
const HTTP_ERROR_BODY_LIMIT: usize = 4096;
const LOCAL_ENDPOINTS_ENV: &str = "AGENTENV_SKILL_PROPOSER_ALLOW_LOCAL_ENDPOINTS";
const PRIVATE_ENDPOINTS_ENV: &str = "AGENTENV_SKILL_PROPOSER_ALLOW_PRIVATE_ENDPOINTS";
const HTTP_TIMEOUT_ENV: &str = "AGENTENV_SKILL_PROPOSER_HTTP_TIMEOUT_MS";

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
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pull_requests: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PullRequestPlan {
    repo: String,
    repo_root: PathBuf,
    branch: String,
    title: String,
    body: String,
}

#[derive(Debug, Clone)]
struct OpenPrContext {
    repo_root: PathBuf,
    output_root: PathBuf,
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
            let body = http_error_body(response, &self.bearer).await;
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
    let open_pr_context = if args.open_pr {
        Some(resolve_open_pr_context(args.out.as_deref())?)
    } else {
        None
    };
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
        let output = ProposeRunOutput {
            proposals: Vec::new(),
            warnings: vec![no_matching_traces_warning(
                &blueprint_id,
                args.env.as_deref(),
            )],
        };
        return finish_skills_propose(args.json, open_pr_context, args.repo.clone(), output);
    }
    let output_root = open_pr_context
        .as_ref()
        .map(|context| context.output_root.clone())
        .or_else(|| args.out.clone())
        .unwrap_or_else(default_proposed_dir);
    let generalizer = generalizer_for_args(&args, blueprint)?;
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

    finish_skills_propose(args.json, open_pr_context, args.repo.clone(), output)
}

fn finish_skills_propose(
    json: bool,
    open_pr_context: Option<OpenPrContext>,
    repo: Option<String>,
    output: ProposeRunOutput,
) -> Result<()> {
    let mut pull_requests = Vec::new();
    if let Some(context) = open_pr_context {
        let proposal = output
            .proposals
            .first()
            .context("--open-pr requested but no proposals were emitted")?;
        let repo = repo.context("--open-pr requires --repo owner/repo")?;
        let plan = pr_plan_for(repo, context.repo_root, proposal);
        pull_requests.push(publish_pr(&plan, &proposal.path)?);
    }

    print_skills_propose_output(json, output, pull_requests)
}

fn print_skills_propose_output(
    json: bool,
    output: ProposeRunOutput,
    pull_requests: Vec<String>,
) -> Result<()> {
    if json {
        let rendered = serde_json::to_string_pretty(&SkillsProposeJson {
            proposals: output.proposals,
            warnings: output.warnings,
            pull_requests,
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
        for pull_request in &pull_requests {
            println!("{pull_request}");
        }
    }
    Ok(())
}

fn pr_plan_for(repo: String, repo_root: PathBuf, proposal: &ProposalEmitOutput) -> PullRequestPlan {
    let short_name = git_ref_safe_slug(&proposal.name);
    PullRequestPlan {
        repo,
        repo_root,
        branch: format!("agentenv/proposed-skill/{short_name}"),
        title: format!("feat: propose trace-derived skill {}", proposal.name),
        body: format!(
            "Trace-derived skill proposal.\n\nNovelty: {}\nSelf-test score: {}\nPath: `{}`\n",
            proposal.novelty,
            proposal.self_test_score,
            proposal.path.display()
        ),
    }
}

fn publish_pr(plan: &PullRequestPlan, proposal_path: &Path) -> Result<String> {
    let relative_proposal_path =
        proposal_path
            .strip_prefix(&plan.repo_root)
            .with_context(|| {
                format!(
                    "proposal path `{}` is not inside git worktree `{}`",
                    proposal_path.display(),
                    plan.repo_root.display()
                )
            })?;
    run_git_command(
        &plan.repo_root,
        &[
            OsStr::new("checkout"),
            OsStr::new("-B"),
            OsStr::new(&plan.branch),
        ],
    )?;
    run_git_command(
        &plan.repo_root,
        &[
            OsStr::new("add"),
            OsStr::new("--"),
            relative_proposal_path.as_os_str(),
        ],
    )?;
    run_git_command(
        &plan.repo_root,
        &[
            OsStr::new("commit"),
            OsStr::new("-m"),
            OsStr::new(&plan.title),
        ],
    )?;
    run_git_command(
        &plan.repo_root,
        &[
            OsStr::new("push"),
            OsStr::new("-u"),
            OsStr::new("origin"),
            OsStr::new(&plan.branch),
        ],
    )?;
    let output = std::process::Command::new("gh")
        .args([
            "pr",
            "create",
            "--repo",
            &plan.repo,
            "--draft",
            "--title",
            &plan.title,
            "--body",
            &plan.body,
        ])
        .output()
        .context("run gh pr create")?;
    if !output.status.success() {
        bail!(
            "gh pr create failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn resolve_open_pr_context(out: Option<&Path>) -> Result<OpenPrContext> {
    let repo_root = git_worktree_root()?;
    let output_root = match out {
        Some(path) => {
            let absolute = absolute_path(path)?;
            if !absolute.starts_with(&repo_root) {
                bail!(
                    "--out must be inside the git worktree when --open-pr is set: `{}` is outside `{}`",
                    absolute.display(),
                    repo_root.display()
                );
            }
            absolute
        }
        None => repo_root.join(".agentenv/skills/proposed"),
    };
    Ok(OpenPrContext {
        repo_root,
        output_root,
    })
}

fn git_worktree_root() -> Result<PathBuf> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .context("run git rev-parse --show-toplevel")?;
    if !output.status.success() {
        bail!(
            "git rev-parse --show-toplevel failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let rendered = String::from_utf8(output.stdout)
        .context("git rev-parse --show-toplevel output was not UTF-8")?;
    let root = rendered.trim();
    if root.is_empty() {
        bail!("git rev-parse --show-toplevel returned an empty path");
    }
    absolute_path(Path::new(root))
}

fn run_git_command(repo_root: &Path, args: &[&OsStr]) -> Result<()> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(args)
        .output()
        .with_context(|| format!("run git -C {}", repo_root.display()))?;
    if !output.status.success() {
        bail!("git failed: {}", String::from_utf8_lossy(&output.stderr));
    }
    Ok(())
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("read current directory")?
            .join(path)
    };
    normalize_absolute_path(&absolute)
}

fn normalize_absolute_path(path: &Path) -> Result<PathBuf> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    bail!("path `{}` escapes its root", path.display());
                }
            }
            Component::Normal(part) => normalized.push(part),
        }
    }
    if !normalized.is_absolute() {
        bail!("path `{}` is not absolute", path.display());
    }
    Ok(normalized)
}

fn git_ref_safe_slug(name: &str) -> String {
    let mut slug = String::new();
    let mut previous_dash = false;
    for byte in name.bytes() {
        let lowered = byte.to_ascii_lowercase();
        if lowered.is_ascii_alphanumeric() {
            slug.push(lowered as char);
            previous_dash = false;
        } else if !previous_dash {
            slug.push('-');
            previous_dash = true;
        }
    }
    let trimmed = slug.trim_matches('-').to_owned();
    let mut slug = if trimmed.is_empty() {
        "skill".to_owned()
    } else {
        trimmed
    };
    if slug != name {
        let digest = Sha256::digest(name.as_bytes());
        let hex = hex::encode(digest);
        slug.push('-');
        slug.push_str(&hex[..8]);
    }
    while slug.ends_with('.') || slug.ends_with(".lock") || slug.ends_with('-') {
        slug.pop();
    }
    if slug.is_empty() {
        let digest = Sha256::digest(name.as_bytes());
        let hex = hex::encode(digest);
        slug = format!("skill-{}", &hex[..8]);
    }
    while slug.contains("..") {
        slug = slug.replace("..", "-");
    }
    if slug.ends_with(".lock") {
        let digest = Sha256::digest(name.as_bytes());
        let hex = hex::encode(digest);
        slug.push('-');
        slug.push_str(&hex[..8]);
    }
    if slug.ends_with('.') {
        slug.push_str("-ref");
    }
    if slug.is_empty() {
        "skill".to_owned()
    } else {
        slug
    }
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

fn generalizer_for_args(
    args: &SkillsProposeArgs,
    blueprint: &Path,
) -> Result<Box<dyn SkillGeneralizer>> {
    if args.llm_provider.as_deref() == Some("fixture") {
        let raw = std::env::var("AGENTENV_SKILL_PROPOSER_FIXTURE_JSON")
            .context("AGENTENV_SKILL_PROPOSER_FIXTURE_JSON is required for fixture provider")?;
        let value = serde_json::from_str(&raw).context("parse fixture generalization JSON")?;
        return Ok(Box::new(FixtureGeneralizer { value }));
    }

    let config = load_effective_skills_config(blueprint)?;
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
    let endpoint = validate_llm_endpoint(&llm.endpoint)?;
    let client = build_http_client(&endpoint)?;

    Ok(Box::new(HttpGeneralizer {
        endpoint: endpoint.url.to_string(),
        model: llm.model,
        bearer,
        client,
    }))
}

async fn http_error_body(mut response: reqwest::Response, bearer: &str) -> String {
    let mut body = Vec::new();
    let mut truncated = false;
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                let remaining = HTTP_ERROR_BODY_LIMIT.saturating_sub(body.len());
                if chunk.len() > remaining {
                    body.extend_from_slice(&chunk[..remaining]);
                    truncated = true;
                    break;
                }
                body.extend_from_slice(&chunk);
                if body.len() == HTTP_ERROR_BODY_LIMIT {
                    truncated = true;
                    break;
                }
            }
            Ok(None) => break,
            Err(error) => return format!("<failed to read response body: {error}>"),
        }
    }

    let mut rendered = String::from_utf8_lossy(&body).into_owned();
    if !bearer.is_empty() {
        rendered = rendered.replace(bearer, "[REDACTED]");
    }
    if truncated {
        rendered.push_str("<truncated>");
    }
    rendered
}

fn load_effective_skills_config(blueprint: &Path) -> Result<SkillsConfig> {
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

    let project = Some(
        load_project_skills_config(
            &fs::read_to_string(blueprint)
                .with_context(|| format!("read `{}`", blueprint.display()))?,
        )
        .with_context(|| format!("load project skills config `{}`", blueprint.display()))?,
    );

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

fn validate_llm_endpoint(endpoint: &str) -> Result<ValidatedUrl> {
    let url = Url::parse(endpoint).with_context(|| {
        format!(
            "skill proposal LLM endpoint `{}` is invalid",
            agentenv_core::security::ssrf::sanitize_untrusted_url_text(endpoint)
        )
    })?;
    validate_outbound(&url, skill_proposer_ssrf_options()).map_err(|error| {
        anyhow::anyhow!(
            "skill proposal LLM endpoint was blocked by SSRF policy: {}",
            error
        )
    })
}

fn skill_proposer_ssrf_options() -> SsrfOptions {
    let mut options = SsrfOptions::default();
    if env_flag_enabled(LOCAL_ENDPOINTS_ENV) {
        options.allow_loopback = true;
    }
    if env_flag_enabled(PRIVATE_ENDPOINTS_ENV) {
        options.allow_private = true;
    }
    options
}

fn build_http_client(endpoint: &ValidatedUrl) -> Result<Client> {
    let timeout = skill_proposer_http_timeout()?;
    let port = endpoint.url.port_or_known_default().unwrap_or(80);
    let addrs: Vec<SocketAddr> = endpoint
        .pinned_ips
        .iter()
        .copied()
        .map(|ip| SocketAddr::new(ip, port))
        .collect();
    Client::builder()
        .timeout(timeout)
        .connect_timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .resolve_to_addrs(&endpoint.host, &addrs)
        .build()
        .context("build skill proposal LLM HTTP client")
}

fn skill_proposer_http_timeout() -> Result<Duration> {
    match std::env::var(HTTP_TIMEOUT_ENV) {
        Ok(value) => {
            let millis = value.parse::<u64>().with_context(|| {
                format!("{HTTP_TIMEOUT_ENV} must be a positive integer number of milliseconds")
            })?;
            if millis == 0 {
                bail!("{HTTP_TIMEOUT_ENV} must be greater than 0");
            }
            Ok(Duration::from_millis(millis))
        }
        Err(std::env::VarError::NotPresent) => Ok(DEFAULT_HTTP_TIMEOUT),
        Err(error) => Err(error).context(format!("read {HTTP_TIMEOUT_ENV}")),
    }
}

fn env_flag_enabled(name: &str) -> bool {
    match std::env::var(name) {
        Ok(value) => matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"),
        Err(_) => false,
    }
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
