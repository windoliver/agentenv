use std::{fmt, path::PathBuf, sync::Arc, time::Instant};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::{
    compute_bundle_digest, load_skill_manifest, load_skill_self_test_spec, AgentProduceRunner,
    SkillError,
};

pub const SKILL_CI_SCHEMA_VERSION: &str = "0.1";

#[derive(Clone)]
pub struct SkillCiRequest {
    pub candidate_path: PathBuf,
    pub registry_snapshot: Option<SkillCiRegistrySnapshot>,
    pub fail_fast: bool,
    pub agent_runner: Arc<dyn AgentProduceRunner>,
}

impl fmt::Debug for SkillCiRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SkillCiRequest")
            .field("candidate_path", &self.candidate_path)
            .field("registry_snapshot", &self.registry_snapshot)
            .field("fail_fast", &self.fail_fast)
            .field("agent_runner", &"<agent runner>")
            .finish()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SkillCiRegistrySnapshot {
    #[serde(default)]
    pub skills: Vec<SkillCiRegistrySkill>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SkillCiRegistrySkill {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub procedure_text: String,
    #[serde(default)]
    pub fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SkillCiReport {
    pub schema_version: &'static str,
    pub candidate: SkillCiCandidate,
    pub status: SkillCiStatus,
    pub tiers: Vec<SkillCiTierReport>,
    pub started_at: OffsetDateTime,
    pub completed_at: OffsetDateTime,
}

#[derive(Debug, Deserialize)]
struct SkillCiReportWire {
    schema_version: String,
    candidate: SkillCiCandidate,
    status: SkillCiStatus,
    tiers: Vec<SkillCiTierReport>,
    started_at: OffsetDateTime,
    completed_at: OffsetDateTime,
}

impl<'de> Deserialize<'de> for SkillCiReport {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = SkillCiReportWire::deserialize(deserializer)?;
        if wire.schema_version != SKILL_CI_SCHEMA_VERSION {
            return Err(serde::de::Error::custom(format!(
                "unsupported skill CI schema version `{}`",
                wire.schema_version
            )));
        }

        Ok(Self {
            schema_version: SKILL_CI_SCHEMA_VERSION,
            candidate: wire.candidate,
            status: wire.status,
            tiers: wire.tiers,
            started_at: wire.started_at,
            completed_at: wire.completed_at,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SkillCiCandidate {
    pub name: String,
    pub version: String,
    pub digest: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SkillCiStatus {
    Passed,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SkillCiTier {
    StaticLint,
    AgentReview,
    SemanticDedup,
    FunctionalRegression,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SkillCiTierStatus {
    Passed,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SkillCiTierReport {
    pub tier: SkillCiTier,
    pub status: SkillCiTierStatus,
    pub duration_ms: u128,
    pub findings: Vec<SkillCiFinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SkillCiFinding {
    pub rule_id: String,
    pub severity: SkillCiSeverity,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SkillCiSeverity {
    Error,
    Warning,
    Note,
}

pub fn run_skill_ci(request: SkillCiRequest) -> Result<SkillCiReport, SkillError> {
    let started_at = OffsetDateTime::now_utc();
    let manifest = load_skill_manifest(&request.candidate_path)?;
    let digest = compute_bundle_digest(&request.candidate_path, &manifest)?;
    let candidate = SkillCiCandidate {
        name: manifest.name.clone(),
        version: manifest.version.to_string(),
        digest,
    };

    let mut tiers = Vec::new();
    let static_report = run_tier(SkillCiTier::StaticLint, || {
        run_static_lint(&request.candidate_path)
            .map(|findings| tier_from_findings(SkillCiTier::StaticLint, findings))
    })?;
    let static_failed = static_report.status == SkillCiTierStatus::Failed;
    tiers.push(static_report);

    for tier in [
        SkillCiTier::AgentReview,
        SkillCiTier::SemanticDedup,
        SkillCiTier::FunctionalRegression,
    ] {
        if request.fail_fast && static_failed {
            tiers.push(skipped_tier(tier, "skipped because static_lint failed"));
        }
    }

    let status = if tiers
        .iter()
        .any(|tier| tier.status == SkillCiTierStatus::Failed)
    {
        SkillCiStatus::Failed
    } else if tiers
        .iter()
        .any(|tier| tier.status == SkillCiTierStatus::Skipped)
    {
        SkillCiStatus::Skipped
    } else {
        SkillCiStatus::Passed
    };

    let _ = load_skill_self_test_spec(&request.candidate_path);
    Ok(SkillCiReport {
        schema_version: SKILL_CI_SCHEMA_VERSION,
        candidate,
        status,
        tiers,
        started_at,
        completed_at: OffsetDateTime::now_utc(),
    })
}

fn run_tier<F>(tier: SkillCiTier, run: F) -> Result<SkillCiTierReport, SkillError>
where
    F: FnOnce() -> Result<SkillCiTierReport, SkillError>,
{
    let started = Instant::now();
    let mut report = run()?;
    report.tier = tier;
    report.duration_ms = started.elapsed().as_millis();
    Ok(report)
}

fn tier_from_findings(tier: SkillCiTier, findings: Vec<SkillCiFinding>) -> SkillCiTierReport {
    let status = if findings
        .iter()
        .any(|finding| finding.severity == SkillCiSeverity::Error)
    {
        SkillCiTierStatus::Failed
    } else {
        SkillCiTierStatus::Passed
    };
    SkillCiTierReport {
        tier,
        status,
        duration_ms: 0,
        findings,
        details: None,
    }
}

fn skipped_tier(tier: SkillCiTier, message: &str) -> SkillCiTierReport {
    SkillCiTierReport {
        tier,
        status: SkillCiTierStatus::Skipped,
        duration_ms: 0,
        findings: vec![SkillCiFinding {
            rule_id: "agentenv.skill.ci.skipped".to_owned(),
            severity: SkillCiSeverity::Note,
            message: message.to_owned(),
            path: None,
            line: None,
        }],
        details: None,
    }
}

fn run_static_lint(candidate_path: &std::path::Path) -> Result<Vec<SkillCiFinding>, SkillError> {
    let mut findings = Vec::new();
    let skill_md = candidate_path.join("SKILL.md");
    let content = std::fs::read_to_string(&skill_md).map_err(|source| SkillError::Io {
        path: skill_md.clone(),
        source,
    })?;
    if has_unclosed_fence(&content) {
        findings.push(SkillCiFinding {
            rule_id: "agentenv.skill.markdown.unclosed-fence".to_owned(),
            severity: SkillCiSeverity::Error,
            message: "Markdown fenced code block is not closed".to_owned(),
            path: Some(skill_md),
            line: None,
        });
    }
    Ok(findings)
}

fn has_unclosed_fence(content: &str) -> bool {
    let mut open = false;
    for line in content.lines() {
        if line.trim_start().starts_with("```") {
            open = !open;
        }
    }
    open
}
