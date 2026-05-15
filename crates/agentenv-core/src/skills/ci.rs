use std::{
    collections::BTreeSet,
    fmt,
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use serde_yaml::Value as YamlValue;
use time::OffsetDateTime;

use super::{
    compute_bundle_digest, load_skill_manifest, load_skill_self_test_spec,
    manifest::{normalize_bundle_path, validated_bundle_file},
    AgentProduceRunner, SkillError, SkillManifest,
};

pub const SKILL_CI_SCHEMA_VERSION: &str = "0.1";
const SECRET_REDACTION: &str = "[REDACTED]";
const SECRET_PREFIX_PATTERNS: &[(&str, usize)] = &[
    ("sk-", 20),
    ("ghp_", 20),
    ("github_pat_", 20),
    ("xoxb-", 20),
    ("xoxp-", 20),
    ("AKIA", 16),
];
const SECRET_KEYWORDS: &[&str] = &[
    "api_key",
    "apikey",
    "access_token",
    "secret",
    "password",
    "token",
];
const DESTRUCTIVE_REVIEW_PATTERNS: &[&str] =
    &["rm -rf", "delete all", "drop database", "format disk"];
const REVIEW_CONSENT_PHRASES: &[&str] = &[
    "ask before",
    "with user consent",
    "after confirmation",
    "explicit consent",
];
const REVIEW_CONSENT_NEGATIONS: &[&str] = &[
    "do not ask",
    "don't ask",
    "without consent",
    "without user consent",
    "no consent",
    "without confirmation",
    "no confirmation",
];
const REVIEW_UNSAFE_EXECUTION_PHRASES: &[&str] = &[
    "automatically",
    "immediately",
    "without asking",
    "without confirmation",
    "without consent",
    "without user consent",
];
const ASK_BEFORE_DESTRUCTIVE_ACTIONS: &[&str] = &[
    "run",
    "running",
    "execute",
    "executing",
    "delete",
    "deleting",
    "drop",
    "dropping",
    "format",
    "formatting",
];
const REVIEW_CONSENT_MAX_DISTANCE: usize = 40;

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

pub trait SkillReviewJudge: Send + Sync {
    fn review(&self, input: SkillReviewInput<'_>) -> Result<SkillReviewReport, SkillError>;
}

pub struct SkillReviewInput<'a> {
    pub manifest: &'a SkillManifest,
    pub skill_md: &'a str,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SkillReviewReport {
    pub findings: Vec<SkillCiFinding>,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct RuleBasedSkillReviewJudge;

impl SkillReviewJudge for RuleBasedSkillReviewJudge {
    fn review(&self, input: SkillReviewInput<'_>) -> Result<SkillReviewReport, SkillError> {
        let mut findings = Vec::new();
        let text = input.skill_md.to_ascii_lowercase();

        if input
            .manifest
            .description
            .as_deref()
            .unwrap_or("")
            .trim()
            .len()
            < 8
        {
            findings.push(warning_finding(
                "agentenv.skill.review.description-vague",
                "description is too short to describe behavior",
                Some(PathBuf::from("skill.yaml")),
                None,
            ));
        }

        if contains_destructive_without_consent(&text) {
            findings.push(error_finding(
                "agentenv.skill.review.destructive-without-consent",
                "destructive operation is described without explicit user consent",
                Some(input.manifest.entry.clone()),
                None,
            ));
        }

        if contains_api_key_reference(&text) && !text.contains("credential") {
            findings.push(error_finding(
                "agentenv.skill.review.credential-handling",
                "credential handling must use agentenv credential language",
                Some(input.manifest.entry.clone()),
                None,
            ));
        }

        Ok(SkillReviewReport { findings })
    }
}

fn contains_destructive_without_consent(text: &str) -> bool {
    DESTRUCTIVE_REVIEW_PATTERNS
        .iter()
        .any(|needle| destructive_matches_without_consent(text, needle))
}

fn destructive_matches_without_consent(text: &str, needle: &str) -> bool {
    let mut cursor = 0;
    while let Some(relative_start) = text[cursor..].find(needle) {
        let start = cursor + relative_start;
        let end = start + needle.len();
        let (segment_start, segment_end) = review_segment_bounds(text, start, end);
        let segment = &text[segment_start..segment_end];
        if !segment_has_valid_consent(segment, start - segment_start, end - segment_start) {
            return true;
        }
        cursor = end;
    }

    false
}

fn review_segment_bounds(text: &str, start: usize, end: usize) -> (usize, usize) {
    let segment_start = text[..start]
        .char_indices()
        .rev()
        .find_map(|(index, ch)| review_segment_boundary(ch).then_some(index + ch.len_utf8()))
        .unwrap_or(0);
    let segment_end = text[end..]
        .char_indices()
        .find_map(|(offset, ch)| review_segment_boundary(ch).then_some(end + offset))
        .unwrap_or(text.len());

    (segment_start, segment_end)
}

fn review_segment_boundary(ch: char) -> bool {
    matches!(ch, '.' | '!' | '?' | ';' | '\n' | '\r')
}

fn segment_has_valid_consent(
    segment: &str,
    destructive_start: usize,
    destructive_end: usize,
) -> bool {
    !REVIEW_CONSENT_NEGATIONS
        .iter()
        .any(|negation| segment.contains(negation))
        && !destructive_window_has_unsafe_execution(segment, destructive_start, destructive_end)
        && REVIEW_CONSENT_PHRASES.iter().any(|phrase| {
            consent_phrase_governs_destructive(segment, phrase, destructive_start, destructive_end)
        })
}

fn destructive_window_has_unsafe_execution(
    segment: &str,
    destructive_start: usize,
    destructive_end: usize,
) -> bool {
    let window_start = previous_char_boundary(
        segment,
        destructive_start.saturating_sub(REVIEW_CONSENT_MAX_DISTANCE),
    );
    let window_end = next_char_boundary(
        segment,
        (destructive_end + REVIEW_CONSENT_MAX_DISTANCE).min(segment.len()),
    );
    let window = &segment[window_start..window_end];

    REVIEW_UNSAFE_EXECUTION_PHRASES
        .iter()
        .any(|phrase| window.contains(phrase))
}

fn consent_phrase_governs_destructive(
    segment: &str,
    phrase: &str,
    destructive_start: usize,
    destructive_end: usize,
) -> bool {
    let mut cursor = 0;
    while let Some(relative_start) = segment[cursor..].find(phrase) {
        let phrase_start = cursor + relative_start;
        let phrase_end = phrase_start + phrase.len();
        if consent_phrase_match_governs_destructive(
            segment,
            phrase,
            phrase_end,
            phrase_start,
            destructive_start,
            destructive_end,
        ) {
            return true;
        }
        cursor = phrase_end;
    }

    false
}

fn consent_phrase_match_governs_destructive(
    segment: &str,
    phrase: &str,
    phrase_end: usize,
    phrase_start: usize,
    destructive_start: usize,
    destructive_end: usize,
) -> bool {
    if phrase_end <= destructive_start {
        let gap = &segment[phrase_end..destructive_start];
        if gap.len() > REVIEW_CONSENT_MAX_DISTANCE {
            return false;
        }
        if phrase == "ask before" {
            return ask_before_gap_governs_destructive(gap);
        }
        !contains_unrelated_consent_separator(gap)
    } else {
        phrase_start < destructive_end
    }
}

fn ask_before_gap_governs_destructive(gap: &str) -> bool {
    if contains_unrelated_consent_separator(gap) {
        return false;
    }

    let gap = gap.trim_matches(|ch: char| {
        ch.is_whitespace() || matches!(ch, '`' | '"' | '\'' | ':' | '-' | '>')
    });
    gap.is_empty()
        || ASK_BEFORE_DESTRUCTIVE_ACTIONS
            .iter()
            .any(|action| starts_with_word(gap, action))
}

fn contains_unrelated_consent_separator(text: &str) -> bool {
    text.contains(',') || contains_word(text, "then") || contains_word(text, "and")
}

fn starts_with_word(text: &str, word: &str) -> bool {
    text.strip_prefix(word).is_some_and(|tail| {
        tail.chars()
            .next()
            .is_none_or(|ch| !ch.is_ascii_alphanumeric())
    })
}

fn contains_word(text: &str, word: &str) -> bool {
    let mut cursor = 0;
    while let Some(relative_start) = text[cursor..].find(word) {
        let start = cursor + relative_start;
        let end = start + word.len();
        let before = text[..start].chars().next_back();
        let after = text[end..].chars().next();
        if before.is_none_or(|ch| !ch.is_ascii_alphanumeric())
            && after.is_none_or(|ch| !ch.is_ascii_alphanumeric())
        {
            return true;
        }
        cursor = end;
    }

    false
}

fn previous_char_boundary(text: &str, index: usize) -> usize {
    if text.is_char_boundary(index) {
        return index;
    }

    text.char_indices()
        .take_while(|(boundary, _)| *boundary < index)
        .last()
        .map(|(boundary, _)| boundary)
        .unwrap_or(0)
}

fn next_char_boundary(text: &str, index: usize) -> usize {
    if text.is_char_boundary(index) {
        return index;
    }

    text.char_indices()
        .find_map(|(boundary, _)| (boundary > index).then_some(boundary))
        .unwrap_or(text.len())
}

fn contains_api_key_reference(text: &str) -> bool {
    text.contains("api key") || text.contains("api-key") || text.contains("apikey")
}

pub fn run_skill_ci(request: SkillCiRequest) -> Result<SkillCiReport, SkillError> {
    let started_at = OffsetDateTime::now_utc();

    let mut tiers = Vec::new();
    let static_started = Instant::now();
    let StaticLintResult {
        candidate,
        findings,
        manifest,
        entry_content,
        functional_regression_ready,
        self_test_source_path,
    } = run_static_lint(&request.candidate_path)?;
    let mut static_report = tier_from_findings(SkillCiTier::StaticLint, findings);
    static_report.duration_ms = static_started.elapsed().as_millis();
    let static_failed = static_report.status == SkillCiTierStatus::Failed;
    tiers.push(static_report);

    if request.fail_fast && static_failed {
        for tier in [
            SkillCiTier::AgentReview,
            SkillCiTier::SemanticDedup,
            SkillCiTier::FunctionalRegression,
        ] {
            tiers.push(skipped_tier(tier, "skipped because static_lint failed"));
        }
    } else if let (Some(manifest), Some(skill_md)) = (manifest.as_ref(), entry_content.as_deref()) {
        let review_started = Instant::now();
        let review = RuleBasedSkillReviewJudge.review(SkillReviewInput { manifest, skill_md })?;
        let mut review_report = tier_from_findings(SkillCiTier::AgentReview, review.findings);
        review_report.duration_ms = review_started.elapsed().as_millis();
        let review_failed = review_report.status == SkillCiTierStatus::Failed;
        tiers.push(review_report);

        let dedup_started = Instant::now();
        let mut dedup_report = run_semantic_dedup(
            manifest,
            &candidate.digest,
            skill_md,
            request.registry_snapshot.as_ref(),
        );
        dedup_report.duration_ms = dedup_started.elapsed().as_millis();
        let dedup_failed = dedup_report.status == SkillCiTierStatus::Failed;
        tiers.push(dedup_report);

        if request.fail_fast && (static_failed || review_failed || dedup_failed) {
            tiers.push(skipped_tier(
                SkillCiTier::FunctionalRegression,
                "skipped because an earlier tier failed",
            ));
        } else if !functional_regression_ready {
            tiers.push(skipped_tier(
                SkillCiTier::FunctionalRegression,
                "skipped because static_lint found an invalid signature or self-test",
            ));
        } else {
            let regression_started = Instant::now();
            let mut regression_report = run_functional_regression(
                &request.candidate_path,
                manifest,
                &candidate.digest,
                self_test_source_path.unwrap_or_else(|| PathBuf::from("skill-test.yaml")),
                Arc::clone(&request.agent_runner),
            )?;
            regression_report.duration_ms = regression_started.elapsed().as_millis();
            tiers.push(regression_report);
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

    Ok(SkillCiReport {
        schema_version: SKILL_CI_SCHEMA_VERSION,
        candidate,
        status,
        tiers,
        started_at,
        completed_at: OffsetDateTime::now_utc(),
    })
}

fn run_semantic_dedup(
    manifest: &super::SkillManifest,
    digest: &str,
    skill_md: &str,
    snapshot: Option<&SkillCiRegistrySnapshot>,
) -> SkillCiTierReport {
    let mut best: Option<(SkillCiRegistrySkill, f32, String, bool)> = None;
    let mut novelty = 0.9_f64;

    if let Some(snapshot) = snapshot {
        for existing in &snapshot.skills {
            let exact_fingerprint = existing.fingerprint.as_deref() == Some(digest);
            let semantic_similarity = [
                text_similarity(skill_md, &existing.procedure_text),
                text_similarity(
                    manifest.description.as_deref().unwrap_or(""),
                    &existing.description,
                ),
            ]
            .into_iter()
            .flatten()
            .fold(None, |best: Option<f32>, similarity| {
                Some(best.map_or(similarity, |best| best.max(similarity)))
            });

            let (similarity, reason) = if exact_fingerprint {
                (1.0, "exact fingerprint match".to_owned())
            } else if let Some(similarity) = semantic_similarity {
                (similarity, "local semantic similarity".to_owned())
            } else {
                continue;
            };

            if best
                .as_ref()
                .is_none_or(|(_, current_similarity, _, current_exact_fingerprint)| {
                    similarity > *current_similarity
                        || (similarity == *current_similarity
                            && exact_fingerprint
                            && !*current_exact_fingerprint)
                })
            {
                best = Some((existing.clone(), similarity, reason, exact_fingerprint));
            }
        }
    }

    let probable_duplicate = best
        .as_ref()
        .is_some_and(|(_, similarity, _, _)| *similarity > 0.92);
    if let Some((_, similarity, _, _)) = &best {
        novelty = if *similarity > 0.92 {
            0.0
        } else if *similarity >= 0.85 {
            0.3
        } else if *similarity >= 0.45 {
            0.6
        } else {
            0.9
        };
    }

    let mut findings = Vec::new();
    if probable_duplicate {
        findings.push(error_finding(
            "agentenv.skill.dedup.probable-duplicate",
            "candidate is probably a duplicate of an existing skill",
            Some(manifest.entry.clone()),
            None,
        ));
    }

    let nearest_neighbors: Vec<Value> = best
        .into_iter()
        .map(|(skill, similarity, reason, _)| {
            json!({
                "name": skill.name,
                "version": skill.version,
                "similarity": similarity,
                "reason": reason
            })
        })
        .collect();
    let mut report = tier_from_findings(SkillCiTier::SemanticDedup, findings);
    report.details = Some(json!({
        "nearest_neighbors": nearest_neighbors,
        "novelty_score": novelty,
        "probable_duplicate": probable_duplicate
    }));
    report
}

fn run_functional_regression(
    candidate_path: &std::path::Path,
    manifest: &super::SkillManifest,
    digest: &str,
    self_test_source_path: PathBuf,
    agent_runner: Arc<dyn AgentProduceRunner>,
) -> Result<SkillCiTierReport, SkillError> {
    let spec = load_skill_self_test_spec(candidate_path)?;
    let report = super::run_skill_self_test(
        candidate_path,
        manifest.name.clone(),
        manifest.version.to_string(),
        digest.to_owned(),
        &spec,
        super::SkillSelfTestOptions::default(),
        agent_runner,
    )?;

    let mut findings = Vec::new();
    if !report.publishable {
        findings.push(error_finding(
            "agentenv.skill.self-test.score-below-threshold",
            &format!(
                "self-test score {:.3} is below required threshold {:.3}",
                report.score,
                super::SELF_TEST_PUBLISH_THRESHOLD
            ),
            Some(self_test_source_path),
            None,
        ));
    }

    let mut tier = tier_from_findings(SkillCiTier::FunctionalRegression, findings);
    tier.details = Some(serde_json::json!({
        "score": report.score,
        "passed": report.passed,
        "total": report.total,
        "publishable": report.publishable,
        "self_test_digest": report.self_test_digest
    }));
    Ok(tier)
}

fn text_similarity(left: &str, right: &str) -> Option<f32> {
    let left = tokens(left);
    let right = tokens(right);
    if left.is_empty() || right.is_empty() {
        return None;
    }

    Some(jaccard_tokens(&left, &right))
}

fn jaccard_tokens(left: &BTreeSet<String>, right: &BTreeSet<String>) -> f32 {
    let intersection = left.intersection(right).count() as f32;
    let union = left.union(right).count() as f32;
    if union == 0.0 {
        0.0
    } else {
        intersection / union
    }
}

fn tokens(value: &str) -> BTreeSet<String> {
    value
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(|token| token.to_ascii_lowercase())
        .collect()
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

pub fn skill_ci_sarif(report: &SkillCiReport) -> Result<String, SkillError> {
    let results: Vec<Value> = report
        .tiers
        .iter()
        .filter(|tier| {
            matches!(
                tier.tier,
                SkillCiTier::StaticLint | SkillCiTier::AgentReview
            )
        })
        .flat_map(|tier| tier.findings.iter())
        .filter(|finding| finding.severity != SkillCiSeverity::Note)
        .map(sarif_result)
        .collect();

    let sarif = json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "agentenv skill ci"
                    }
                },
                "results": results
            }
        ]
    });

    serde_json::to_string_pretty(&sarif).map_err(|source| SkillError::SkillCiSarif {
        message: source.to_string(),
    })
}

fn sarif_result(finding: &SkillCiFinding) -> Value {
    let mut result = Map::new();
    let message = redact_sarif_message(&finding.message);
    result.insert("ruleId".to_owned(), json!(finding.rule_id));
    result.insert("level".to_owned(), json!(sarif_level(finding.severity)));
    result.insert(
        "message".to_owned(),
        json!({
            "text": message,
        }),
    );

    if let Some(path) = &finding.path {
        let mut physical_location = Map::new();
        physical_location.insert(
            "artifactLocation".to_owned(),
            json!({
                "uri": sarif_uri(path),
            }),
        );
        if let Some(line) = finding.line {
            physical_location.insert(
                "region".to_owned(),
                json!({
                    "startLine": line,
                }),
            );
        }
        result.insert(
            "locations".to_owned(),
            json!([
                {
                    "physicalLocation": Value::Object(physical_location),
                }
            ]),
        );
    }

    Value::Object(result)
}

fn sarif_level(severity: SkillCiSeverity) -> &'static str {
    match severity {
        SkillCiSeverity::Error => "error",
        SkillCiSeverity::Warning => "warning",
        SkillCiSeverity::Note => "note",
    }
}

fn sarif_uri(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn redact_sarif_message(message: &str) -> String {
    redact_labeled_secrets(&redact_prefixed_secrets(message))
}

fn redact_prefixed_secrets(message: &str) -> String {
    let mut redacted = String::with_capacity(message.len());
    let mut cursor = 0;

    while let Some((start, end)) = find_next_prefixed_secret(message, cursor) {
        redacted.push_str(&message[cursor..start]);
        redacted.push_str(SECRET_REDACTION);
        cursor = end;
    }

    redacted.push_str(&message[cursor..]);
    redacted
}

fn find_next_prefixed_secret(message: &str, start_at: usize) -> Option<(usize, usize)> {
    SECRET_PREFIX_PATTERNS
        .iter()
        .filter_map(|(prefix, minimum_suffix)| {
            find_next_prefixed_secret_for_prefix(message, start_at, prefix, *minimum_suffix)
        })
        .min_by_key(|(start, _)| *start)
}

fn find_next_prefixed_secret_for_prefix(
    message: &str,
    start_at: usize,
    prefix: &str,
    minimum_suffix: usize,
) -> Option<(usize, usize)> {
    let mut cursor = start_at;
    loop {
        let start = cursor + message[cursor..].find(prefix)?;
        let suffix_start = start + prefix.len();
        let end = secret_token_end(message, suffix_start);
        let suffix_length = message[suffix_start..end].chars().count();
        if suffix_length >= minimum_suffix {
            return Some((start, end));
        }
        cursor = suffix_start;
    }
}

fn redact_labeled_secrets(message: &str) -> String {
    let mut redacted = String::with_capacity(message.len());
    let mut cursor = 0;

    while let Some((start, end)) = find_next_labeled_secret(message, cursor) {
        redacted.push_str(&message[cursor..start]);
        redacted.push_str(SECRET_REDACTION);
        cursor = end;
    }

    redacted.push_str(&message[cursor..]);
    redacted
}

fn find_next_labeled_secret(message: &str, start_at: usize) -> Option<(usize, usize)> {
    let lower = message.to_ascii_lowercase();
    let mut cursor = start_at;

    loop {
        let (keyword_start, keyword) = SECRET_KEYWORDS
            .iter()
            .filter_map(|keyword| {
                lower[cursor..]
                    .find(keyword)
                    .map(|relative| (cursor + relative, *keyword))
            })
            .min_by_key(|(start, _)| *start)?;

        let keyword_end = keyword_start + keyword.len();
        let tail = &message[keyword_end..];
        let separator_index = tail.find([':', '='])?;
        let value_start = keyword_end + separator_index + 1;
        let secret_start = secret_value_start(message, value_start);
        let secret_end = secret_token_end(message, secret_start);
        let secret_length = message[secret_start..secret_end].chars().count();
        if secret_length >= 20 {
            return Some((secret_start, secret_end));
        }

        cursor = keyword_end;
    }
}

fn secret_value_start(message: &str, start_at: usize) -> usize {
    message[start_at..]
        .char_indices()
        .find_map(|(offset, ch)| {
            if ch.is_whitespace() || matches!(ch, '"' | '\'') {
                None
            } else {
                Some(start_at + offset)
            }
        })
        .unwrap_or(message.len())
}

fn secret_token_end(message: &str, start_at: usize) -> usize {
    message[start_at..]
        .char_indices()
        .find_map(|(offset, ch)| {
            if is_secret_char(ch) {
                None
            } else {
                Some(start_at + offset)
            }
        })
        .unwrap_or(message.len())
}

struct StaticLintResult {
    candidate: SkillCiCandidate,
    findings: Vec<SkillCiFinding>,
    manifest: Option<SkillManifest>,
    entry_content: Option<String>,
    functional_regression_ready: bool,
    self_test_source_path: Option<PathBuf>,
}

fn run_static_lint(candidate_path: &Path) -> Result<StaticLintResult, SkillError> {
    let mut findings = Vec::new();
    let mut candidate = fallback_candidate(candidate_path);

    let manifest = match load_skill_manifest(candidate_path) {
        Ok(manifest) => manifest,
        Err(_) => {
            findings.push(error_finding(
                "agentenv.skill.manifest.invalid",
                "skill manifest is invalid",
                Some(PathBuf::from("skill.yaml")),
                None,
            ));
            return Ok(StaticLintResult {
                candidate,
                findings,
                manifest: None,
                entry_content: None,
                functional_regression_ready: false,
                self_test_source_path: None,
            });
        }
    };

    candidate.name = manifest.name.clone();
    candidate.version = manifest.version.to_string();

    if !manifest.version.pre.is_empty() {
        findings.push(error_finding(
            "agentenv.skill.version.prerelease",
            "skill manifest version must not be a prerelease",
            Some(PathBuf::from("skill.yaml")),
            None,
        ));
    }

    let mut functional_regression_ready = true;
    let digest = match compute_bundle_digest(candidate_path, &manifest) {
        Ok(digest) => {
            candidate.digest = digest.clone();
            Some(digest)
        }
        Err(_) => {
            functional_regression_ready = false;
            findings.push(error_finding(
                "agentenv.skill.signature.invalid",
                "skill package signature could not be verified",
                Some(PathBuf::from("skill.yaml")),
                None,
            ));
            None
        }
    };

    if let Some(digest) = digest.as_deref() {
        if super::signature::verify_skill_package_signature(&manifest, digest, false).is_err() {
            functional_regression_ready = false;
            findings.push(error_finding(
                "agentenv.skill.signature.invalid",
                "skill package signature is invalid",
                Some(PathBuf::from("skill.yaml")),
                None,
            ));
        }
    }

    let self_test_source_path = match load_skill_self_test_spec(candidate_path) {
        Ok(_) => Some(self_test_source_path(candidate_path)),
        Err(_) => {
            functional_regression_ready = false;
            findings.push(error_finding(
                "agentenv.skill.self-test.invalid",
                "skill self-test is invalid",
                Some(PathBuf::from("skill.yaml")),
                None,
            ));
            None
        }
    };

    let entry_content = match read_declared_text(candidate_path, &manifest.entry) {
        Ok(content) => {
            lint_markdown(&manifest.entry, &content, &mut findings);
            Some(content)
        }
        Err(_) => {
            findings.push(error_finding(
                "agentenv.skill.manifest.invalid",
                "skill manifest entry cannot be read as text",
                Some(manifest.entry.clone()),
                None,
            ));
            None
        }
    };

    lint_declared_text_secrets(candidate_path, &manifest, &mut findings);

    Ok(StaticLintResult {
        candidate,
        findings,
        manifest: Some(manifest),
        entry_content,
        functional_regression_ready,
        self_test_source_path,
    })
}

fn self_test_source_path(candidate_path: &Path) -> PathBuf {
    if candidate_path.join("skill-test.yaml").is_file() {
        return PathBuf::from("skill-test.yaml");
    }

    if skill_md_declares_self_test(candidate_path) {
        return PathBuf::from("SKILL.md");
    }

    PathBuf::from("skill.yaml")
}

fn skill_md_declares_self_test(candidate_path: &Path) -> bool {
    let Ok(content) = read_declared_text(candidate_path, Path::new("SKILL.md")) else {
        return false;
    };
    let FrontmatterState::Closed(end_line) = frontmatter_end_line(&content) else {
        return false;
    };

    let yaml = content
        .lines()
        .skip(1)
        .take(end_line.saturating_sub(2))
        .collect::<Vec<_>>()
        .join("\n");
    let Ok(YamlValue::Mapping(mapping)) = serde_yaml::from_str::<YamlValue>(&yaml) else {
        return false;
    };
    mapping.contains_key(YamlValue::String("self_test".to_owned()))
}

fn fallback_candidate(candidate_path: &Path) -> SkillCiCandidate {
    SkillCiCandidate {
        name: candidate_path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown".to_owned()),
        version: "unknown".to_owned(),
        digest: String::new(),
    }
}

fn error_finding(
    rule_id: &str,
    message: &str,
    path: Option<PathBuf>,
    line: Option<usize>,
) -> SkillCiFinding {
    SkillCiFinding {
        rule_id: rule_id.to_owned(),
        severity: SkillCiSeverity::Error,
        message: message.to_owned(),
        path,
        line,
    }
}

fn warning_finding(
    rule_id: impl Into<String>,
    message: impl Into<String>,
    path: Option<PathBuf>,
    line: Option<usize>,
) -> SkillCiFinding {
    SkillCiFinding {
        rule_id: rule_id.into(),
        severity: SkillCiSeverity::Warning,
        message: message.into(),
        path,
        line,
    }
}

fn read_declared_text(root: &Path, declared: &Path) -> Result<String, SkillError> {
    let declared = normalize_bundle_path(declared)?;
    let path = validated_bundle_file(root, &declared)?;
    std::fs::read_to_string(&path).map_err(|source| SkillError::Io { path, source })
}

fn lint_markdown(path: &Path, content: &str, findings: &mut Vec<SkillCiFinding>) {
    let frontmatter_end_line = match frontmatter_end_line(content) {
        FrontmatterState::Absent => 0,
        FrontmatterState::Closed(line) => line,
        FrontmatterState::Unclosed => {
            findings.push(error_finding(
                "agentenv.skill.frontmatter.unclosed",
                "YAML frontmatter is not closed",
                Some(path.to_path_buf()),
                Some(1),
            ));
            usize::MAX
        }
    };

    let mut fence: Option<(String, usize)> = None;
    let mut previous_heading_level: Option<usize> = None;
    for (index, line) in content.lines().enumerate() {
        let line_number = index + 1;
        if line_number <= frontmatter_end_line {
            continue;
        }

        let trimmed = line.trim_start();
        if let Some((marker, _)) = fence.as_ref() {
            if trimmed.starts_with(marker) {
                fence = None;
            }
            continue;
        }

        if let Some(marker) = opening_fence_marker(trimmed) {
            fence = Some((marker.to_owned(), line_number));
            continue;
        }

        let Some(heading_level) = markdown_heading_level(trimmed) else {
            continue;
        };
        if let Some(previous) = previous_heading_level {
            if heading_level > previous + 1 {
                findings.push(error_finding(
                    "agentenv.skill.markdown.heading-jump",
                    "Markdown heading level jumps by more than one",
                    Some(path.to_path_buf()),
                    Some(line_number),
                ));
            }
        }
        previous_heading_level = Some(heading_level);
    }

    if let Some((_, line)) = fence {
        findings.push(error_finding(
            "agentenv.skill.markdown.unclosed-fence",
            "Markdown fenced code block is not closed",
            Some(path.to_path_buf()),
            Some(line),
        ));
    }
}

enum FrontmatterState {
    Absent,
    Closed(usize),
    Unclosed,
}

fn frontmatter_end_line(content: &str) -> FrontmatterState {
    let mut lines = content.lines();
    if lines.next() != Some("---") {
        return FrontmatterState::Absent;
    }

    for (index, line) in lines.enumerate() {
        if line.trim_end() == "---" {
            return FrontmatterState::Closed(index + 2);
        }
    }

    FrontmatterState::Unclosed
}

fn opening_fence_marker(line: &str) -> Option<&'static str> {
    if line.starts_with("```") {
        Some("```")
    } else if line.starts_with("~~~") {
        Some("~~~")
    } else {
        None
    }
}

fn markdown_heading_level(trimmed: &str) -> Option<usize> {
    let level = trimmed
        .chars()
        .take_while(|character| *character == '#')
        .count();
    if !(1..=6).contains(&level) {
        return None;
    }

    match trimmed[level..].chars().next() {
        None | Some(' ' | '\t') => Some(level),
        _ => None,
    }
}

fn lint_declared_text_secrets(
    candidate_path: &Path,
    manifest: &SkillManifest,
    findings: &mut Vec<SkillCiFinding>,
) {
    for declared in secret_scan_paths(manifest) {
        let Ok(content) = read_declared_text(candidate_path, &declared) else {
            continue;
        };
        lint_secrets(&declared, &content, findings);
    }
}

fn secret_scan_paths(manifest: &SkillManifest) -> BTreeSet<PathBuf> {
    let mut paths = BTreeSet::new();
    paths.insert(PathBuf::from("skill.yaml"));
    paths.insert(PathBuf::from("skill-test.yaml"));
    paths.insert(manifest.entry.clone());

    for declared in &manifest.declared_files {
        if is_text_path(declared) {
            paths.insert(declared.clone());
        }
    }

    paths
}

fn lint_secrets(path: &Path, content: &str, findings: &mut Vec<SkillCiFinding>) {
    if let Some((index, _)) = content
        .lines()
        .enumerate()
        .find(|(_, line)| contains_secret_like_text(line))
    {
        findings.push(error_finding(
            "agentenv.skill.secret.detected",
            "secret-like content detected in bundled text",
            Some(path.to_path_buf()),
            Some(index + 1),
        ));
    }
}

fn is_text_path(path: &Path) -> bool {
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    if matches!(
        file_name.as_str(),
        "skill.md" | "skill.yaml" | "skill.yml" | "skill-test.yaml" | "skill-test.yml"
    ) {
        return true;
    }

    let Some(extension) = path
        .extension()
        .map(|extension| extension.to_string_lossy().to_ascii_lowercase())
    else {
        return false;
    };

    matches!(
        extension.as_str(),
        "md" | "mdx"
            | "txt"
            | "yaml"
            | "yml"
            | "json"
            | "toml"
            | "rs"
            | "sh"
            | "bash"
            | "zsh"
            | "fish"
            | "py"
            | "js"
            | "ts"
            | "tsx"
            | "jsx"
            | "html"
            | "css"
            | "csv"
    )
}

fn contains_secret_like_text(text: &str) -> bool {
    SECRET_PREFIX_PATTERNS
        .iter()
        .any(|(prefix, minimum_suffix)| has_prefixed_secret(text, prefix, *minimum_suffix))
        || has_keyword_assigned_secret(text)
}

fn has_prefixed_secret(text: &str, prefix: &str, minimum_suffix: usize) -> bool {
    text.match_indices(prefix).any(|(index, _)| {
        let suffix = &text[index + prefix.len()..];
        suffix.chars().take_while(|ch| is_secret_char(*ch)).count() >= minimum_suffix
    })
}

fn has_keyword_assigned_secret(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    SECRET_KEYWORDS.iter().any(|keyword| {
        let Some(index) = lower.find(keyword) else {
            return false;
        };
        let tail = &text[index + keyword.len()..];
        let Some(separator_index) = tail.find([':', '=']) else {
            return false;
        };
        let candidate = tail[separator_index + 1..]
            .trim_start_matches(|ch: char| ch.is_whitespace() || matches!(ch, '"' | '\''));
        candidate
            .chars()
            .take_while(|ch| is_secret_char(*ch))
            .count()
            >= 20
    })
}

fn is_secret_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.')
}
