use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread,
    time::{Duration, Instant},
};

#[cfg(unix)]
use std::os::unix::process::CommandExt;

use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use super::{manifest::normalize_bundle_path, SkillError};

const SKILL_TEST_FILE: &str = "skill-test.yaml";
const SKILL_MD_FILE: &str = "SKILL.md";
const SKILL_YAML_FILE: &str = "skill.yaml";
const DEFAULT_TIMEOUT_SECONDS: u64 = 120;
const LEGACY_TIMEOUT_SECONDS: u64 = 30;
pub const SELF_TEST_PUBLISH_THRESHOLD: f64 = 0.8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SkillSelfTestRunner {
    Agentenv,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SkillSelfTestSpec {
    pub runner: SkillSelfTestRunner,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blueprint: Option<PathBuf>,
    pub assertions: Vec<SkillSelfTestAssertion>,
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum SkillSelfTestAssertion {
    CommandExitsZero {
        cmd: String,
    },
    FileExists {
        path: PathBuf,
    },
    AgentProduces {
        prompt: String,
        expect_tokens_matching: Vec<String>,
        min_match_ratio: f64,
    },
}

impl SkillSelfTestAssertion {
    pub fn kind(&self) -> &'static str {
        match self {
            SkillSelfTestAssertion::CommandExitsZero { .. } => "command_exits_zero",
            SkillSelfTestAssertion::FileExists { .. } => "file_exists",
            SkillSelfTestAssertion::AgentProduces { .. } => "agent_produces",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SkillSelfTestReport {
    pub name: String,
    pub version: String,
    pub digest: String,
    pub self_test_digest: String,
    pub score: f64,
    pub passed: usize,
    pub total: usize,
    pub publishable: bool,
    pub assertions: Vec<SkillAssertionResult>,
    pub started_at: OffsetDateTime,
    pub completed_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillAssertionResult {
    #[serde(rename = "type")]
    pub assertion_type: String,
    pub status: SkillAssertionStatus,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillAssertionStatus {
    Passed,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Copy)]
pub struct SkillSelfTestOptions {
    pub threshold: f64,
}

impl Default for SkillSelfTestOptions {
    fn default() -> Self {
        Self {
            threshold: SELF_TEST_PUBLISH_THRESHOLD,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AgentProduceRequest<'a> {
    pub skill_root: &'a Path,
    pub blueprint: &'a Path,
    pub prompt: &'a str,
    pub timeout: Duration,
    pub cancelled: Arc<AtomicBool>,
}

/// Runs an `agent_produces` prompt for the self-test engine.
///
/// Implementations must honor `AgentProduceRequest::timeout` and return promptly
/// when `AgentProduceRequest::cancelled` is set. The core runner also bounds its
/// wait on this call, but Rust cannot safely stop an arbitrary blocked thread.
pub trait AgentProduceRunner: Send + Sync + 'static {
    fn run_agent_prompt(&self, request: AgentProduceRequest<'_>) -> Result<String, SkillError>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct UnsupportedAgentProduceRunner;

impl AgentProduceRunner for UnsupportedAgentProduceRunner {
    fn run_agent_prompt(&self, _request: AgentProduceRequest<'_>) -> Result<String, SkillError> {
        Err(SkillError::UnsupportedAgentProduces)
    }
}

pub fn run_skill_self_test(
    skill_root: impl AsRef<Path>,
    name: impl Into<String>,
    version: impl Into<String>,
    digest: impl Into<String>,
    spec: &SkillSelfTestSpec,
    options: SkillSelfTestOptions,
    agent_runner: Arc<dyn AgentProduceRunner>,
) -> Result<SkillSelfTestReport, SkillError> {
    let skill_root = skill_root.as_ref();
    if !options.threshold.is_finite() || !(0.0..=1.0).contains(&options.threshold) {
        return Err(SkillError::InvalidSelfTest {
            message: "self-test threshold must be between 0.0 and 1.0".to_owned(),
        });
    }
    if spec.timeout_seconds == 0 {
        return Err(SkillError::InvalidSelfTest {
            message: "self-test timeout_seconds must be greater than 0".to_owned(),
        });
    }

    let started_at = OffsetDateTime::now_utc();
    let started = Instant::now();
    let timeout = Duration::from_secs(spec.timeout_seconds);
    let deadline = started
        .checked_add(timeout)
        .ok_or_else(|| SkillError::InvalidSelfTest {
            message: "self-test timeout_seconds is too large".to_owned(),
        })?;
    let mut assertions = Vec::with_capacity(spec.assertions.len());

    for assertion in &spec.assertions {
        if Instant::now() >= deadline {
            assertions.push(SkillAssertionResult {
                assertion_type: assertion.kind().to_owned(),
                status: SkillAssertionStatus::Skipped,
                message: "self-test deadline was reached before assertion ran".to_owned(),
            });
            continue;
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        assertions.push(run_assertion(
            skill_root,
            spec,
            assertion,
            Arc::clone(&agent_runner),
            remaining,
        ));
    }

    let passed = assertions
        .iter()
        .filter(|assertion| assertion.status == SkillAssertionStatus::Passed)
        .count();
    let total = spec.assertions.len();
    let score = if total == 0 {
        0.0
    } else {
        passed as f64 / total as f64
    };
    let threshold = options.threshold;
    Ok(SkillSelfTestReport {
        name: name.into(),
        version: version.into(),
        digest: digest.into(),
        self_test_digest: normalized_self_test_digest(spec)?,
        score,
        passed,
        total,
        publishable: score >= threshold,
        assertions,
        started_at,
        completed_at: OffsetDateTime::now_utc(),
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SelfTestDocument {
    self_test: RawSelfTestSpec,
}

#[derive(Debug, Deserialize)]
struct FrontmatterSelfTestDocument {
    self_test: RawSelfTestSpec,
    #[serde(flatten)]
    _extra: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSelfTestSpec {
    runner: Option<String>,
    blueprint: Option<String>,
    assertions: Option<Vec<SkillSelfTestAssertion>>,
    timeout_seconds: Option<u64>,
    command: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawSkillYaml {
    self_test: Option<RawSelfTestSpec>,
    #[serde(flatten)]
    _extra: BTreeMap<String, Value>,
}

pub fn load_skill_self_test_spec(root: impl AsRef<Path>) -> Result<SkillSelfTestSpec, SkillError> {
    let root = root.as_ref();
    let mut specs = Vec::new();

    if let Some(spec) = load_from_skill_test_yaml(root)? {
        specs.push(("skill-test.yaml", spec));
    }
    if let Some(spec) = load_from_skill_md_frontmatter(root)? {
        specs.push(("SKILL.md", spec));
    }
    if let Some(spec) = load_from_skill_yaml(root)? {
        specs.push(("skill.yaml", spec));
    }

    let Some((_, first)) = specs.first().cloned() else {
        return Err(SkillError::MissingSelfTest);
    };
    let first_digest = normalized_self_test_digest(&first)?;
    for (source, spec) in specs.iter().skip(1) {
        if first_digest != normalized_self_test_digest(spec)? {
            return Err(SkillError::ConflictingSelfTestDeclarations {
                declaration_source: (*source).to_owned(),
            });
        }
    }
    Ok(first)
}

pub fn normalized_self_test_digest(spec: &SkillSelfTestSpec) -> Result<String, SkillError> {
    let bytes = serde_json::to_vec(spec).map_err(|source| SkillError::InvalidSelfTest {
        message: format!("failed to serialize normalized self-test: {source}"),
    })?;
    let digest = Sha256::digest(bytes);
    Ok(format!("sha256:{}", hex::encode(digest)))
}

fn run_assertion(
    skill_root: &Path,
    spec: &SkillSelfTestSpec,
    assertion: &SkillSelfTestAssertion,
    agent_runner: Arc<dyn AgentProduceRunner>,
    remaining_timeout: Duration,
) -> SkillAssertionResult {
    match assertion {
        SkillSelfTestAssertion::FileExists { path } => run_file_exists(skill_root, assertion, path),
        SkillSelfTestAssertion::CommandExitsZero { cmd } => {
            run_command_exits_zero(skill_root, assertion, cmd, remaining_timeout)
        }
        SkillSelfTestAssertion::AgentProduces { .. } => {
            run_agent_produces(skill_root, spec, assertion, agent_runner, remaining_timeout)
        }
    }
}

fn passed(assertion: &SkillSelfTestAssertion, message: impl Into<String>) -> SkillAssertionResult {
    SkillAssertionResult {
        assertion_type: assertion.kind().to_owned(),
        status: SkillAssertionStatus::Passed,
        message: message.into(),
    }
}

fn failed(assertion: &SkillSelfTestAssertion, message: impl Into<String>) -> SkillAssertionResult {
    SkillAssertionResult {
        assertion_type: assertion.kind().to_owned(),
        status: SkillAssertionStatus::Failed,
        message: message.into(),
    }
}

fn run_file_exists(
    skill_root: &Path,
    assertion: &SkillSelfTestAssertion,
    path: &Path,
) -> SkillAssertionResult {
    let normalized = match normalize_bundle_path(path) {
        Ok(path) => path,
        Err(error) => return failed(assertion, error.to_string()),
    };
    let full_path = skill_root.join(&normalized);
    if full_path.is_file() {
        passed(assertion, format!("file exists `{}`", normalized.display()))
    } else {
        failed(
            assertion,
            format!("file does not exist `{}`", normalized.display()),
        )
    }
}

fn run_command_exits_zero(
    skill_root: &Path,
    assertion: &SkillSelfTestAssertion,
    cmd: &str,
    timeout: Duration,
) -> SkillAssertionResult {
    let mut command = shell_command(cmd);
    let mut child = match command
        .current_dir(skill_root)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .env_clear()
        .spawn()
    {
        Ok(child) => child,
        Err(source) => {
            return failed(
                assertion,
                format!("command failed to start `{cmd}`: {source}"),
            );
        }
    };
    let started = Instant::now();

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if status.success() {
                    return passed(assertion, format!("command exited zero `{cmd}`"));
                }
                return failed(
                    assertion,
                    format!("command exited nonzero `{cmd}` with status {status}"),
                );
            }
            Ok(None) => {
                if started.elapsed() >= timeout {
                    let cleanup_message = terminate_timed_out_self_test(&mut child)
                        .err()
                        .map(|error| format!("; cleanup failed: {error}"))
                        .unwrap_or_default();
                    return failed(
                        assertion,
                        format!(
                            "command timed out after {}s `{cmd}`{cleanup_message}",
                            timeout.as_secs()
                        ),
                    );
                }
                thread::sleep(Duration::from_millis(25));
            }
            Err(source) => {
                let _ = terminate_timed_out_self_test(&mut child);
                return failed(assertion, format!("command poll failed `{cmd}`: {source}"));
            }
        }
    }
}

fn run_agent_produces(
    skill_root: &Path,
    spec: &SkillSelfTestSpec,
    assertion: &SkillSelfTestAssertion,
    agent_runner: Arc<dyn AgentProduceRunner>,
    timeout: Duration,
) -> SkillAssertionResult {
    let SkillSelfTestAssertion::AgentProduces {
        prompt,
        expect_tokens_matching,
        min_match_ratio,
    } = assertion
    else {
        return failed(assertion, "internal assertion type mismatch");
    };

    let Some(blueprint) = &spec.blueprint else {
        return failed(assertion, "agent_produces requires self-test blueprint");
    };
    let normalized_blueprint = match normalize_bundle_path(blueprint) {
        Ok(path) => path,
        Err(error) => return failed(assertion, error.to_string()),
    };
    let blueprint = skill_root.join(normalized_blueprint);
    if expect_tokens_matching.is_empty() {
        return failed(
            assertion,
            "agent_produces requires at least one expected token",
        );
    }
    if !min_match_ratio.is_finite() || !(0.0..=1.0).contains(min_match_ratio) {
        return failed(
            assertion,
            "agent_produces min_match_ratio must be between 0.0 and 1.0",
        );
    }
    let output = match run_agent_prompt_with_timeout(
        agent_runner,
        skill_root.to_path_buf(),
        blueprint,
        prompt.to_owned(),
        timeout,
    ) {
        Ok(output) => output,
        Err(error) => return failed(assertion, error.to_string()),
    };
    let matched = expect_tokens_matching
        .iter()
        .filter(|token| output.contains(token.as_str()))
        .count();
    let ratio = matched as f64 / expect_tokens_matching.len() as f64;
    if ratio >= *min_match_ratio {
        passed(
            assertion,
            format!(
                "matched {matched}/{} expected tokens ({ratio:.3})",
                expect_tokens_matching.len()
            ),
        )
    } else {
        failed(
            assertion,
            format!(
                "matched {matched}/{} expected tokens ({ratio:.3}), below required {min_match_ratio:.3}",
                expect_tokens_matching.len()
            ),
        )
    }
}

fn run_agent_prompt_with_timeout(
    agent_runner: Arc<dyn AgentProduceRunner>,
    skill_root: PathBuf,
    blueprint: PathBuf,
    prompt: String,
    timeout: Duration,
) -> Result<String, SkillError> {
    let (sender, receiver) = mpsc::channel();
    let cancelled = Arc::new(AtomicBool::new(false));
    let request_cancelled = Arc::clone(&cancelled);
    thread::spawn(move || {
        let request = AgentProduceRequest {
            skill_root: &skill_root,
            blueprint: &blueprint,
            prompt: &prompt,
            timeout,
            cancelled: request_cancelled,
        };
        let _ = sender.send(agent_runner.run_agent_prompt(request));
    });

    match receiver.recv_timeout(timeout) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            cancelled.store(true, Ordering::Relaxed);
            Err(SkillError::SelfTestTimeout {
                timeout_seconds: timeout.as_secs(),
            })
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(SkillError::InvalidSelfTest {
            message: "agent_produces runner stopped before returning a result".to_owned(),
        }),
    }
}

#[cfg(unix)]
fn shell_command(command: &str) -> Command {
    let mut shell = Command::new("/bin/sh");
    shell.args([
        "-c",
        &format!("trap 'jobs -p | xargs kill -KILL 2>/dev/null || true' EXIT\n{command}"),
    ]);
    shell.process_group(0);
    shell
}

#[cfg(windows)]
fn shell_command(command: &str) -> Command {
    let mut shell = Command::new("cmd.exe");
    shell.args(["/C", command]);
    shell
}

#[cfg(not(any(unix, windows)))]
fn shell_command(command: &str) -> Command {
    let mut shell = Command::new("sh");
    shell.args(["-c", command]);
    shell
}

#[cfg(unix)]
fn terminate_timed_out_self_test(child: &mut Child) -> Result<(), String> {
    let process_group_id = child.id() as i32;
    let mut descendant_pids = unix_descendant_pids(process_group_id).unwrap_or_default();
    let _ = unix_signal_process_group(process_group_id, "STOP");
    unix_signal_pids(&descendant_pids, "STOP");
    thread::sleep(Duration::from_millis(25));

    if let Ok(mut discovered_pids) = unix_descendant_pids(process_group_id) {
        descendant_pids.append(&mut discovered_pids);
        descendant_pids.sort_unstable();
        descendant_pids.dedup();
    }

    let group_signal_error = unix_kill_process_group(process_group_id).err();
    unix_kill_pids(&descendant_pids);

    let _ = Command::new("pkill")
        .arg("-KILL")
        .arg("-g")
        .arg(process_group_id.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    child
        .wait()
        .map_err(|source| format!("wait failed: {source}"))?;

    let started_at = Instant::now();
    loop {
        let survivor_pids = unix_process_group_pids(process_group_id)?;
        if survivor_pids.is_empty() {
            return Ok(());
        }

        unix_kill_pids(&survivor_pids);
        if started_at.elapsed() >= Duration::from_secs(2) {
            let group_signal_error = group_signal_error
                .as_deref()
                .unwrap_or("process-group signal started successfully");
            return Err(format!(
                "process group {process_group_id} still has survivor pids {survivor_pids:?}; {group_signal_error}"
            ));
        }
        thread::sleep(Duration::from_millis(25));
    }
}

#[cfg(unix)]
fn unix_kill_process_group(process_group_id: i32) -> Result<(), String> {
    unix_signal_process_group(process_group_id, "KILL")
}

#[cfg(unix)]
fn unix_signal_process_group(process_group_id: i32, signal: &str) -> Result<(), String> {
    let status = Command::new("kill")
        .arg(format!("-{signal}"))
        .arg("--")
        .arg(format!("-{process_group_id}"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|source| format!("could not start process-group signal: {source}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "process-group signal {signal} exited with {status}"
        ))
    }
}

#[cfg(unix)]
fn unix_kill_pids(pids: &[i32]) {
    unix_signal_pids(pids, "KILL");
}

#[cfg(unix)]
fn unix_signal_pids(pids: &[i32], signal: &str) {
    for pid in pids {
        let _ = Command::new("kill")
            .arg(format!("-{signal}"))
            .arg("--")
            .arg(pid.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

#[cfg(unix)]
fn unix_process_group_pids(process_group_id: i32) -> Result<Vec<i32>, String> {
    let output = Command::new("pgrep")
        .arg("-g")
        .arg(process_group_id.to_string())
        .output()
        .map_err(|source| format!("could not list process group {process_group_id}: {source}"))?;
    if !output.status.success() {
        return Ok(Vec::new());
    }
    parse_pid_lines(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(unix)]
fn unix_descendant_pids(root_pid: i32) -> Result<Vec<i32>, String> {
    let output = Command::new("ps")
        .arg("-axo")
        .arg("pid=,ppid=")
        .output()
        .map_err(|source| format!("could not list processes: {source}"))?;
    if !output.status.success() {
        return Err(format!("process listing exited with {}", output.status));
    }

    let mut processes = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let mut parts = line.split_whitespace();
        let (Some(pid), Some(parent_pid)) = (parts.next(), parts.next()) else {
            continue;
        };
        let (Ok(pid), Ok(parent_pid)) = (pid.parse::<i32>(), parent_pid.parse::<i32>()) else {
            continue;
        };
        processes.push((pid, parent_pid));
    }

    let mut descendants = Vec::new();
    let mut stack = vec![root_pid];
    while let Some(parent_pid) = stack.pop() {
        for (pid, candidate_parent_pid) in &processes {
            if *candidate_parent_pid == parent_pid {
                descendants.push(*pid);
                stack.push(*pid);
            }
        }
    }

    descendants.sort_unstable();
    descendants.dedup();
    Ok(descendants)
}

#[cfg(unix)]
fn parse_pid_lines(stdout: &str) -> Result<Vec<i32>, String> {
    let mut pids = Vec::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let pid = trimmed
            .parse::<i32>()
            .map_err(|source| format!("failed to parse pid `{trimmed}`: {source}"))?;
        pids.push(pid);
    }
    pids.sort_unstable();
    pids.dedup();
    Ok(pids)
}

#[cfg(windows)]
fn terminate_timed_out_self_test(child: &mut Child) -> Result<(), String> {
    let status = Command::new("taskkill")
        .arg("/PID")
        .arg(child.id().to_string())
        .arg("/T")
        .arg("/F")
        .status()
        .map_err(|source| format!("could not start taskkill: {source}"))?;
    if !status.success() {
        child.kill().map_err(|source| {
            format!("taskkill failed with {status}; direct kill failed: {source}")
        })?;
    }
    child
        .wait()
        .map_err(|source| format!("wait failed: {source}"))?;
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn terminate_timed_out_self_test(child: &mut Child) -> Result<(), String> {
    child
        .kill()
        .map_err(|source| format!("could not kill child: {source}"))?;
    child
        .wait()
        .map_err(|source| format!("wait failed: {source}"))?;
    Ok(())
}

fn load_from_skill_test_yaml(root: &Path) -> Result<Option<SkillSelfTestSpec>, SkillError> {
    let path = root.join(SKILL_TEST_FILE);
    let Some(content) = read_optional_file(&path)? else {
        return Ok(None);
    };
    let document =
        serde_yaml::from_str::<SelfTestDocument>(&content).map_err(|source| SkillError::Yaml {
            path: path.clone(),
            source,
        })?;
    normalize_raw_self_test(document.self_test, false).map(Some)
}

fn load_from_skill_yaml(root: &Path) -> Result<Option<SkillSelfTestSpec>, SkillError> {
    let path = root.join(SKILL_YAML_FILE);
    let Some(content) = read_optional_file(&path)? else {
        return Ok(None);
    };
    let document =
        serde_yaml::from_str::<RawSkillYaml>(&content).map_err(|source| SkillError::Yaml {
            path: path.clone(),
            source,
        })?;
    document
        .self_test
        .map(|raw| normalize_raw_self_test(raw, true))
        .transpose()
}

fn load_from_skill_md_frontmatter(root: &Path) -> Result<Option<SkillSelfTestSpec>, SkillError> {
    let path = root.join(SKILL_MD_FILE);
    let Some(content) = read_optional_file(&path)? else {
        return Ok(None);
    };
    let Some(frontmatter) = yaml_frontmatter(&content) else {
        return Ok(None);
    };
    if !frontmatter_contains_self_test_key(frontmatter) {
        return Ok(None);
    }
    let document =
        serde_yaml::from_str::<FrontmatterSelfTestDocument>(frontmatter).map_err(|source| {
            SkillError::Yaml {
                path: path.clone(),
                source,
            }
        })?;
    normalize_raw_self_test(document.self_test, false).map(Some)
}

fn yaml_frontmatter(content: &str) -> Option<&str> {
    let content = content.strip_prefix("---")?;
    let content = content
        .strip_prefix("\r\n")
        .or_else(|| content.strip_prefix('\n'))?;
    let marker = content.find("\n---")?;
    Some(&content[..marker])
}

fn frontmatter_contains_self_test_key(frontmatter: &str) -> bool {
    frontmatter.lines().any(|line| {
        if line.starts_with(char::is_whitespace) {
            return false;
        }
        let Some((key, _)) = line.split_once(':') else {
            return false;
        };
        let key = key.trim();
        matches!(key, "self_test" | "'self_test'" | "\"self_test\"")
    })
}

fn normalize_raw_self_test(
    raw: RawSelfTestSpec,
    allow_legacy_command: bool,
) -> Result<SkillSelfTestSpec, SkillError> {
    if raw.command.is_some() && !allow_legacy_command {
        return Err(SkillError::InvalidSelfTest {
            message: "`command` self-test shorthand is only supported in skill.yaml".to_owned(),
        });
    }
    if raw.command.is_some() && raw.assertions.is_some() {
        return Err(SkillError::InvalidSelfTest {
            message: "`command` self-test shorthand cannot be combined with assertions".to_owned(),
        });
    }
    if raw.command.is_some() && raw.blueprint.is_some() {
        return Err(SkillError::InvalidSelfTest {
            message: "`command` self-test shorthand cannot be combined with blueprint".to_owned(),
        });
    }

    let legacy_command = raw.command;
    let is_legacy_command = legacy_command.is_some();
    let runner = match raw.runner.as_deref().unwrap_or("agentenv") {
        "agentenv" => SkillSelfTestRunner::Agentenv,
        runner => {
            return Err(SkillError::InvalidSelfTest {
                message: format!("unsupported self-test runner `{runner}`"),
            });
        }
    };
    let blueprint = raw
        .blueprint
        .map(|blueprint| normalize_bundle_path(Path::new(&blueprint)))
        .transpose()?;
    let mut assertions = if let Some(command) = legacy_command {
        vec![SkillSelfTestAssertion::CommandExitsZero { cmd: command }]
    } else {
        raw.assertions.ok_or_else(|| SkillError::InvalidSelfTest {
            message: "self-test assertions are required".to_owned(),
        })?
    };

    if assertions.is_empty() {
        return Err(SkillError::InvalidSelfTest {
            message: "self-test assertions must not be empty".to_owned(),
        });
    }
    for assertion in &mut assertions {
        validate_assertion(assertion)?;
    }

    let timeout_seconds = if is_legacy_command {
        LEGACY_TIMEOUT_SECONDS
    } else {
        raw.timeout_seconds.unwrap_or(DEFAULT_TIMEOUT_SECONDS)
    };
    if timeout_seconds == 0 {
        return Err(SkillError::InvalidSelfTest {
            message: "self-test timeout_seconds must be greater than 0".to_owned(),
        });
    }

    Ok(SkillSelfTestSpec {
        runner,
        blueprint,
        assertions,
        timeout_seconds,
    })
}

fn validate_assertion(assertion: &mut SkillSelfTestAssertion) -> Result<(), SkillError> {
    match assertion {
        SkillSelfTestAssertion::CommandExitsZero { cmd } => {
            if cmd.trim().is_empty() {
                return Err(SkillError::InvalidSelfTest {
                    message: "command_exits_zero assertion requires a non-empty cmd".to_owned(),
                });
            }
        }
        SkillSelfTestAssertion::FileExists { path } => {
            *path = normalize_bundle_path(path)?;
        }
        SkillSelfTestAssertion::AgentProduces {
            prompt,
            expect_tokens_matching,
            min_match_ratio,
        } => {
            if prompt.trim().is_empty() {
                return Err(SkillError::InvalidSelfTest {
                    message: "agent_produces assertion requires a non-empty prompt".to_owned(),
                });
            }
            if expect_tokens_matching.is_empty() {
                return Err(SkillError::InvalidSelfTest {
                    message: "agent_produces assertion requires expected tokens".to_owned(),
                });
            }
            if expect_tokens_matching
                .iter()
                .any(|token| token.trim().is_empty())
            {
                return Err(SkillError::InvalidSelfTest {
                    message: "agent_produces expected tokens must not be empty".to_owned(),
                });
            }
            if !min_match_ratio.is_finite() || *min_match_ratio < 0.0 || *min_match_ratio > 1.0 {
                return Err(SkillError::InvalidSelfTest {
                    message: "agent_produces min_match_ratio must be between 0.0 and 1.0"
                        .to_owned(),
                });
            }
        }
    }

    Ok(())
}

fn read_optional_file(path: &Path) -> Result<Option<String>, SkillError> {
    match fs::read_to_string(path) {
        Ok(content) => Ok(Some(content)),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(SkillError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}
