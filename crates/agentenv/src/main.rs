use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{self, Read, Seek, SeekFrom, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    process,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use agentenv_approvals::{
    verify_payload, verify_slack_signature, ApprovalConfig, ApprovalCoordinator,
    ApprovalCoordinatorConfig, ApprovalDecisionRecord, ApprovalDecisionValue, ApprovalNotifier,
    ApprovalRequest, ApprovalRequestFilter, ApprovalScope, ApprovalStatus, ApprovalStore,
    UrlValidator,
};
use agentenv_core::admission::{AdmissionReport, AdmissionStatus, ReasonCode};
use agentenv_core::driver_catalog::{DiscoveredDriver, DriverCatalog};
use agentenv_core::hardening::HardeningLintSeverity;
use agentenv_credstore::{CredentialStore, CredentialStoreError, SecretString};
use agentenv_events::{
    audit::{AuditPolicy, AuditSigningKey, AuditStore},
    metrics::{render_prometheus, EnvMetricRow, MetricsSnapshot, SinkCounterMetric},
    sink::{JsonlSink, SqliteSink},
    store::{parse_legacy_jsonl_activity_event, EventQuery, SqliteEventStore, StoredEvent},
    ActivityEvent, ActivityKind, ActivityResult, EventDispatcher, EventEmitter, EventSink,
    SinkConfig, WebhookConfig, WebhookSink,
};
use anyhow::{bail, Context, Result};
use clap::{Args, CommandFactory, Parser, Subcommand};
use hyper::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing_subscriber::EnvFilter;

mod builtin_factory;
mod render;
mod term_backend;

const SELF_ENV_SENTINEL: &str = "__self__";

#[derive(Debug, Parser)]
#[command(
    name = "agentenv",
    about = "Declarative environments for AI coding agents",
    version = concat!("v", env!("CARGO_PKG_VERSION"))
)]
struct Cli {
    #[arg(long = "events-sink", global = true)]
    events_sink: Vec<String>,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Create(CreateArgs),
    Enter(EnterArgs),
    Resume(ResumeArgs),
    Sessions(SessionsArgs),
    List(ListArgs),
    Destroy(DestroyArgs),
    Uninstall(UninstallArgs),
    Describe(DescribeArgs),
    Status(StatusArgs),
    Logs(LogsArgs),
    Stats(StatsArgs),
    Audit(AuditArgs),
    Metrics(MetricsArgs),
    Approvals(ApprovalsArgs),
    Term(TermArgs),
    Snapshot(SnapshotArgs),
    Fork(ForkArgs),
    Exec(ExecArgs),
    Blueprint(BlueprintArgs),
    Credentials(CredentialsArgs),
    Drivers(DriversArgs),
    VerifyBlueprint {
        file: PathBuf,
    },
    Verify {
        lockfile: PathBuf,
    },
    Freeze {
        name: String,
        #[arg(long, value_name = "FILE")]
        output: Option<PathBuf>,
    },
    Reproduce(ReproduceArgs),
}

#[derive(Debug, Args)]
struct CreateArgs {
    name: String,
    #[arg(long, value_name = "FILE")]
    blueprint: Option<PathBuf>,
    #[arg(long, value_name = "FILE")]
    reproduce: Option<PathBuf>,
    #[arg(
        long = "from",
        env = "AGENTENV_FROM_DOCKERFILE",
        value_name = "DOCKERFILE"
    )]
    from: Option<PathBuf>,
    #[arg(long)]
    preflight_only: bool,
    #[arg(long)]
    json: bool,
    #[arg(
        long,
        env = "AGENTENV_NON_INTERACTIVE",
        action = clap::ArgAction::SetTrue,
        value_parser = clap::builder::BoolishValueParser::new()
    )]
    non_interactive: bool,
}

#[derive(Debug, Args)]
struct ReproduceArgs {
    lockfile: PathBuf,
    #[arg(long)]
    name: Option<String>,
    #[arg(
        long,
        env = "AGENTENV_NON_INTERACTIVE",
        action = clap::ArgAction::SetTrue,
        value_parser = clap::builder::BoolishValueParser::new()
    )]
    non_interactive: bool,
}

#[derive(Debug, Args)]
struct EnterArgs {
    name: String,
    #[arg(long)]
    detach: bool,
    #[arg(long)]
    new: bool,
}

#[derive(Debug, Args)]
struct ResumeArgs {
    name: String,
    session_id: Option<String>,
}

#[derive(Debug, Args)]
struct SessionsArgs {
    #[command(subcommand)]
    command: SessionsCommand,
}

#[derive(Debug, Subcommand)]
enum SessionsCommand {
    List(SessionsListArgs),
    Kill(SessionsKillArgs),
}

#[derive(Debug, Args)]
struct SessionsListArgs {
    env: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct SessionsKillArgs {
    session_id: String,
}

#[derive(Debug, Args)]
struct ListArgs {
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct DestroyArgs {
    name: String,
    #[arg(long)]
    yes: bool,
    #[arg(long)]
    purge_credentials: bool,
    #[arg(
        long,
        env = "AGENTENV_NON_INTERACTIVE",
        action = clap::ArgAction::SetTrue,
        value_parser = clap::builder::BoolishValueParser::new()
    )]
    non_interactive: bool,
}

#[derive(Debug, Args)]
struct UninstallArgs {
    #[arg(short = 'y', long)]
    yes: bool,
    #[arg(long)]
    keep_openshell: bool,
    #[arg(long)]
    keep_drivers: bool,
    #[arg(long)]
    keep_credentials: bool,
    #[arg(long)]
    keep_data: bool,
    #[arg(long)]
    delete_models: bool,
    #[arg(long)]
    dry_run: bool,
}

impl UninstallArgs {
    fn to_script_args(&self) -> Vec<&'static str> {
        let mut args = Vec::new();
        if self.yes {
            args.push("--yes");
        }
        if self.keep_openshell {
            args.push("--keep-openshell");
        }
        if self.keep_drivers {
            args.push("--keep-drivers");
        }
        if self.keep_credentials {
            args.push("--keep-credentials");
        }
        if self.keep_data {
            args.push("--keep-data");
        }
        if self.delete_models {
            args.push("--delete-models");
        }
        if self.dry_run {
            args.push("--dry-run");
        }
        args
    }
}

#[derive(Debug, Args)]
struct DescribeArgs {
    name: String,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct StatusArgs {
    name: String,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct LogsArgs {
    #[arg(value_name = "NAME")]
    name: Option<String>,
    #[arg(long)]
    env: Option<String>,
    #[arg(long)]
    kind: Option<String>,
    #[arg(long)]
    json: bool,
    #[arg(long)]
    follow: bool,
    #[arg(long)]
    driver: Option<String>,
}

#[derive(Debug, Args)]
struct StatsArgs {
    #[arg(long)]
    env: Option<String>,
}

#[derive(Debug, Args)]
struct AuditArgs {
    #[command(subcommand)]
    command: AuditCommand,
}

#[derive(Debug, Subcommand)]
enum AuditCommand {
    Export {
        #[arg(long)]
        from: Option<String>,
        #[arg(long)]
        to: Option<String>,
        #[arg(long, default_value_t = AuditFormat::Jsonl)]
        format: AuditFormat,
        #[arg(long)]
        env: Option<String>,
    },
    Verify {
        #[arg(long)]
        env: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum AuditFormat {
    Jsonl,
    Csv,
}

impl std::fmt::Display for AuditFormat {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Jsonl => formatter.write_str("jsonl"),
            Self::Csv => formatter.write_str("csv"),
        }
    }
}

#[derive(Debug, Args)]
struct MetricsArgs {
    #[command(subcommand)]
    command: MetricsCommand,
}

#[derive(Debug, Args)]
struct ApprovalsArgs {
    #[command(subcommand)]
    command: ApprovalsCommand,
}

#[derive(Debug, Subcommand)]
enum ApprovalsCommand {
    List(ApprovalsListArgs),
    Watch(ApprovalsWatchArgs),
    Approve(ApprovalsApproveArgs),
    Deny(ApprovalsDenyArgs),
    Serve(ApprovalsServeArgs),
}

#[derive(Debug, Args)]
struct ApprovalsListArgs {
    #[arg(long)]
    env: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ApprovalsWatchArgs {
    #[arg(long)]
    env: Option<String>,
    #[arg(long)]
    json: bool,
    #[arg(long, hide = true)]
    once: bool,
}

#[derive(Debug, Args)]
struct ApprovalsApproveArgs {
    request_id: String,
    #[arg(long)]
    env: String,
    #[arg(long)]
    scope: Option<ApprovalScopeArg>,
    #[arg(long)]
    reason: Option<String>,
}

#[derive(Debug, Args)]
struct ApprovalsDenyArgs {
    request_id: String,
    #[arg(long)]
    env: String,
    #[arg(long)]
    reason: Option<String>,
}

#[derive(Debug, Args)]
struct ApprovalsServeArgs {
    #[arg(long, default_value = "127.0.0.1:9181")]
    addr: String,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum ApprovalScopeArg {
    Once,
    Session,
    PersistSandbox,
    ProposeForBaseline,
}

impl From<ApprovalScopeArg> for ApprovalScope {
    fn from(value: ApprovalScopeArg) -> Self {
        match value {
            ApprovalScopeArg::Once => Self::Once,
            ApprovalScopeArg::Session => Self::Session,
            ApprovalScopeArg::PersistSandbox => Self::PersistSandbox,
            ApprovalScopeArg::ProposeForBaseline => Self::ProposeForBaseline,
        }
    }
}

#[derive(Debug, Subcommand)]
enum MetricsCommand {
    Serve {
        #[arg(long, default_value_t = 9180)]
        port: u16,
    },
}

#[derive(Debug, Args)]
struct ExecArgs {
    name: String,
    #[arg(last = true, required = true)]
    cmd: Vec<String>,
}

#[derive(Debug, Args)]
#[command(after_long_help = "\
Key bindings:
  [Tab] switch pane
  [Shift+Tab] switch pane backward
  [j]/[k] move selection
  [a-z] jump env
  [A] approvals
  [a]/[y] allow selected approval
  [d]/[n] deny selected approval
  [L] logs
  [P] policy
  [?] help
  [:] command mode
  :destroy <env>
  [q] quit")]
struct TermArgs {
    #[arg(long)]
    no_color: bool,
    #[arg(long, value_name = "ENDPOINT")]
    remote: Option<String>,
    #[arg(long, hide = true)]
    once: bool,
}

#[derive(Debug, Args)]
struct SnapshotArgs {
    #[command(subcommand)]
    command: Option<SnapshotCommand>,
    #[arg(value_name = "ENV")]
    env: Option<String>,
    #[arg(long, value_name = "PATH", requires = "env")]
    output: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum SnapshotCommand {
    Verify { path: PathBuf },
    Restore(SnapshotRestoreCliArgs),
}

#[derive(Debug, Args)]
struct SnapshotRestoreCliArgs {
    path: PathBuf,
    #[arg(long = "as", value_name = "NEW_NAME")]
    as_name: Option<String>,
    #[arg(
        long,
        env = "AGENTENV_NON_INTERACTIVE",
        action = clap::ArgAction::SetTrue,
        value_parser = clap::builder::BoolishValueParser::new()
    )]
    non_interactive: bool,
}

#[derive(Debug, Args)]
struct ForkArgs {
    #[arg(value_name = "SOURCE")]
    source: String,
    #[arg(long, value_name = "NEW_ENV")]
    name: String,
}

#[derive(Debug, Args)]
struct BlueprintArgs {
    #[command(subcommand)]
    command: BlueprintCommand,
}

#[derive(Debug, Subcommand)]
enum BlueprintCommand {
    Lint(BlueprintLintArgs),
}

#[derive(Debug, Args)]
struct BlueprintLintArgs {
    file: PathBuf,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct CredentialsArgs {
    #[command(subcommand)]
    command: CredentialCommand,
}

#[derive(Debug, Args)]
struct DriversArgs {
    #[command(subcommand)]
    command: DriverCommand,
}

#[derive(Debug, Subcommand)]
enum DriverCommand {
    /// Lists built-in and discovered subprocess drivers.
    List,
}

#[derive(Debug, Subcommand)]
enum CredentialCommand {
    /// Lists credential names only.
    List,
    /// Removes a credential from storage.
    Reset {
        /// Credential name, for example ANTHROPIC_API_KEY.
        name: String,
    },
    /// Stores a credential value (interactive by default).
    Set {
        /// Credential name, for example ANTHROPIC_API_KEY.
        name: String,
        /// Read the value from an environment variable.
        /// When omitted: prompts interactively.
        /// When passed without a value: uses <name> as the environment variable.
        #[arg(
            long,
            num_args = 0..=1,
            default_missing_value = SELF_ENV_SENTINEL,
            value_name = "ENV_VAR"
        )]
        from_env: Option<String>,
    },
    /// Reports which backend currently resolves a credential.
    Where {
        /// Credential name, for example ANTHROPIC_API_KEY.
        name: String,
    },
}

#[tokio::main]
async fn main() {
    init_tracing();
    if let Err(error) = run().await {
        eprintln!("error: {error:#}");
        exit_process(1);
    }
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .with_target(false)
        .with_writer(std::io::stderr)
        .try_init();
}

async fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Some(Commands::Create(args)) => run_create(args, &cli.events_sink).await,
        Some(Commands::Enter(args)) => run_enter(args).await,
        Some(Commands::Resume(args)) => run_resume(args).await,
        Some(Commands::Sessions(args)) => run_sessions(args).await,
        Some(Commands::List(args)) => run_list(args),
        Some(Commands::Destroy(args)) => run_destroy(args, &cli.events_sink).await,
        Some(Commands::Uninstall(args)) => run_uninstall(args),
        Some(Commands::Describe(args)) => run_describe(args),
        Some(Commands::Status(args)) => run_status(args).await,
        Some(Commands::Logs(args)) => run_logs(args).await,
        Some(Commands::Stats(args)) => run_stats(args),
        Some(Commands::Audit(args)) => run_audit(args),
        Some(Commands::Metrics(args)) => run_metrics(args).await,
        Some(Commands::Approvals(args)) => run_approvals(args, &cli.events_sink).await,
        Some(Commands::Snapshot(args)) => run_snapshot(args).await,
        Some(Commands::Fork(args)) => run_fork(args).await,
        Some(Commands::Exec(args)) => run_exec(args, &cli.events_sink).await,
        Some(Commands::Term(args)) => run_term(args).await,
        Some(Commands::Blueprint(command)) => run_blueprint(command),
        Some(Commands::Credentials(command)) => run_credentials(command, &cli.events_sink).await,
        Some(Commands::Drivers(command)) => run_drivers(command),
        Some(Commands::VerifyBlueprint { file }) => verify_blueprint(&file),
        Some(Commands::Verify { lockfile }) => verify_lockfile(&lockfile),
        Some(Commands::Freeze { name, output }) => freeze(&name, output.as_deref()),
        Some(Commands::Reproduce(args)) => reproduce(args).await,
        None => {
            let mut command = Cli::command();
            command.print_help().context("print help output")?;
            println!();
            Ok(())
        }
    }
}

fn run_uninstall(args: UninstallArgs) -> Result<()> {
    let script = resolve_uninstall_script()?;
    let current_exe = std::env::current_exe().ok();
    let mut command = process::Command::new("sh");
    command.arg(&script.path).args(args.to_script_args());
    if std::env::var_os("AGENTENV_BIN").is_none() {
        if let Some(path) = &current_exe {
            command.env("AGENTENV_BIN", path);
        }
    }
    if std::env::var_os("AGENTENV_INSTALL_DIR").is_none() {
        if let Some(dir) = current_exe.as_ref().and_then(|path| path.parent()) {
            command.env("AGENTENV_INSTALL_DIR", dir);
        }
    }
    let status = command.status();
    script.cleanup_best_effort();
    let status = status
        .with_context(|| format!("failed to run uninstall script `{}`", script.path.display()))?;

    match status.code() {
        Some(0) => Ok(()),
        Some(code) => exit_process(code),
        None => bail!(
            "uninstall script `{}` terminated by signal",
            script.path.display()
        ),
    }
}

struct ResolvedUninstallScript {
    path: PathBuf,
    cleanup_dir: Option<PathBuf>,
}

impl ResolvedUninstallScript {
    fn local(path: PathBuf) -> Self {
        Self {
            path,
            cleanup_dir: None,
        }
    }

    fn downloaded(path: PathBuf, cleanup_dir: PathBuf) -> Self {
        Self {
            path,
            cleanup_dir: Some(cleanup_dir),
        }
    }

    fn cleanup_best_effort(&self) {
        if let Some(dir) = &self.cleanup_dir {
            let _ = fs::remove_dir_all(dir);
        }
    }
}

fn resolve_uninstall_script() -> Result<ResolvedUninstallScript> {
    if let Some(script) = std::env::var_os("AGENTENV_UNINSTALL_SCRIPT") {
        let script = PathBuf::from(script);
        if script.is_file() {
            return Ok(ResolvedUninstallScript::local(script));
        }
        bail!(
            "AGENTENV_UNINSTALL_SCRIPT points to `{}`, which is not a file",
            script.display()
        );
    }

    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(exe_dir) = current_exe.parent() {
            let script = exe_dir.join("uninstall.sh");
            if script.is_file() {
                return Ok(ResolvedUninstallScript::local(script));
            }
        }
    }

    download_hosted_uninstall_script()
}

fn download_hosted_uninstall_script() -> Result<ResolvedUninstallScript> {
    let repo = std::env::var("AGENTENV_REPO").unwrap_or_else(|_| "windoliver/agentenv".to_owned());
    let base_url = std::env::var("AGENTENV_RELEASE_BASE_URL")
        .unwrap_or_else(|_| format!("https://github.com/{repo}/releases/download"));
    let version = hosted_uninstall_version();
    let base_url = base_url.trim_end_matches('/');
    let script_url = format!("{base_url}/{version}/uninstall.sh");
    let checksum_url = format!("{base_url}/{version}/uninstall.sh.sha256");

    let download_dir = make_uninstall_download_dir()?;
    let download_guard = UninstallDownloadGuard::new(download_dir.clone());
    let script_path = download_dir.join("uninstall.sh");
    let checksum_path = download_dir.join("uninstall.sh.sha256");

    download_url_to_file(&script_url, &script_path)
        .with_context(|| format!("download uninstall script from `{script_url}`"))?;
    download_url_to_file(&checksum_url, &checksum_path)
        .with_context(|| format!("download uninstall checksum from `{checksum_url}`"))?;
    verify_file_sha256(&script_path, &checksum_path)?;

    let cleanup_dir = download_guard.keep();
    Ok(ResolvedUninstallScript::downloaded(
        script_path,
        cleanup_dir,
    ))
}

fn hosted_uninstall_version() -> String {
    let default = || format!("v{}", env!("CARGO_PKG_VERSION"));
    let Ok(version) = std::env::var("AGENTENV_VERSION") else {
        return default();
    };
    let version = version.trim();
    if version.is_empty() {
        return default();
    }
    version
        .strip_prefix("refs/tags/")
        .unwrap_or(version)
        .to_owned()
}

struct UninstallDownloadGuard {
    path: PathBuf,
    keep: bool,
}

impl UninstallDownloadGuard {
    fn new(path: PathBuf) -> Self {
        Self { path, keep: false }
    }

    fn keep(mut self) -> PathBuf {
        self.keep = true;
        self.path.clone()
    }
}

impl Drop for UninstallDownloadGuard {
    fn drop(&mut self) {
        if !self.keep {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

fn make_uninstall_download_dir() -> Result<PathBuf> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time is before UNIX_EPOCH")?
        .as_nanos();
    let path = std::env::temp_dir().join(format!("agentenv-uninstall-{}-{now}", process::id()));
    fs::create_dir(&path).with_context(|| {
        format!(
            "failed to create uninstall download directory `{}`",
            path.display()
        )
    })?;
    Ok(path)
}

fn download_url_to_file(url: &str, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create download destination directory `{}`",
                parent.display()
            )
        })?;
    }

    let curl_status = process::Command::new("curl")
        .args(["-fsSL", "-o"])
        .arg(path)
        .arg(url)
        .status();
    if matches!(curl_status, Ok(status) if status.success()) {
        return Ok(());
    }

    let wget_status = process::Command::new("wget")
        .args(["-q", "-O"])
        .arg(path)
        .arg(url)
        .status();
    if matches!(wget_status, Ok(status) if status.success()) {
        return Ok(());
    }

    bail!("failed to download `{url}` with curl or wget");
}

fn verify_file_sha256(file_path: &Path, checksum_path: &Path) -> Result<()> {
    let checksum = fs::read_to_string(checksum_path)
        .with_context(|| format!("failed to read checksum `{}`", checksum_path.display()))?;
    let expected = checksum
        .split_whitespace()
        .next()
        .context("checksum file is empty")?
        .to_ascii_lowercase();

    let mut file = fs::File::open(file_path)
        .with_context(|| format!("failed to open downloaded file `{}`", file_path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("failed to read `{}`", file_path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let actual = hex::encode(hasher.finalize());
    if actual != expected {
        bail!(
            "checksum mismatch for `{}`: expected {expected}, got {actual}",
            file_path.display()
        );
    }

    Ok(())
}

async fn run_create(args: CreateArgs, event_sink_args: &[String]) -> Result<()> {
    let options = runtime_options(args.non_interactive)?;
    let cwd = std::env::current_dir().context("failed to determine current working directory")?;
    let blueprint_path = match resolve_create_blueprint_path(
        args.blueprint.as_deref(),
        args.reproduce.as_deref(),
        &cwd,
    ) {
        Ok(path) => path,
        Err(error) if args.json => {
            let reason_code = if args.reproduce.is_some() {
                ReasonCode::ReproduceBlueprintMissing
            } else {
                ReasonCode::InvalidBlueprint
            };
            exit_json_error(reason_code, error);
        }
        Err(error) => return Err(error),
    };
    let blueprint_yaml = match read_text_file(&blueprint_path, "blueprint") {
        Ok(yaml) => yaml,
        Err(error) if args.json => exit_json_error(ReasonCode::InvalidBlueprint, error),
        Err(error) => return Err(error),
    };
    let blueprint_yaml = match args.from.as_deref() {
        Some(from) => match overlay_from_dockerfile(&blueprint_yaml, from, &cwd) {
            Ok(yaml) => yaml,
            Err(error) if args.json => exit_json_error(ReasonCode::InvalidBlueprint, error),
            Err(error) => return Err(error),
        },
        None => blueprint_yaml,
    };
    let factory = builtin_factory::BuiltInDriverFactory;

    if args.preflight_only {
        let resolved = match agentenv_core::lifecycle::verify_blueprint_yaml(&blueprint_yaml) {
            Ok(resolved) => resolved,
            Err(error) if args.json => exit_json_error(ReasonCode::InvalidBlueprint, error),
            Err(error) => return Err(error.into()),
        };
        let selection = agentenv_core::runtime::DriverSelection {
            sandbox: resolved.sandbox.driver,
            agent: resolved.agent.driver,
            context: resolved.context.driver,
            inference: resolved.inference.map(|driver| driver.driver),
        };
        match agentenv_core::runtime::run_preflight_only(&options, &factory, &args.name, &selection)
            .await
            .map(|mut report| {
                agentenv_core::runtime::add_byo_dockerfile_preflight_warnings(
                    &mut report,
                    &resolved.blueprint.sandbox.extra,
                );
                report
            }) {
            Ok(report) if args.json => {
                render::print_json(&report)?;
                if report.status == agentenv_core::admission::AdmissionStatus::Rejected {
                    exit_process(report.exit_class().code());
                }
                Ok(())
            }
            Ok(report) => {
                render::print_admission_text(&report);
                if report.status == agentenv_core::admission::AdmissionStatus::Rejected {
                    exit_process(report.exit_class().code());
                }
                Ok(())
            }
            Err(error) if args.json => {
                render::print_error_json(&error);
                exit_process(render::exit_for_error(&error).code());
            }
            Err(error) => Err(error.into()),
        }
    } else {
        let dispatcher = build_event_dispatcher(&options, Some(&args.name), event_sink_args)?;
        let emitter = Arc::new(AuditingEventEmitter::new(
            dispatcher.emitter(),
            audit_signing_key_path(&options),
            audit_write_db_paths(&options, Some(&args.name))?,
        ));
        let store = CredentialStore::from_default_paths().context("initialize credential store")?;
        let mut provider = CliCredentialProvider {
            store,
            non_interactive: args.non_interactive,
            prompter: Box::new(TerminalCredentialPrompter),
        };
        match agentenv_core::runtime::create_env_observed(
            &options,
            &factory,
            &mut provider,
            &args.name,
            &blueprint_yaml,
            Arc::clone(&emitter) as Arc<dyn EventEmitter>,
        )
        .await
        {
            Ok(result) if args.json => {
                emitter.check_audit()?;
                flush_dispatcher_best_effort(&dispatcher).await;
                render::print_json(&result.admission)?;
                exit_if_rejected(&result.admission);
                Ok(())
            }
            Ok(result) => {
                emitter.check_audit()?;
                flush_dispatcher_best_effort(&dispatcher).await;
                render::print_admission_text(&result.admission);
                exit_if_rejected(&result.admission);
                println!("Next: agentenv enter {}", args.name);
                Ok(())
            }
            Err(error) if args.json => {
                flush_dispatcher_best_effort(&dispatcher).await;
                if let Err(audit_error) = emitter.check_audit() {
                    exit_json_error(
                        ReasonCode::DriverCommandFailed,
                        audit_error_after_original(audit_error, &error),
                    );
                }
                render::print_error_json(&error);
                exit_process(render::exit_for_error(&error).code());
            }
            Err(error) => {
                flush_dispatcher_best_effort(&dispatcher).await;
                if let Err(audit_error) = emitter.check_audit() {
                    return Err(audit_error_after_original(audit_error, &error));
                }
                Err(error.into())
            }
        }
    }
}

async fn run_enter(args: EnterArgs) -> Result<()> {
    let options = runtime_options(true)?;
    match agentenv_core::runtime::enter_env(
        &options,
        &builtin_factory::BuiltInDriverFactory,
        &args.name,
        args.detach,
        args.new,
    )
    .await?
    {
        agentenv_core::runtime::EnterResult::Detached(shell) => {
            println!("{}", shell.session_id);
            Ok(())
        }
        agentenv_core::runtime::EnterResult::Attached(result) => {
            print!("{}", result.stdout);
            eprint!("{}", result.stderr);
            io::stdout().flush().context("flush forwarded stdout")?;
            io::stderr().flush().context("flush forwarded stderr")?;
            process::exit(result.status);
        }
    }
}

async fn run_resume(args: ResumeArgs) -> Result<()> {
    let options = runtime_options(true)?;
    let result = agentenv_core::runtime::resume_env(
        &options,
        &builtin_factory::BuiltInDriverFactory,
        &args.name,
        args.session_id.as_deref(),
    )
    .await?;
    print!("{}", result.stdout);
    eprint!("{}", result.stderr);
    io::stdout().flush().context("flush forwarded stdout")?;
    io::stderr().flush().context("flush forwarded stderr")?;
    process::exit(result.status);
}

async fn run_sessions(args: SessionsArgs) -> Result<()> {
    match args.command {
        SessionsCommand::List(args) => run_sessions_list(args).await,
        SessionsCommand::Kill(args) => run_sessions_kill(args).await,
    }
}

async fn run_sessions_list(args: SessionsListArgs) -> Result<()> {
    let options = runtime_options(true)?;
    match agentenv_core::runtime::list_sessions_env(
        &options,
        &builtin_factory::BuiltInDriverFactory,
        args.env.as_deref(),
    )
    .await
    {
        Ok(rows) if args.json => render::print_json(&render::SessionsJson { sessions: rows }),
        Ok(rows) => {
            render::print_sessions_text(&rows);
            Ok(())
        }
        Err(error) if args.json => {
            render::print_error_json(&error);
            exit_process(render::exit_for_error(&error).code());
        }
        Err(error) => Err(error.into()),
    }
}

async fn run_sessions_kill(args: SessionsKillArgs) -> Result<()> {
    let options = runtime_options(true)?;
    agentenv_core::runtime::kill_session_env(
        &options,
        &builtin_factory::BuiltInDriverFactory,
        &args.session_id,
    )
    .await?;
    println!("killed: {}", args.session_id);
    Ok(())
}

fn run_list(args: ListArgs) -> Result<()> {
    let options = runtime_options(true)?;
    match agentenv_core::runtime::list_envs(&options) {
        Ok(rows) if args.json => render::print_json(&render::ListJson { envs: rows }),
        Ok(rows) => {
            render::print_list_text(&rows);
            Ok(())
        }
        Err(error) if args.json => {
            render::print_error_json(&error);
            exit_process(render::exit_for_error(&error).code());
        }
        Err(error) => Err(error.into()),
    }
}

async fn run_destroy(args: DestroyArgs, event_sink_args: &[String]) -> Result<()> {
    let options = runtime_options(true)?;
    if !args.yes {
        confirm_destroy(&args.name, args.non_interactive)?;
    }
    let purge_credentials = if args.purge_credentials {
        agentenv_core::runtime::describe_env(&options, &args.name)?
            .state
            .credential_names
    } else {
        Vec::new()
    };
    let dispatcher = build_destroy_event_dispatcher(&options, event_sink_args)?;
    let emitter = Arc::new(AuditingEventEmitter::new(
        dispatcher.emitter(),
        audit_signing_key_path(&options),
        audit_destroy_write_db_paths(&options)?,
    ));
    let report = match agentenv_core::runtime::destroy_env_observed(
        &options,
        &builtin_factory::BuiltInDriverFactory,
        &args.name,
        Arc::clone(&emitter) as Arc<dyn EventEmitter>,
    )
    .await
    {
        Ok(report) => {
            emitter.check_audit()?;
            flush_dispatcher_best_effort(&dispatcher).await;
            report
        }
        Err(error) => {
            flush_dispatcher_best_effort(&dispatcher).await;
            if let Err(audit_error) = emitter.check_audit() {
                return Err(audit_error_after_original(audit_error, &error));
            }
            return Err(error.into());
        }
    };
    if args.purge_credentials {
        purge_state_credentials(&purge_credentials)?;
    }
    render::print_admission_text(&report);
    Ok(())
}

fn run_describe(args: DescribeArgs) -> Result<()> {
    let options = runtime_options(true)?;
    match agentenv_core::runtime::describe_env(&options, &args.name) {
        Ok(description) if args.json => render::print_json(&description),
        Ok(description) => {
            render::print_describe_text(&description);
            Ok(())
        }
        Err(error) if args.json => {
            render::print_error_json(&error);
            exit_process(render::exit_for_error(&error).code());
        }
        Err(error) => Err(error.into()),
    }
}

async fn run_status(args: StatusArgs) -> Result<()> {
    let options = runtime_options(true)?;
    let status = agentenv_core::runtime::status_env(
        &options,
        &builtin_factory::BuiltInDriverFactory,
        &args.name,
    )
    .await?;
    if args.json {
        render::print_json(&render::StatusJson {
            healthy: status.healthy,
            status: status.clone(),
        })?;
    } else {
        println!("healthy: {}", status.healthy);
    }
    if !status.healthy {
        exit_process(agentenv_core::admission::ExitClass::Unhealthy.code());
    }
    Ok(())
}

async fn run_logs(args: LogsArgs) -> Result<()> {
    let options = runtime_options(true)?;
    let use_activity_logs = args.env.is_some() || args.kind.is_some() || args.json;
    let name = args
        .env
        .as_deref()
        .or(args.name.as_deref())
        .context("logs requires an environment name or --env <name>")?;
    if let Some(driver) = args.driver.as_deref().filter(|driver| *driver != "sandbox") {
        print_event_logs(&options, name, Some(driver), args.follow)?;
        return Ok(());
    }
    if use_activity_logs {
        print_activity_logs(&options, name, args.kind.as_deref(), args.json, args.follow).await?;
        return Ok(());
    }
    if args.follow {
        let _guard = agentenv_core::runtime::start_logs_stream_env(
            &options,
            &builtin_factory::BuiltInDriverFactory,
            name,
        )
        .await?;
        tokio::signal::ctrl_c()
            .await
            .context("wait for log stream interrupt")?;
        return Ok(());
    }
    let logs = agentenv_core::runtime::logs_env(
        &options,
        &builtin_factory::BuiltInDriverFactory,
        name,
        args.follow,
    )
    .await?;
    for entry in logs.entries {
        println!("{} {:?} {}", entry.ts, entry.level, entry.msg);
    }
    Ok(())
}

fn run_stats(args: StatsArgs) -> Result<()> {
    let options = runtime_options(true)?;
    let env_filter = args.env.as_deref();
    if let Some(env) = env_filter {
        agentenv_core::env::validate_env_name(env)?;
    }
    let db_path = activity_stats_reader_db_path(&options, env_filter)?;
    let store = SqliteEventStore::open(&db_path)
        .with_context(|| format!("open activity database `{}`", db_path.display()))?;

    let scope = env_filter.unwrap_or("global");
    println!("activity summary for {scope}");
    println!("kind/result counts:");
    for row in store.counts_by_kind_result()? {
        if env_filter.is_none_or(|env| row.env.as_deref() == Some(env)) {
            println!(
                "  {} {} {}",
                activity_kind_label(row.kind),
                activity_result_label(row.result),
                row.count
            );
        }
    }

    println!("policy blocks:");
    for row in store.policy_blocks_by_kind_driver_for_env(env_filter)? {
        println!(
            "  {} {} {}",
            row.kind,
            row.driver.as_deref().unwrap_or("-"),
            row.count
        );
    }

    println!(
        "pending approvals: {}",
        store.approvals_pending_count_for_env(env_filter)?
    );
    let latency_rows = store.sandbox_latency_rows_for_env(env_filter)?;
    if latency_rows.is_empty() {
        println!("latency: none");
    } else {
        let count = latency_rows.len() as u64;
        let sum = latency_rows.iter().map(|row| row.latency_ms).sum::<u64>();
        let max = latency_rows
            .iter()
            .map(|row| row.latency_ms)
            .max()
            .unwrap_or(0);
        println!("latency: count={count} avg_ms={} max_ms={max}", sum / count);
    }
    println!("sink drops/errors: unavailable");
    Ok(())
}

fn run_audit(args: AuditArgs) -> Result<()> {
    let options = runtime_options(true)?;
    match args.command {
        AuditCommand::Export {
            from,
            to,
            format,
            env,
        } => {
            let store = AuditStore::open(audit_reader_db_path(&options, env.as_deref())?)
                .with_context(|| audit_store_context(env.as_deref()))?;
            let stdout = io::stdout();
            let mut handle = stdout.lock();
            match format {
                AuditFormat::Jsonl => store.export_jsonl_range_for_env(
                    &mut handle,
                    from.as_deref(),
                    to.as_deref(),
                    env.as_deref(),
                )?,
                AuditFormat::Csv => store.export_csv_range_for_env(
                    &mut handle,
                    from.as_deref(),
                    to.as_deref(),
                    env.as_deref(),
                )?,
            }
            Ok(())
        }
        AuditCommand::Verify { env } => {
            let store = AuditStore::open(audit_reader_db_path(&options, env.as_deref())?)
                .with_context(|| audit_store_context(env.as_deref()))?;
            let scoped_count = env
                .as_deref()
                .map(|env| store.count_entries_for_env(env))
                .transpose()?;
            if scoped_count == Some(0) {
                println!("valid: 0 entries checked");
                return Ok(());
            }
            let report = store.verify()?;
            if report.valid {
                println!(
                    "valid: {} entries checked",
                    scoped_count.unwrap_or(report.checked_entries)
                );
                Ok(())
            } else {
                println!(
                    "invalid: {} entries checked, first invalid sequence {}",
                    report.checked_entries,
                    report
                        .first_invalid_sequence
                        .map(|sequence| sequence.to_string())
                        .unwrap_or_else(|| "-".to_owned())
                );
                exit_process(1);
            }
        }
    }
}

async fn run_metrics(args: MetricsArgs) -> Result<()> {
    match args.command {
        MetricsCommand::Serve { port } => serve_metrics(port).await,
    }
}

fn pending_approval_rows_all_envs(
    options: &agentenv_core::runtime::RuntimeOptions,
) -> Result<Vec<render::ApprovalRowJson>> {
    let mut rows = Vec::new();
    for env in approval_env_names(options)? {
        if !approval_store_exists(options, &env)? {
            continue;
        }
        rows.extend(pending_approval_rows(options, &env)?);
    }
    Ok(rows)
}

fn approval_store_exists(
    options: &agentenv_core::runtime::RuntimeOptions,
    env: &str,
) -> Result<bool> {
    let db_path = agentenv_core::runtime::env_events_db_path(options, env)?;
    match fs::symlink_metadata(&db_path) {
        Ok(_) => Ok(true),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(source)
            .with_context(|| format!("inspect approval database `{}`", db_path.display())),
    }
}

fn approval_env_names(options: &agentenv_core::runtime::RuntimeOptions) -> Result<Vec<String>> {
    Ok(agentenv_core::runtime::list_envs(options)?
        .into_iter()
        .map(|row| row.name)
        .collect())
}

async fn run_approvals(args: ApprovalsArgs, event_sink_args: &[String]) -> Result<()> {
    let options = runtime_options(true)?;
    match args.command {
        ApprovalsCommand::List(args) => {
            let env = args
                .env
                .as_deref()
                .context("approvals list requires --env <name>")?;
            let rows = pending_approval_rows(&options, env)?;
            print_approval_rows(&rows, args.json)
        }
        ApprovalsCommand::Watch(args) => run_approvals_watch(&options, args).await,
        ApprovalsCommand::Approve(args) => {
            let decision = ApprovalDecisionValue::Allow;
            let record = decide_approval(
                &options,
                &args.env,
                &args.request_id,
                decision,
                args.scope.map(Into::into),
                args.reason,
                event_sink_args,
            )
            .await?;
            ensure_requested_decision(&record, decision)?;
            println!("approved: {}", args.request_id);
            Ok(())
        }
        ApprovalsCommand::Deny(args) => {
            let decision = ApprovalDecisionValue::Deny;
            let record = decide_approval(
                &options,
                &args.env,
                &args.request_id,
                decision,
                Some(ApprovalScope::Once),
                args.reason,
                event_sink_args,
            )
            .await?;
            ensure_requested_decision(&record, decision)?;
            println!("denied: {}", args.request_id);
            Ok(())
        }
        ApprovalsCommand::Serve(args) => serve_approvals(args, event_sink_args).await,
    }
}

fn ensure_requested_decision(
    record: &ApprovalDecisionRecord,
    requested: ApprovalDecisionValue,
) -> Result<()> {
    if record.decision != requested {
        bail!(
            "approval request {} already decided as {}",
            record.request_id,
            approval_decision_label(record.decision)
        );
    }
    Ok(())
}

fn approval_decision_label(decision: ApprovalDecisionValue) -> &'static str {
    match decision {
        ApprovalDecisionValue::Allow => "allow",
        ApprovalDecisionValue::Deny => "deny",
    }
}

async fn run_approvals_watch(
    options: &agentenv_core::runtime::RuntimeOptions,
    args: ApprovalsWatchArgs,
) -> Result<()> {
    let env = args
        .env
        .as_deref()
        .context("approvals watch requires --env <name>")?;
    loop {
        let rows = pending_approval_rows(options, env)?;
        print_approval_rows(&rows, args.json)?;
        if args.once {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

fn pending_approval_rows(
    options: &agentenv_core::runtime::RuntimeOptions,
    env: &str,
) -> Result<Vec<render::ApprovalRowJson>> {
    let store = open_approval_store(options, env)?;
    let requests = store
        .list_requests(ApprovalRequestFilter {
            env: Some(env.to_owned()),
            status: Some(ApprovalStatus::Pending),
        })
        .with_context(|| format!("list pending approval requests for `{env}`"))?;
    Ok(requests
        .iter()
        .map(render::ApprovalRowJson::from_request)
        .collect())
}

fn print_approval_rows(rows: &[render::ApprovalRowJson], json: bool) -> Result<()> {
    if json {
        render::print_json(&render::ApprovalsListJson {
            approvals: rows.to_vec(),
        })
    } else {
        render::print_approval_rows_text(rows);
        Ok(())
    }
}

async fn decide_approval(
    options: &agentenv_core::runtime::RuntimeOptions,
    env: &str,
    request_id: &str,
    decision: ApprovalDecisionValue,
    scope: Option<ApprovalScope>,
    reason: Option<String>,
    event_sink_args: &[String],
) -> Result<ApprovalDecisionRecord> {
    decide_approval_as(
        options,
        env,
        request_id,
        decision,
        scope,
        reason,
        "agentenv:cli".to_owned(),
        "cli",
        event_sink_args,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn decide_approval_as(
    options: &agentenv_core::runtime::RuntimeOptions,
    env: &str,
    request_id: &str,
    decision: ApprovalDecisionValue,
    scope: Option<ApprovalScope>,
    reason: Option<String>,
    decided_by: String,
    source: &str,
    event_sink_args: &[String],
) -> Result<ApprovalDecisionRecord> {
    let store = open_approval_store(options, env)?;
    let request = store
        .get_request(request_id)
        .with_context(|| format!("load approval request `{request_id}`"))?
        .with_context(|| format!("approval request `{request_id}` was not found"))?;
    let scope = scope.unwrap_or(request.default_scope);
    let dispatcher = build_event_dispatcher(options, Some(env), event_sink_args)?;
    let emitter = Arc::new(AuditingEventEmitter::new(
        dispatcher.emitter(),
        audit_signing_key_path(options),
        audit_write_db_paths(options, Some(env))?,
    ));
    let coordinator = approval_coordinator(
        options,
        env,
        store,
        Arc::clone(&emitter) as Arc<dyn EventEmitter>,
    )?;
    let record = ApprovalDecisionRecord {
        request_id: request.id.clone(),
        decision,
        scope,
        decided_by,
        decided_at: ::time::OffsetDateTime::now_utc(),
        reason,
        context: serde_json::json!({"source": source}),
        trace_id: new_cli_trace_id(),
    };

    match coordinator.decide(record).await {
        Ok(record) => {
            emitter.check_audit()?;
            flush_dispatcher_best_effort(&dispatcher).await;
            Ok(record)
        }
        Err(error) => {
            flush_dispatcher_best_effort(&dispatcher).await;
            if let Err(audit_error) = emitter.check_audit() {
                return Err(audit_error_after_original(audit_error, &error));
            }
            Err(error).with_context(|| format!("record approval decision for `{request_id}`"))
        }
    }
}

fn approval_coordinator(
    options: &agentenv_core::runtime::RuntimeOptions,
    env: &str,
    store: ApprovalStore,
    events: Arc<dyn EventEmitter>,
) -> Result<ApprovalCoordinator> {
    Ok(ApprovalCoordinator::new(ApprovalCoordinatorConfig {
        store,
        events,
        poll_interval: Duration::from_millis(250),
        overlay_path: Some(agentenv_core::runtime::env_approval_overlay_path(
            options, env,
        )?),
        proposal_path: Some(agentenv_core::runtime::env_approval_proposals_path(
            options, env,
        )?),
        notifications: approval_notifications(options)?,
    }))
}

fn approval_notifications(
    options: &agentenv_core::runtime::RuntimeOptions,
) -> Result<Option<Arc<ApprovalNotifier>>> {
    let config = ApprovalConfig::load(&approval_config_path(options)).with_context(|| {
        format!(
            "load approval config `{}`",
            approval_config_path(options).display()
        )
    })?;
    Ok(ApprovalNotifier::from_config(config, approval_url_validator())?.map(Arc::new))
}

fn approval_url_validator() -> UrlValidator {
    Arc::new(|raw_url| {
        let url = url::Url::parse(raw_url).map_err(|error| error.to_string())?;
        agentenv_core::security::ssrf::validate_outbound(
            &url,
            agentenv_core::security::ssrf::SsrfOptions::default(),
        )
        .map(|_| ())
        .map_err(|error| error.to_string())
    })
}

fn open_approval_store(
    options: &agentenv_core::runtime::RuntimeOptions,
    env: &str,
) -> Result<ApprovalStore> {
    let db_path = agentenv_core::runtime::env_events_db_path(options, env)?;
    ApprovalStore::open(&db_path)
        .with_context(|| format!("open approval database `{}`", db_path.display()))
}

#[derive(Clone)]
struct ApprovalServerState {
    options: agentenv_core::runtime::RuntimeOptions,
    config: ApprovalConfig,
    event_sink_args: Arc<Vec<String>>,
}

struct HttpRequest {
    method: Option<Method>,
    path: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

struct HttpResponse {
    status: StatusCode,
    content_type: &'static str,
    body: String,
}

#[derive(Deserialize)]
struct CallbackDecisionBody {
    request_id: String,
    decision: CallbackDecisionValue,
    scope: Option<ApprovalScope>,
    decided_by: String,
    reason: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum CallbackDecisionValue {
    Allow,
    Deny,
}

#[derive(Deserialize)]
struct SlackInteractionPayload {
    user: Option<SlackInteractionUser>,
    actions: Vec<SlackInteractionAction>,
}

#[derive(Deserialize)]
struct SlackInteractionUser {
    id: Option<String>,
    username: Option<String>,
    name: Option<String>,
}

#[derive(Deserialize)]
struct SlackInteractionAction {
    value: Option<String>,
}

struct SlackActionDecision {
    request_id: String,
    decision: ApprovalDecisionValue,
    scope: Option<ApprovalScope>,
}

const MAX_APPROVAL_HTTP_REQUEST_BYTES: usize = 64 * 1024;

async fn serve_approvals(args: ApprovalsServeArgs, event_sink_args: &[String]) -> Result<()> {
    let options = runtime_options(true)?;
    let addr = args
        .addr
        .parse::<SocketAddr>()
        .with_context(|| format!("invalid approvals server address `{}`", args.addr))?;
    let config = ApprovalConfig::load(&approval_config_path(&options))
        .context("load approval callback config")?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind approvals listener on {addr}"))?;
    let state = ApprovalServerState {
        options,
        config,
        event_sink_args: Arc::new(event_sink_args.to_vec()),
    };

    loop {
        let (stream, _) = listener
            .accept()
            .await
            .context("accept approvals callback request")?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_approvals_connection(stream, state).await {
                tracing::warn!(%error, "approvals callback request failed");
            }
        });
    }
}

async fn handle_approvals_connection(
    mut stream: tokio::net::TcpStream,
    state: ApprovalServerState,
) -> Result<()> {
    let response = match read_http_request(&mut stream).await {
        Ok(request) => route_approval_request(request, &state)
            .await
            .unwrap_or_else(internal_server_error_response),
        Err(error) => {
            tracing::warn!(%error, "failed to parse approvals callback request");
            bad_request_response("bad request\n")
        }
    };
    write_http_response(
        &mut stream,
        response.status,
        response.content_type,
        &response.body,
    )
    .await
}

async fn route_approval_request(
    request: HttpRequest,
    state: &ApprovalServerState,
) -> Result<HttpResponse> {
    let path = path_without_query(&request.path);

    if request.method == Some(Method::GET) && path == "/healthz" {
        return Ok(text_response(StatusCode::OK, "ok\n"));
    }

    if request.method == Some(Method::POST) {
        if let Some(request_id) = approval_decision_request_id(path) {
            return handle_agentenv_decision_callback(request_id, &request, state).await;
        }
        if path == "/slack/interactions" {
            return handle_slack_interaction_callback(&request, state).await;
        }
    }

    Ok(text_response(StatusCode::NOT_FOUND, "not found\n"))
}

async fn handle_agentenv_decision_callback(
    request_id: &str,
    request: &HttpRequest,
    state: &ApprovalServerState,
) -> Result<HttpResponse> {
    let body = match serde_json::from_slice::<CallbackDecisionBody>(&request.body) {
        Ok(body) => body,
        Err(error) => {
            tracing::warn!(%error, "invalid approval decision callback body");
            return Ok(bad_request_response("invalid decision body\n"));
        }
    };
    if body.request_id != request_id {
        return Ok(bad_request_response("request id mismatch\n"));
    }

    if !verify_agentenv_callback_signature(&state.config, &request.headers, &request.body)? {
        return Ok(text_response(StatusCode::UNAUTHORIZED, "unauthorized\n"));
    }

    let decision = ApprovalDecisionValue::from(body.decision);
    let record = decide_callback_approval(
        state,
        request_id,
        decision,
        body.scope,
        body.reason,
        non_empty_or(body.decided_by, "agentenv:webhook"),
        "webhook",
    )
    .await?;

    if record.decision != decision {
        return Ok(text_response(
            StatusCode::CONFLICT,
            "approval already decided differently\n",
        ));
    }

    json_response(
        StatusCode::OK,
        serde_json::json!({
            "request_id": record.request_id,
            "decision": record.decision,
            "scope": record.scope,
        }),
    )
}

async fn handle_slack_interaction_callback(
    request: &HttpRequest,
    state: &ApprovalServerState,
) -> Result<HttpResponse> {
    if !verify_slack_callback_signature(&state.config, &request.headers, &request.body)? {
        return Ok(text_response(StatusCode::UNAUTHORIZED, "unauthorized\n"));
    }

    let Some(payload) = form_field(&request.body, "payload")? else {
        return Ok(bad_request_response("missing slack payload\n"));
    };
    let payload = match serde_json::from_str::<SlackInteractionPayload>(&payload) {
        Ok(payload) => payload,
        Err(error) => {
            tracing::warn!(%error, "invalid Slack interaction payload");
            return Ok(bad_request_response("invalid slack payload\n"));
        }
    };
    let Some(action_value) = payload
        .actions
        .iter()
        .find_map(|action| action.value.as_deref())
    else {
        return Ok(bad_request_response("missing slack action value\n"));
    };
    let action = match parse_slack_action_value(action_value) {
        Ok(action) => action,
        Err(error) => {
            tracing::warn!(%error, "invalid Slack action value");
            return Ok(bad_request_response("invalid slack action value\n"));
        }
    };
    let source_decided_by = payload.decided_by();
    let record = decide_callback_approval(
        state,
        &action.request_id,
        action.decision,
        action.scope,
        Some("slack interaction".to_owned()),
        source_decided_by,
        "slack",
    )
    .await?;

    if record.decision != action.decision {
        return Ok(text_response(
            StatusCode::CONFLICT,
            "approval already decided differently\n",
        ));
    }

    json_response(
        StatusCode::OK,
        serde_json::json!({
            "response_type": "ephemeral",
            "text": format!("recorded {} for {}", approval_decision_label(record.decision), record.request_id),
        }),
    )
}

async fn decide_callback_approval(
    state: &ApprovalServerState,
    request_id: &str,
    decision: ApprovalDecisionValue,
    scope: Option<ApprovalScope>,
    reason: Option<String>,
    decided_by: String,
    source: &str,
) -> Result<ApprovalDecisionRecord> {
    let request = find_approval_request(&state.options, request_id)?;
    let scope = match decision {
        ApprovalDecisionValue::Allow => scope,
        ApprovalDecisionValue::Deny => scope.or(Some(ApprovalScope::Once)),
    };
    decide_approval_as(
        &state.options,
        &request.env,
        request_id,
        decision,
        scope,
        reason,
        decided_by,
        source,
        state.event_sink_args.as_ref().as_slice(),
    )
    .await
}

fn find_approval_request(
    options: &agentenv_core::runtime::RuntimeOptions,
    request_id: &str,
) -> Result<ApprovalRequest> {
    let mut found = None;
    for row in agentenv_core::runtime::list_envs(options).context("list environments")? {
        let store = open_approval_store(options, &row.name)?;
        if let Some(request) = store
            .get_request(request_id)
            .with_context(|| format!("load approval request `{request_id}` for `{}`", row.name))?
        {
            if found.is_some() {
                bail!("approval request `{request_id}` matched multiple environments");
            }
            found = Some(request);
        }
    }

    found.with_context(|| format!("approval request `{request_id}` was not found"))
}

fn verify_agentenv_callback_signature(
    config: &ApprovalConfig,
    headers: &BTreeMap<String, String>,
    body: &[u8],
) -> Result<bool> {
    verify_agentenv_callback_signature_at(
        config,
        headers,
        body,
        ::time::OffsetDateTime::now_utc().unix_timestamp(),
    )
}

fn verify_agentenv_callback_signature_at(
    config: &ApprovalConfig,
    headers: &BTreeMap<String, String>,
    body: &[u8],
    now_unix_seconds: i64,
) -> Result<bool> {
    let Some(signature) = header_value(headers, "x-agentenv-signature") else {
        return Ok(false);
    };
    let Some(timestamp) =
        header_value(headers, "x-agentenv-timestamp").and_then(|value| value.parse::<i64>().ok())
    else {
        return Ok(false);
    };
    if timestamp.abs_diff(now_unix_seconds) > 300 {
        return Ok(false);
    }
    let Some(delivery_id) = header_value(headers, "x-agentenv-delivery") else {
        return Ok(false);
    };

    for secret in configured_webhook_secrets(config) {
        if verify_payload(&secret, timestamp, delivery_id, body, signature)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn verify_slack_callback_signature(
    config: &ApprovalConfig,
    headers: &BTreeMap<String, String>,
    body: &[u8],
) -> Result<bool> {
    let Some(secret) = configured_slack_signing_secret(config) else {
        return Ok(false);
    };
    let Some(signature) = header_value(headers, "x-slack-signature") else {
        return Ok(false);
    };
    let Some(timestamp) =
        header_value(headers, "x-slack-request-timestamp").and_then(|value| value.parse().ok())
    else {
        return Ok(false);
    };
    Ok(verify_slack_signature(
        &secret,
        timestamp,
        signature,
        body,
        ::time::OffsetDateTime::now_utc().unix_timestamp(),
    )?)
}

fn configured_webhook_secrets(config: &ApprovalConfig) -> Vec<String> {
    let mut secrets = Vec::new();
    for target in &config.approvals.webhooks {
        if let Some(secret) = target
            .secret
            .as_deref()
            .and_then(resolve_inline_or_env_secret)
        {
            secrets.push(secret);
        }
        if let Some(secret) = target
            .secret_ref
            .as_deref()
            .and_then(resolve_env_secret_ref)
        {
            secrets.push(secret);
        }
    }
    secrets
}

fn configured_slack_signing_secret(config: &ApprovalConfig) -> Option<String> {
    config
        .approvals
        .slack
        .as_ref()?
        .signing_secret
        .as_deref()
        .and_then(resolve_inline_or_env_secret)
}

fn resolve_inline_or_env_secret(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(name) = env_placeholder_name(trimmed) {
        return std::env::var(name)
            .ok()
            .filter(|secret| !secret.trim().is_empty());
    }
    if let Some(name) = trimmed.strip_prefix("env:") {
        return std::env::var(name)
            .ok()
            .filter(|secret| !secret.trim().is_empty());
    }
    Some(trimmed.to_owned())
}

fn resolve_env_secret_ref(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let name = env_placeholder_name(trimmed)
        .or_else(|| trimmed.strip_prefix("env:"))
        .unwrap_or(trimmed);
    std::env::var(name)
        .ok()
        .filter(|secret| !secret.trim().is_empty())
}

fn env_placeholder_name(value: &str) -> Option<&str> {
    value
        .strip_prefix("${")
        .and_then(|rest| rest.strip_suffix('}'))
        .filter(|name| !name.trim().is_empty())
}

fn parse_slack_action_value(value: &str) -> Result<SlackActionDecision> {
    let mut parts = value.split(':');
    let action = parts.next().unwrap_or_default();
    let request_id = parts
        .next()
        .filter(|request_id| !request_id.trim().is_empty())
        .context("Slack action value missing request id")?;
    let parsed_scope = parts
        .next()
        .filter(|scope| !scope.trim().is_empty())
        .map(parse_approval_scope)
        .transpose()?;
    let decision = match action {
        "approve" | "allow" => ApprovalDecisionValue::Allow,
        "deny" => ApprovalDecisionValue::Deny,
        _ => bail!("unsupported Slack action `{action}`"),
    };
    let scope = match decision {
        ApprovalDecisionValue::Allow => parsed_scope,
        ApprovalDecisionValue::Deny => parsed_scope.or(Some(ApprovalScope::Once)),
    };

    Ok(SlackActionDecision {
        request_id: request_id.to_owned(),
        decision,
        scope,
    })
}

fn parse_approval_scope(value: &str) -> Result<ApprovalScope> {
    serde_json::from_value(serde_json::Value::String(value.to_owned()))
        .with_context(|| format!("invalid approval scope `{value}`"))
}

impl From<CallbackDecisionValue> for ApprovalDecisionValue {
    fn from(value: CallbackDecisionValue) -> Self {
        match value {
            CallbackDecisionValue::Allow => Self::Allow,
            CallbackDecisionValue::Deny => Self::Deny,
        }
    }
}

impl SlackInteractionPayload {
    fn decided_by(&self) -> String {
        let Some(user) = &self.user else {
            return "agentenv:slack".to_owned();
        };
        if let Some(id) = user.id.as_deref().filter(|value| !value.trim().is_empty()) {
            return format!("slack:{id}");
        }
        if let Some(username) = user
            .username
            .as_deref()
            .filter(|value| !value.trim().is_empty())
        {
            return format!("slack:{username}");
        }
        if let Some(name) = user
            .name
            .as_deref()
            .filter(|value| !value.trim().is_empty())
        {
            return format!("slack:{name}");
        }
        "agentenv:slack".to_owned()
    }
}

async fn read_http_request(stream: &mut tokio::net::TcpStream) -> Result<HttpRequest> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        let read = stream
            .read(&mut chunk)
            .await
            .context("read approvals HTTP request")?;
        if read == 0 {
            bail!("HTTP request ended before headers were complete");
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.len() > MAX_APPROVAL_HTTP_REQUEST_BYTES {
            bail!("HTTP request exceeded maximum size");
        }
        if let Some(position) = find_header_end(&buffer) {
            break position;
        }
    };

    let header_text = std::str::from_utf8(&buffer[..header_end])
        .context("HTTP request headers were not UTF-8")?;
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().context("HTTP request line is missing")?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .and_then(|value| Method::from_bytes(value.as_bytes()).ok());
    let path = request_parts.next().unwrap_or_default().to_owned();
    let mut headers = BTreeMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
    }

    let content_length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    if content_length > MAX_APPROVAL_HTTP_REQUEST_BYTES {
        bail!("HTTP request body exceeded maximum size");
    }
    let body_start = header_end + b"\r\n\r\n".len();
    while buffer.len().saturating_sub(body_start) < content_length {
        let read = stream
            .read(&mut chunk)
            .await
            .context("read approvals HTTP request body")?;
        if read == 0 {
            bail!("HTTP request body ended before content-length was satisfied");
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.len() > MAX_APPROVAL_HTTP_REQUEST_BYTES {
            bail!("HTTP request exceeded maximum size");
        }
    }

    let body_end = body_start + content_length;
    let body = buffer
        .get(body_start..body_end)
        .context("HTTP request body bounds were invalid")?
        .to_vec();

    Ok(HttpRequest {
        method,
        path,
        headers,
        body,
    })
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(b"\r\n\r\n".len())
        .position(|window| window == b"\r\n\r\n")
}

fn form_field(body: &[u8], field: &str) -> Result<Option<String>> {
    let body = std::str::from_utf8(body).context("form body was not UTF-8")?;
    for pair in body.split('&') {
        let (raw_name, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
        if percent_decode_form(raw_name)? == field {
            return Ok(Some(percent_decode_form(raw_value)?));
        }
    }
    Ok(None)
}

fn percent_decode_form(value: &str) -> Result<String> {
    let raw = value.as_bytes();
    let mut decoded = Vec::with_capacity(raw.len());
    let mut index = 0;
    while index < raw.len() {
        match raw[index] {
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < raw.len() => {
                let high = hex_nibble(raw[index + 1]).context("invalid form percent encoding")?;
                let low = hex_nibble(raw[index + 2]).context("invalid form percent encoding")?;
                decoded.push((high << 4) | low);
                index += 3;
            }
            b'%' => bail!("truncated form percent encoding"),
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(decoded).context("decoded form field was not UTF-8")
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn approval_decision_request_id(path: &str) -> Option<&str> {
    let mut segments = path.trim_start_matches('/').split('/');
    match (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) {
        (Some("approvals"), Some(request_id), Some("decision"), None) if !request_id.is_empty() => {
            Some(request_id)
        }
        _ => None,
    }
}

fn path_without_query(path: &str) -> &str {
    path.split_once('?')
        .map(|(path, _query)| path)
        .unwrap_or(path)
}

fn header_value<'a>(headers: &'a BTreeMap<String, String>, name: &str) -> Option<&'a str> {
    headers.get(name).map(String::as_str)
}

fn non_empty_or(value: String, default: &str) -> String {
    if value.trim().is_empty() {
        default.to_owned()
    } else {
        value
    }
}

fn approval_config_path(options: &agentenv_core::runtime::RuntimeOptions) -> PathBuf {
    options.root.join("config.yaml")
}

fn text_response(status: StatusCode, body: impl Into<String>) -> HttpResponse {
    HttpResponse {
        status,
        content_type: "text/plain; charset=utf-8",
        body: body.into(),
    }
}

fn bad_request_response(body: impl Into<String>) -> HttpResponse {
    text_response(StatusCode::BAD_REQUEST, body)
}

fn internal_server_error_response(error: anyhow::Error) -> HttpResponse {
    tracing::warn!(%error, "approval callback handler failed");
    text_response(StatusCode::INTERNAL_SERVER_ERROR, "internal server error\n")
}

fn json_response(status: StatusCode, value: serde_json::Value) -> Result<HttpResponse> {
    Ok(HttpResponse {
        status,
        content_type: "application/json",
        body: serde_json::to_string(&value)?,
    })
}

async fn serve_metrics(port: u16) -> Result<()> {
    let options = runtime_options(true)?;
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .with_context(|| format!("bind metrics listener on 127.0.0.1:{port}"))?;
    loop {
        let (stream, _) = listener.accept().await.context("accept metrics request")?;
        let options = options.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_metrics_connection(stream, options).await {
                tracing::warn!(%error, "metrics request failed");
            }
        });
    }
}

async fn handle_metrics_connection(
    mut stream: tokio::net::TcpStream,
    options: agentenv_core::runtime::RuntimeOptions,
) -> Result<()> {
    let mut buffer = [0u8; 4096];
    let read = stream
        .read(&mut buffer)
        .await
        .context("read metrics request")?;
    let request = String::from_utf8_lossy(&buffer[..read]);
    let mut parts = request
        .lines()
        .next()
        .unwrap_or_default()
        .split_whitespace();
    let method = parts
        .next()
        .and_then(|value| Method::from_bytes(value.as_bytes()).ok());
    let path = parts.next().unwrap_or_default();

    let (status, content_type, body) = if method == Some(Method::GET) && path == "/metrics" {
        (
            StatusCode::OK,
            "text/plain; version=0.0.4",
            render_metrics_body(&options)?,
        )
    } else {
        (
            StatusCode::NOT_FOUND,
            "text/plain; charset=utf-8",
            "not found\n".to_owned(),
        )
    };
    write_http_response(&mut stream, status, content_type, &body).await
}

fn render_metrics_body(options: &agentenv_core::runtime::RuntimeOptions) -> Result<String> {
    let store = SqliteEventStore::open(global_events_db_path(options))
        .context("open global activity database")?;
    let env_rows = env_status_metrics(options)?;
    let mut snapshot =
        MetricsSnapshot::from_store(&store, &env_rows).context("build metrics snapshot")?;
    snapshot.event_drops_total = Vec::<SinkCounterMetric>::new();
    snapshot.event_sink_errors_total = Vec::<SinkCounterMetric>::new();
    Ok(render_prometheus(&snapshot))
}

fn env_status_metrics(
    options: &agentenv_core::runtime::RuntimeOptions,
) -> Result<Vec<EnvMetricRow>> {
    let mut counts = BTreeMap::<String, u64>::new();
    for row in agentenv_core::runtime::list_envs(options)? {
        *counts.entry(row.status).or_default() += 1;
    }
    Ok(counts
        .into_iter()
        .map(|(status, count)| EnvMetricRow { status, count })
        .collect())
}

async fn write_http_response(
    stream: &mut tokio::net::TcpStream,
    status: StatusCode,
    content_type: &str,
    body: &str,
) -> Result<()> {
    let reason = status.canonical_reason().unwrap_or("");
    let response = format!(
        "HTTP/1.1 {} {}\r\ncontent-type: {}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        status.as_u16(),
        reason,
        content_type,
        body.len(),
        body
    );
    stream
        .write_all(response.as_bytes())
        .await
        .context("write metrics response")
}

async fn run_snapshot(args: SnapshotArgs) -> Result<()> {
    match args.command {
        Some(SnapshotCommand::Verify { path }) => run_snapshot_verify(path),
        Some(SnapshotCommand::Restore(args)) => run_snapshot_restore(args).await,
        None => run_snapshot_create(args).await,
    }
}

async fn run_snapshot_create(args: SnapshotArgs) -> Result<()> {
    let env = args
        .env
        .ok_or_else(|| anyhow::anyhow!("snapshot requires an env name or subcommand"))?;
    let output = match args.output {
        Some(output) => output,
        None => default_snapshot_output_path(&env)?,
    };
    reject_snapshot_stdout_output(&output)?;

    let options = runtime_options(true)?;
    let result = agentenv_core::runtime::snapshot_env(
        &options,
        &builtin_factory::BuiltInDriverFactory,
        agentenv_core::runtime::SnapshotEnvArgs { env, output },
    )
    .await?;

    println!("Snapshot written: {}", result.path.display());
    println!("files: {}", result.file_count);
    println!("merkle root: {}", result.merkle_root);
    Ok(())
}

fn run_snapshot_verify(path: PathBuf) -> Result<()> {
    let result = agentenv_core::runtime::verify_snapshot(&path)
        .with_context(|| format!("failed to verify snapshot `{}`", path.display()))?;
    println!("Snapshot verified: {}", result.path.display());
    println!("files: {}", result.file_count);
    println!("merkle root: {}", result.merkle_root);
    println!("signature: verified");
    Ok(())
}

async fn run_snapshot_restore(args: SnapshotRestoreCliArgs) -> Result<()> {
    let options = runtime_options(args.non_interactive)?;
    let store = CredentialStore::from_default_paths().context("initialize credential store")?;
    let mut provider = CliCredentialProvider {
        store,
        non_interactive: args.non_interactive,
        prompter: Box::new(TerminalCredentialPrompter),
    };

    let result = agentenv_core::runtime::restore_snapshot_env(
        &options,
        &builtin_factory::BuiltInDriverFactory,
        &mut provider,
        agentenv_core::runtime::SnapshotRestoreArgs {
            snapshot: args.path.clone(),
            name: args.as_name,
        },
    )
    .await
    .with_context(|| format!("failed to restore snapshot `{}`", args.path.display()))?;

    println!(
        "Environment `{}` restored from snapshot {}",
        result.name,
        result.snapshot.display()
    );
    Ok(())
}

async fn run_fork(args: ForkArgs) -> Result<()> {
    let options = runtime_options(true)?;
    let result = agentenv_core::runtime::fork_env(
        &options,
        &builtin_factory::BuiltInDriverFactory,
        &args.source,
        &args.name,
    )
    .await?;

    println!(
        "Environment `{}` forked from `{}`",
        result.name, result.source
    );
    println!("snapshot: {}", result.snapshot_id);
    println!("sandbox: {}", result.sandbox_handle);
    Ok(())
}

fn reject_snapshot_stdout_output(output: &Path) -> Result<()> {
    if output == Path::new("-") {
        bail!("--output - is not supported for snapshots; choose a directory path");
    }
    Ok(())
}

fn default_snapshot_output_path(env: &str) -> Result<PathBuf> {
    let cwd = std::env::current_dir().context("failed to determine current working directory")?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_nanos();
    Ok(cwd.join(format!("{env}-{timestamp}.agentenvsnap")))
}

async fn run_exec(args: ExecArgs, event_sink_args: &[String]) -> Result<()> {
    let options = runtime_options(true)?;
    let dispatcher = build_event_dispatcher(&options, Some(&args.name), event_sink_args)?;
    let emitter = Arc::new(AuditingEventEmitter::new(
        dispatcher.emitter(),
        audit_signing_key_path(&options),
        audit_write_db_paths(&options, Some(&args.name))?,
    ));
    let result = match agentenv_core::runtime::exec_env_observed(
        &options,
        &builtin_factory::BuiltInDriverFactory,
        &args.name,
        args.cmd,
        Arc::clone(&emitter) as Arc<dyn EventEmitter>,
    )
    .await
    {
        Ok(result) => {
            emitter.check_audit()?;
            flush_dispatcher_best_effort(&dispatcher).await;
            result
        }
        Err(error) => {
            flush_dispatcher_best_effort(&dispatcher).await;
            if let Err(audit_error) = emitter.check_audit() {
                return Err(audit_error_after_original(audit_error, &error));
            }
            return Err(error.into());
        }
    };
    print!("{}", result.stdout);
    eprint!("{}", result.stderr);
    io::stdout().flush().context("flush forwarded stdout")?;
    io::stderr().flush().context("flush forwarded stderr")?;
    process::exit(result.status);
}

async fn run_term(args: TermArgs) -> Result<()> {
    if let Some(endpoint) = args.remote {
        bail!("remote term requires a future agentenv daemon; unsupported endpoint `{endpoint}`");
    }
    let options = runtime_options(true)?;
    if args.once {
        return print_approval_rows(&pending_approval_rows_all_envs(&options)?, false);
    }
    let backend = term_backend::LocalOpsBackend::new(options)?;
    agentenv_tui::run_terminal(
        backend,
        agentenv_tui::terminal::TermOptions {
            no_color: args.no_color,
            refresh_interval: Duration::from_millis(250),
        },
    )
    .await
}

fn exit_json_error(reason_code: ReasonCode, error: impl std::fmt::Display) -> ! {
    render::print_error_body_json(reason_code, error.to_string());
    exit_process(render::exit_for_reason(reason_code).code());
}

fn audit_error_after_original(
    audit_error: anyhow::Error,
    original_error: impl std::fmt::Display,
) -> anyhow::Error {
    anyhow::anyhow!(
        "failed to write audit event after original command error `{}`: {:#}",
        original_error,
        audit_error
    )
}

fn exit_if_rejected(report: &AdmissionReport) {
    if report.status == AdmissionStatus::Rejected {
        exit_process(report.exit_class().code());
    }
}

fn exit_process(code: i32) -> ! {
    let _ = io::stdout().flush();
    let _ = io::stderr().flush();
    process::exit(code);
}

fn confirm_destroy(name: &str, non_interactive: bool) -> Result<()> {
    if non_interactive {
        exit_json_error(
            ReasonCode::NonInteractivePromptRequired,
            "destroy requires --yes in non-interactive mode",
        );
    }

    print!("Type `{name}` to destroy environment `{name}`: ");
    io::stdout().flush().context("flush destroy prompt")?;
    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .context("read destroy confirmation")?;
    if answer.trim() != name {
        bail!("destroy canceled");
    }
    Ok(())
}

fn purge_state_credentials(credential_names: &[String]) -> Result<()> {
    if credential_names.is_empty() {
        return Ok(());
    }

    let mut store =
        CredentialStore::from_default_paths().context("initialize credential store for purge")?;
    for name in credential_names {
        match store.remove(name) {
            Ok(()) => eprintln!("purged credential `{name}`"),
            Err(CredentialStoreError::MissingCredential { .. }) => {}
            Err(error) => return Err(error).with_context(|| format!("purge credential `{name}`")),
        }
    }
    Ok(())
}

async fn print_activity_logs(
    options: &agentenv_core::runtime::RuntimeOptions,
    name: &str,
    kind_filter: Option<&str>,
    json: bool,
    follow: bool,
) -> Result<()> {
    let kind = parse_activity_kind_opt(kind_filter)?;
    let mut rows = Vec::new();
    let mut follow_source = None;
    let mut empty_follow_source = None;
    let global_db_path = global_events_db_path(options);
    if global_db_path.is_file() {
        match query_sqlite_activity_logs(&global_db_path, name, kind, None) {
            Ok(global_rows) => {
                let after_id = global_rows.last().map(|row| row.id);
                if follow && !global_rows.is_empty() && follow_source.is_none() {
                    follow_source = Some((global_db_path.clone(), after_id));
                } else if follow && empty_follow_source.is_none() {
                    empty_follow_source = Some((global_db_path.clone(), after_id));
                }
                rows.extend(global_rows);
            }
            Err(error) => {
                tracing::warn!(
                    path = %global_db_path.display(),
                    %error,
                    "failed to read global activity database; trying fallback"
                );
            }
        }
    }

    let db_path = env_events_db_path(options, name)?;
    if db_path.is_file() {
        match query_sqlite_activity_logs(&db_path, name, kind, None) {
            Ok(env_rows) => {
                let after_id = env_rows.last().map(|row| row.id);
                if follow && !env_rows.is_empty() && follow_source.is_none() {
                    follow_source = Some((db_path.clone(), after_id));
                } else if follow && empty_follow_source.is_none() {
                    empty_follow_source = Some((db_path.clone(), after_id));
                }
                rows.extend(env_rows);
            }
            Err(error) => {
                tracing::warn!(
                    path = %db_path.display(),
                    %error,
                    "failed to read per-env activity database; trying fallback"
                );
            }
        }
    }
    if follow && follow_source.is_none() {
        follow_source = empty_follow_source;
    }

    if !rows.is_empty() || follow_source.is_some() {
        print_activity_rows(dedupe_activity_rows(rows)?, json, None)?;
        if let Some((db_path, after_id)) = follow_source {
            return follow_sqlite_activity_logs(&db_path, name, kind, json, after_id).await;
        }
        return Ok(());
    }

    print_legacy_activity_logs(options, name, kind, json, follow)
}

async fn follow_sqlite_activity_logs(
    db_path: &Path,
    env: &str,
    kind: Option<ActivityKind>,
    json: bool,
    mut after_id: Option<i64>,
) -> Result<()> {
    loop {
        after_id = print_sqlite_activity_logs(db_path, env, kind, json, after_id)?;
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

fn print_sqlite_activity_logs(
    db_path: &Path,
    env: &str,
    kind: Option<ActivityKind>,
    json: bool,
    after_id: Option<i64>,
) -> Result<Option<i64>> {
    let rows = query_sqlite_activity_logs(db_path, env, kind, after_id)?;
    print_activity_rows(rows, json, after_id)
}

fn query_sqlite_activity_logs(
    db_path: &Path,
    env: &str,
    kind: Option<ActivityKind>,
    after_id: Option<i64>,
) -> Result<Vec<StoredEvent>> {
    let store = SqliteEventStore::open(db_path.to_path_buf())
        .with_context(|| format!("open activity database `{}`", db_path.display()))?;
    let mut rows = store
        .query(EventQuery {
            env: Some(env.to_owned()),
            kind,
            after_id,
            limit: 1000,
            ..EventQuery::default()
        })
        .with_context(|| format!("query activity database `{}`", db_path.display()))?;
    rows.sort_by_key(|row| row.id);
    Ok(rows)
}

fn print_activity_rows(
    rows: Vec<StoredEvent>,
    json: bool,
    after_id: Option<i64>,
) -> Result<Option<i64>> {
    let last_id = rows.last().map(|row| row.id).or(after_id);
    for row in rows {
        print_activity_event(&row.event, json)?;
    }
    io::stdout().flush().context("flush activity logs")?;
    Ok(last_id)
}

fn dedupe_activity_rows(rows: Vec<StoredEvent>) -> Result<Vec<StoredEvent>> {
    let mut seen = BTreeSet::new();
    let mut deduped = Vec::new();
    for row in rows {
        let key = serde_json::to_string(&row.event)?;
        if seen.insert(key) {
            deduped.push(row);
        }
    }
    deduped.sort_by(|left, right| {
        left.event
            .ts
            .cmp(&right.event.ts)
            .then(left.event.trace_id.cmp(&right.event.trace_id))
            .then(left.id.cmp(&right.id))
    });
    Ok(deduped)
}

fn print_legacy_activity_logs(
    options: &agentenv_core::runtime::RuntimeOptions,
    name: &str,
    kind: Option<ActivityKind>,
    json: bool,
    follow: bool,
) -> Result<()> {
    if follow {
        let env_name = agentenv_core::env::validate_env_name(name)?;
        let paths = agentenv_core::env::EnvPaths::new(options.root.clone(), env_name);
        follow_legacy_activity_logs(&paths.events_path(), kind, json)
    } else {
        let env_name = agentenv_core::env::validate_env_name(name)?;
        let paths = agentenv_core::env::EnvPaths::new(options.root.clone(), env_name);
        print_legacy_activity_log_chunk(&paths.events_path(), kind, json, 0).map(|_| ())
    }
}

fn follow_legacy_activity_logs(
    events_path: &Path,
    kind: Option<ActivityKind>,
    json: bool,
) -> Result<()> {
    let mut position = 0;
    loop {
        position = print_legacy_activity_log_chunk(events_path, kind, json, position)?;
        thread::sleep(Duration::from_millis(200));
    }
}

fn print_legacy_activity_log_chunk(
    events_path: &Path,
    kind: Option<ActivityKind>,
    json: bool,
    position: u64,
) -> Result<u64> {
    let mut file = match fs::File::open(events_path) {
        Ok(file) => file,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(position),
        Err(source) => {
            return Err(agentenv_core::env::EnvError::Io {
                path: events_path.to_path_buf(),
                source,
            }
            .into());
        }
    };
    let len = file
        .metadata()
        .with_context(|| format!("read events metadata `{}`", events_path.display()))?
        .len();
    let start = if position <= len { position } else { 0 };
    file.seek(SeekFrom::Start(start))
        .with_context(|| format!("seek events log `{}`", events_path.display()))?;
    let mut content = String::new();
    file.read_to_string(&mut content)
        .with_context(|| format!("read events log `{}`", events_path.display()))?;

    for line in content.lines().filter(|line| !line.trim().is_empty()) {
        let Ok(event) = parse_legacy_jsonl_activity_event(line) else {
            continue;
        };
        if kind.is_some_and(|kind| event.kind != kind) {
            continue;
        }
        print_activity_event(&event, json)?;
    }
    io::stdout().flush().context("flush activity logs")?;

    Ok(start + content.len() as u64)
}

fn print_activity_event(event: &ActivityEvent, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string(event)?);
    } else {
        println!(
            "{} {} {} {}",
            event.ts,
            activity_kind_label(event.kind),
            activity_result_label(event.result),
            event
                .reason_code
                .as_deref()
                .or_else(|| event
                    .subject
                    .get("message")
                    .and_then(serde_json::Value::as_str))
                .or_else(|| event
                    .subject
                    .get("target")
                    .and_then(serde_json::Value::as_str))
                .unwrap_or("")
        );
    }
    Ok(())
}

fn print_event_logs(
    options: &agentenv_core::runtime::RuntimeOptions,
    name: &str,
    driver_filter: Option<&str>,
    follow: bool,
) -> Result<()> {
    agentenv_core::runtime::describe_env(options, name)?;
    let env_name = agentenv_core::env::validate_env_name(name)?;
    let paths = agentenv_core::env::EnvPaths::new(options.root.clone(), env_name);
    let events_path = paths.events_path();

    if follow {
        follow_event_logs(&events_path, driver_filter)
    } else {
        print_event_log_chunk(&events_path, driver_filter, 0).map(|_| ())
    }
}

fn follow_event_logs(events_path: &Path, driver_filter: Option<&str>) -> Result<()> {
    let mut position = 0;
    loop {
        position = print_event_log_chunk(events_path, driver_filter, position)?;
        thread::sleep(Duration::from_millis(200));
    }
}

fn print_event_log_chunk(
    events_path: &Path,
    driver_filter: Option<&str>,
    position: u64,
) -> Result<u64> {
    let mut file = match fs::File::open(events_path) {
        Ok(file) => file,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(position),
        Err(source) => {
            return Err(agentenv_core::env::EnvError::Io {
                path: events_path.to_path_buf(),
                source,
            }
            .into());
        }
    };
    let len = file
        .metadata()
        .with_context(|| format!("read events metadata `{}`", events_path.display()))?
        .len();
    let start = if position <= len { position } else { 0 };
    file.seek(SeekFrom::Start(start))
        .with_context(|| format!("seek events log `{}`", events_path.display()))?;
    let mut content = String::new();
    file.read_to_string(&mut content)
        .with_context(|| format!("read events log `{}`", events_path.display()))?;

    for line in content.lines().filter(|line| !line.trim().is_empty()) {
        match serde_json::from_str::<serde_json::Value>(line) {
            Ok(event) if event_matches_driver(&event, driver_filter) => {
                if let Some(rendered) = format_event_log(&event) {
                    println!("{rendered}");
                } else {
                    println!("{line}");
                }
            }
            Ok(_) => {}
            Err(_) if driver_filter.is_none() => println!("{line}"),
            Err(_) => {}
        }
    }
    io::stdout().flush().context("flush event logs")?;

    Ok(start + content.len() as u64)
}

fn event_matches_driver(event: &serde_json::Value, driver_filter: Option<&str>) -> bool {
    match driver_filter {
        Some(driver) => event
            .get("driver")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|value| value == driver),
        None => true,
    }
}

fn format_event_log(event: &serde_json::Value) -> Option<String> {
    let msg = event
        .get("msg")
        .or_else(|| event.get("message"))
        .and_then(serde_json::Value::as_str)?;
    let ts = event
        .get("ts")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("-");
    let level = event
        .get("level")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("info");
    let driver = event
        .get("driver")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("event");
    Some(format!("{ts} {level} {driver} {msg}"))
}

fn runtime_options(non_interactive: bool) -> Result<agentenv_core::runtime::RuntimeOptions> {
    let home = dirs::home_dir().context("home directory is unavailable")?;
    Ok(agentenv_core::runtime::RuntimeOptions {
        root: home.join(".agentenv"),
        log_level: agentenv_proto::LogLevel::Info,
        non_interactive,
    })
}

fn build_event_dispatcher(
    options: &agentenv_core::runtime::RuntimeOptions,
    env: Option<&str>,
    sink_args: &[String],
) -> Result<EventDispatcher> {
    let mut sinks: Vec<Box<dyn EventSink>> = Vec::new();
    add_default_event_sinks(&mut sinks, options, env)?;
    for raw in sink_args {
        match SinkConfig::parse(raw)? {
            SinkConfig::DefaultSqlite => {}
            SinkConfig::Sqlite { path } => sinks.push(Box::new(SqliteSink::new(path))),
            SinkConfig::Jsonl { path } => sinks.push(Box::new(JsonlSink::new(path))),
            SinkConfig::OtelGrpc { endpoint } => {
                sinks.push(agentenv_events::sink::otel_grpc_sink(endpoint)?);
            }
            SinkConfig::Webhook { config } => {
                validate_webhook_sink_url(&config)?;
                sinks.push(Box::new(WebhookSink::new(
                    config,
                    Arc::new(|url| {
                        agentenv_core::security::ssrf::validate_outbound(
                            url,
                            agentenv_core::security::ssrf::SsrfOptions::default(),
                        )
                        .map(|_| ())
                        .map_err(|source| {
                            agentenv_events::SinkError::webhook_validation_failed(
                                url,
                                source.to_string(),
                            )
                        })
                    }),
                )));
            }
        }
    }
    Ok(EventDispatcher::with_sinks(1024, sinks))
}

fn build_destroy_event_dispatcher(
    options: &agentenv_core::runtime::RuntimeOptions,
    sink_args: &[String],
) -> Result<EventDispatcher> {
    build_event_dispatcher(options, None, sink_args)
}

fn validate_webhook_sink_url(config: &WebhookConfig) -> Result<()> {
    agentenv_core::security::ssrf::validate_outbound(
        &config.url,
        agentenv_core::security::ssrf::SsrfOptions::default(),
    )
    .with_context(|| {
        format!(
            "webhook events sink failed SSRF validation for `{}`",
            config.url
        )
    })?;
    Ok(())
}

fn add_default_event_sinks(
    sinks: &mut Vec<Box<dyn EventSink>>,
    options: &agentenv_core::runtime::RuntimeOptions,
    env: Option<&str>,
) -> Result<()> {
    let global_db_path = global_events_db_path(options);
    sinks.push(Box::new(SqliteSink::new(global_db_path)));
    if let Some(env) = env {
        let env_db_path = env_events_db_path(options, env)?;
        if env_db_path.parent().is_some_and(|env_dir| env_dir.is_dir()) {
            sinks.push(Box::new(SqliteSink::new(env_db_path)));
        }
    }
    Ok(())
}

#[derive(Clone)]
struct AuditingEventEmitter<E> {
    inner: E,
    audit: ReliableAuditWriter,
}

impl<E> AuditingEventEmitter<E> {
    fn new(inner: E, key_path: PathBuf, db_paths: Vec<PathBuf>) -> Self {
        Self {
            inner,
            audit: ReliableAuditWriter::new(key_path, db_paths),
        }
    }

    fn check_audit(&self) -> Result<()> {
        self.audit.check()
    }
}

impl<E> EventEmitter for AuditingEventEmitter<E>
where
    E: EventEmitter,
{
    fn emit(&self, event: ActivityEvent) {
        let event = event.redacted();
        self.audit.append(&event);
        self.inner.emit(event);
    }
}

#[derive(Clone)]
struct ReliableAuditWriter {
    state: Arc<Mutex<ReliableAuditState>>,
}

impl ReliableAuditWriter {
    fn new(key_path: PathBuf, db_paths: Vec<PathBuf>) -> Self {
        Self {
            state: Arc::new(Mutex::new(ReliableAuditState {
                key_path,
                db_paths,
                key: None,
                error: None,
            })),
        }
    }

    fn append(&self, event: &ActivityEvent) {
        if !AuditPolicy::includes(event) {
            return;
        }

        match self.state.lock() {
            Ok(mut state) => {
                if let Err(error) = state.append(event) {
                    state.error = Some(format!("{error:#}"));
                }
            }
            Err(_) => {
                eprintln!("warning: audit writer lock is unavailable");
            }
        }
    }

    fn check(&self) -> Result<()> {
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("audit writer lock is unavailable"))?;
        if let Some(error) = &state.error {
            anyhow::bail!("failed to write audit event: {error}");
        }
        Ok(())
    }
}

struct ReliableAuditState {
    key_path: PathBuf,
    db_paths: Vec<PathBuf>,
    key: Option<AuditSigningKey>,
    error: Option<String>,
}

impl ReliableAuditState {
    fn append(&mut self, event: &ActivityEvent) -> Result<()> {
        if self.key.is_none() {
            self.key = Some(
                AuditSigningKey::load_or_create(&self.key_path)
                    .context("load audit signing key")?,
            );
        }
        let key = self.key.as_ref().context("audit signing key unavailable")?;
        for db_path in &self.db_paths {
            append_audit_event_with_retry(db_path, key, event)?;
        }
        Ok(())
    }
}

fn append_audit_event_with_retry(
    db_path: &Path,
    key: &AuditSigningKey,
    event: &ActivityEvent,
) -> Result<()> {
    let mut last_error = None;
    for _ in 0..5 {
        match AuditStore::open(db_path).and_then(|store| store.append(key, event).map(|_| ())) {
            Ok(()) => return Ok(()),
            Err(error) => {
                last_error = Some(error);
                thread::sleep(Duration::from_millis(20));
            }
        }
    }
    let error = last_error.context("audit append was not attempted")?;
    Err(error).with_context(|| format!("append audit event to `{}`", db_path.display()))
}

async fn flush_dispatcher_best_effort(dispatcher: &EventDispatcher) {
    match tokio::time::timeout(Duration::from_secs(2), dispatcher.flush()).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => eprintln!("warning: failed to flush event sinks: {error}"),
        Err(_) => eprintln!("warning: timed out flushing event sinks"),
    }
}

fn emit_credential_event(
    emitter: &dyn EventEmitter,
    kind: ActivityKind,
    result: ActivityResult,
    name: &str,
) {
    emitter.emit(
        ActivityEvent::new(now_event_ts(), kind, result, new_cli_trace_id())
            .with_actor_value("kind", serde_json::json!("cli"))
            .with_subject_value("name", serde_json::json!(name))
            .redacted(),
    );
}

fn global_events_db_path(options: &agentenv_core::runtime::RuntimeOptions) -> PathBuf {
    options.root.join("events.db")
}

fn activity_reader_db_path(
    options: &agentenv_core::runtime::RuntimeOptions,
    env: Option<&str>,
) -> Result<PathBuf> {
    match env {
        Some(env) => env_events_db_path(options, env),
        None => Ok(global_events_db_path(options)),
    }
}

fn activity_stats_reader_db_path(
    options: &agentenv_core::runtime::RuntimeOptions,
    env: Option<&str>,
) -> Result<PathBuf> {
    if let Some(env) = env {
        agentenv_core::env::validate_env_name(env)?;
        let global_path = global_events_db_path(options);
        if global_path.is_file() {
            let global_store = SqliteEventStore::open(&global_path)
                .with_context(|| format!("open activity database `{}`", global_path.display()))?;
            if global_store.has_entries_for_env(env)? {
                return Ok(global_path);
            }
        }
        let env_path = env_events_db_path(options, env)?;
        if env_path.is_file() {
            return Ok(env_path);
        }
        return Ok(global_path);
    }
    activity_reader_db_path(options, env)
}

fn audit_reader_db_path(
    options: &agentenv_core::runtime::RuntimeOptions,
    env: Option<&str>,
) -> Result<PathBuf> {
    if let Some(env) = env {
        agentenv_core::env::validate_env_name(env)?;
        let global_path = global_events_db_path(options);
        if global_path.is_file() {
            let global_store = AuditStore::open(&global_path)
                .with_context(|| format!("open audit database `{}`", global_path.display()))?;
            if global_store.has_entries_for_env(env)? {
                return Ok(global_path);
            }
        }
        let env_path = env_events_db_path(options, env)?;
        if env_path.is_file() {
            return Ok(env_path);
        }
        return Ok(global_path);
    }
    activity_reader_db_path(options, env)
}

fn audit_store_context(env: Option<&str>) -> String {
    match env {
        Some(env) => format!("open audit database for environment `{env}`"),
        None => "open global audit database".to_owned(),
    }
}

fn audit_signing_key_path(options: &agentenv_core::runtime::RuntimeOptions) -> PathBuf {
    options.root.join("audit-signing-key")
}

fn audit_write_db_paths(
    options: &agentenv_core::runtime::RuntimeOptions,
    env: Option<&str>,
) -> Result<Vec<PathBuf>> {
    let mut paths = vec![global_events_db_path(options)];
    if let Some(env) = env {
        let env_db_path = env_events_db_path(options, env)?;
        if env_db_path.parent().is_some_and(|env_dir| env_dir.is_dir()) {
            paths.push(env_db_path);
        }
    }
    Ok(paths)
}

fn audit_destroy_write_db_paths(
    options: &agentenv_core::runtime::RuntimeOptions,
) -> Result<Vec<PathBuf>> {
    audit_write_db_paths(options, None)
}

fn env_events_db_path(
    options: &agentenv_core::runtime::RuntimeOptions,
    name: &str,
) -> Result<PathBuf> {
    Ok(agentenv_core::runtime::env_events_db_path(options, name)?)
}

fn parse_activity_kind_opt(value: Option<&str>) -> Result<Option<ActivityKind>> {
    value.map(parse_activity_kind).transpose()
}

fn parse_activity_kind(value: &str) -> Result<ActivityKind> {
    serde_json::from_value(serde_json::Value::String(value.to_owned()))
        .with_context(|| format!("invalid activity kind `{value}`"))
}

fn activity_kind_label(kind: ActivityKind) -> String {
    enum_label(kind)
}

fn activity_result_label(result: ActivityResult) -> String {
    enum_label(result)
}

fn enum_label<T>(value: T) -> String
where
    T: Serialize,
{
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(label)) => label,
        _ => "unknown".to_owned(),
    }
}

fn now_event_ts() -> String {
    match ::time::OffsetDateTime::now_utc().format(&::time::format_description::well_known::Rfc3339)
    {
        Ok(value) => value,
        Err(_) => "1970-01-01T00:00:00Z".to_owned(),
    }
}

fn new_cli_trace_id() -> String {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => format!("cli-{}-{}", process::id(), duration.as_nanos()),
        Err(_) => format!("cli-{}-0", process::id()),
    }
}

struct CliCredentialProvider {
    store: CredentialStore,
    non_interactive: bool,
    prompter: Box<dyn CredentialPrompter>,
}

trait CredentialPrompter {
    fn prompt(
        &mut self,
        requirement: &agentenv_proto::CredentialRequirement,
    ) -> agentenv_core::runtime::RuntimeResult<SecretString>;
}

struct TerminalCredentialPrompter;

impl CredentialPrompter for TerminalCredentialPrompter {
    fn prompt(
        &mut self,
        requirement: &agentenv_proto::CredentialRequirement,
    ) -> agentenv_core::runtime::RuntimeResult<SecretString> {
        let mut prompt = format!("Enter value for `{}`", requirement.name);
        if !requirement.description.trim().is_empty() {
            prompt.push_str(&format!(" ({})", requirement.description));
        }
        prompt.push_str(": ");
        let value = rpassword::prompt_password(prompt).map_err(|source| {
            agentenv_core::runtime::RuntimeError::Driver(
                agentenv_core::driver::DriverError::InvalidInput {
                    message: format!(
                        "failed to prompt for credential `{}`: {source}",
                        requirement.name
                    ),
                },
            )
        })?;
        Ok(SecretString::new(value))
    }
}

impl agentenv_core::runtime::CredentialProvider for CliCredentialProvider {
    fn resolve(
        &mut self,
        requirement: &agentenv_proto::CredentialRequirement,
    ) -> agentenv_core::runtime::RuntimeResult<Option<agentenv_core::runtime::RuntimeSecret>> {
        let name = &requirement.name;
        match self.store.resolve(name, requirement) {
            Ok(secret) => Ok(Some(agentenv_core::runtime::RuntimeSecret::new(
                secret.expose_secret().to_owned(),
            ))),
            Err(CredentialStoreError::MissingCredential { .. }) if !requirement.required => {
                Ok(None)
            }
            Err(CredentialStoreError::MissingCredential { .. }) if self.non_interactive => {
                Err(agentenv_core::runtime::RuntimeError::MissingCredential {
                    name: name.to_owned(),
                })
            }
            Err(CredentialStoreError::MissingCredential { .. }) => {
                let prompted = self.prompter.prompt(requirement)?;
                self.store
                    .store(name, &prompted)
                    .map_err(credential_store_runtime_error)?;
                let resolved = self
                    .store
                    .resolve(name, requirement)
                    .map_err(credential_store_runtime_error)?;
                Ok(Some(agentenv_core::runtime::RuntimeSecret::new(
                    resolved.expose_secret().to_owned(),
                )))
            }
            Err(error) => Err(credential_store_runtime_error(error)),
        }
    }

    fn backend_name(&self, name: &str) -> agentenv_core::runtime::RuntimeResult<Option<String>> {
        Ok(self
            .store
            .where_is(name)
            .ok()
            .flatten()
            .map(|backend| backend.to_string()))
    }
}

fn credential_store_runtime_error(
    error: CredentialStoreError,
) -> agentenv_core::runtime::RuntimeError {
    agentenv_core::runtime::RuntimeError::Driver(agentenv_core::driver::DriverError::InvalidInput {
        message: error.to_string(),
    })
}

async fn run_credentials(args: CredentialsArgs, event_sink_args: &[String]) -> Result<()> {
    let options = runtime_options(true)?;
    let dispatcher = build_event_dispatcher(&options, None, event_sink_args)?;
    let emitter = AuditingEventEmitter::new(
        dispatcher.emitter(),
        audit_signing_key_path(&options),
        audit_write_db_paths(&options, None)?,
    );
    let mut store = CredentialStore::from_default_paths().context("initialize credential store")?;
    for warning in store.startup_warnings() {
        eprintln!("warning: {warning}");
    }

    match args.command {
        CredentialCommand::List => {
            for name in store.list().context("list credentials")? {
                println!("{name}");
            }
            Ok(())
        }
        CredentialCommand::Reset { name } => {
            store
                .remove(&name)
                .with_context(|| format!("reset credential `{name}`"))?;
            emit_credential_event(
                &emitter,
                ActivityKind::CredentialReset,
                ActivityResult::Ok,
                &name,
            );
            emitter.check_audit()?;
            flush_dispatcher_best_effort(&dispatcher).await;
            println!("{name}");
            Ok(())
        }
        CredentialCommand::Set { name, from_env } => {
            if let Some(env_name) = from_env {
                let source_env = if env_name == SELF_ENV_SENTINEL {
                    name.clone()
                } else {
                    env_name
                };
                store.store_from_env(&name, &source_env).with_context(|| {
                    format!("store credential `{name}` from env `{source_env}`")
                })?;
            } else {
                let prompt = format!("Enter value for `{name}`: ");
                let value = rpassword::prompt_password(prompt)
                    .with_context(|| format!("prompt for credential `{name}`"))?;
                store
                    .store(&name, &SecretString::new(value))
                    .with_context(|| format!("store credential `{name}`"))?;
            }
            emit_credential_event(
                &emitter,
                ActivityKind::CredentialSet,
                ActivityResult::Ok,
                &name,
            );
            emitter.check_audit()?;
            flush_dispatcher_best_effort(&dispatcher).await;
            println!("{name}");
            Ok(())
        }
        CredentialCommand::Where { name } => match store
            .where_is(&name)
            .with_context(|| format!("lookup credential `{name}`"))?
        {
            Some(backend) => {
                println!("{backend}");
                Ok(())
            }
            None => bail!("credential `{name}` not found"),
        },
    }
}

fn run_blueprint(args: BlueprintArgs) -> Result<()> {
    match args.command {
        BlueprintCommand::Lint(args) => run_blueprint_lint(args),
    }
}

fn run_blueprint_lint(args: BlueprintLintArgs) -> Result<()> {
    let blueprint_yaml = read_text_file(&args.file, "blueprint")?;
    let cwd = args
        .file
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let report = agentenv_core::hardening::lint_blueprint_hardening(&blueprint_yaml, cwd)
        .with_context(|| format!("failed to lint blueprint `{}`", args.file.display()))?;
    let has_error = report
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.severity == HardeningLintSeverity::Error);

    if args.json {
        render::print_json(&report)?;
    } else {
        print_hardening_lint_text(&report);
    }

    if has_error {
        exit_process(1);
    }
    Ok(())
}

fn print_hardening_lint_text(report: &agentenv_core::hardening::HardeningLintReport) {
    println!("profile: {}", report.profile);
    if let Some(path) = report.dockerfile.as_ref() {
        println!("dockerfile: {}", path.display());
    }

    if report.diagnostics.is_empty() {
        println!("diagnostics: none");
        return;
    }

    for diagnostic in &report.diagnostics {
        let line = diagnostic
            .line
            .map(|line| format!(" line {line}"))
            .unwrap_or_default();
        println!(
            "{} {}{}: {}",
            hardening_lint_severity_label(diagnostic.severity),
            diagnostic.code,
            line,
            diagnostic.message
        );
        if let Some(remediation) = diagnostic.remediation.as_ref() {
            println!("  remediation: {remediation}");
        }
    }
}

fn hardening_lint_severity_label(severity: HardeningLintSeverity) -> &'static str {
    match severity {
        HardeningLintSeverity::Info => "info",
        HardeningLintSeverity::Warning => "warning",
        HardeningLintSeverity::Error => "error",
    }
}

fn run_drivers(args: DriversArgs) -> Result<()> {
    match args.command {
        DriverCommand::List => {
            let catalog =
                DriverCatalog::discover_from_environment().context("discover installed drivers")?;
            print_driver_table(&catalog.entries);
            Ok(())
        }
    }
}

fn print_driver_table(entries: &[DiscoveredDriver]) {
    println!(
        "{:<10} {:<24} {:<14} {:<10} BINARY",
        "KIND", "NAME", "VERSION", "SOURCE"
    );
    for entry in entries {
        let binary = entry
            .binary
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "-".to_owned());
        println!(
            "{:<10} {:<24} {:<14} {:<10} {}",
            entry.kind.to_string(),
            entry.name,
            entry.version,
            entry.source.label(),
            binary
        );
    }
}

fn verify_blueprint(path: &Path) -> Result<()> {
    let blueprint_yaml = read_text_file(path, "blueprint")?;
    agentenv_core::lifecycle::verify_blueprint_yaml(&blueprint_yaml)
        .with_context(|| format!("failed to verify blueprint `{}`", path.display()))?;

    println!("Blueprint verified: {}", path.display());
    Ok(())
}

fn freeze(name: &str, output: Option<&Path>) -> Result<()> {
    let options = runtime_options(true)?;
    let lockfile = agentenv_core::runtime::freeze_env_lockfile(&options, name)
        .with_context(|| format!("failed to freeze environment `{name}`"))?;

    match output {
        Some(path) if path == Path::new("-") => {
            print!("{lockfile}");
        }
        Some(path) => {
            fs::write(path, &lockfile)
                .with_context(|| format!("failed to write lockfile to `{}`", path.display()))?;
            println!(
                "Lockfile written for environment `{name}`: {}",
                path.display()
            );
        }
        None => {
            let path = Path::new("agentenv.lock");
            fs::write(path, &lockfile)
                .with_context(|| format!("failed to write lockfile to `{}`", path.display()))?;
            println!(
                "Lockfile written for environment `{name}`: {}",
                path.display()
            );
        }
    }

    Ok(())
}

fn verify_lockfile(path: &Path) -> Result<()> {
    let lockfile_yaml = read_text_file(path, "lockfile")?;
    let options = runtime_options(true)?;
    let driver_artifacts = discover_runtime_driver_artifacts(&options)?;
    let report = agentenv_core::portable_lockfile::verify_portable_lockfile_yaml(
        &lockfile_yaml,
        &driver_artifacts,
    )
    .with_context(|| format!("failed to verify lockfile `{}`", path.display()))?;

    for warning in &report.warnings {
        eprintln!("warning: {}", warning.message);
    }

    if !report.is_ok() {
        let details = report
            .errors
            .iter()
            .map(|issue| issue.message.as_str())
            .collect::<Vec<_>>()
            .join("; ");
        bail!("lockfile verification failed: {details}");
    }

    println!("Lockfile verified: {}", path.display());
    Ok(())
}

fn discover_runtime_driver_artifacts(
    options: &agentenv_core::runtime::RuntimeOptions,
) -> Result<Vec<agentenv_core::driver_artifact::DriverArtifact>> {
    let mut discovery_config = agentenv_core::driver_catalog::DriverDiscoveryConfig::from_env();
    discovery_config.installed_root = options.root.join("drivers");
    agentenv_core::driver_artifact::discover_driver_artifacts(discovery_config, None)
        .context("failed to discover driver artifacts")
}

async fn reproduce(args: ReproduceArgs) -> Result<()> {
    let lockfile_yaml = read_text_file(&args.lockfile, "lockfile")?;
    let env_name = args
        .name
        .unwrap_or_else(|| default_reproduce_env_name(&args.lockfile, &lockfile_yaml));
    let options = runtime_options(args.non_interactive)?;
    let store = CredentialStore::from_default_paths().context("initialize credential store")?;
    let mut provider = CliCredentialProvider {
        store,
        non_interactive: args.non_interactive,
        prompter: Box::new(TerminalCredentialPrompter),
    };

    let result = agentenv_core::runtime::reproduce_env(
        &options,
        &builtin_factory::BuiltInDriverFactory,
        &mut provider,
        &env_name,
        &lockfile_yaml,
    )
    .await
    .with_context(|| format!("failed to reproduce lockfile `{}`", args.lockfile.display()))?;

    render::print_admission_text(&result.admission);
    exit_if_rejected(&result.admission);
    println!(
        "Environment `{env_name}` reproduced from lockfile {}",
        args.lockfile.display()
    );
    Ok(())
}

fn default_reproduce_env_name(path: &Path, lockfile_yaml: &str) -> String {
    match agentenv_core::lockfile::LockfileDocument::from_yaml(lockfile_yaml) {
        Ok(agentenv_core::lockfile::LockfileDocument::Portable(lockfile)) => lockfile.name,
        Ok(agentenv_core::lockfile::LockfileDocument::Legacy(_)) | Err(_) => {
            derive_reproduced_env_name(path)
        }
    }
}

fn resolve_blueprint_path_in_dir(explicit: Option<&Path>, cwd: &Path) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path.to_path_buf());
    }

    let default_path = cwd.join("agentenv.yaml");
    if default_path.is_file() {
        return Ok(default_path);
    }

    bail!(
        "no blueprint provided. Pass `--blueprint <file>` or create `{}` in the current directory",
        default_path.display()
    );
}

fn resolve_create_blueprint_path(
    explicit: Option<&Path>,
    reproduce: Option<&Path>,
    cwd: &Path,
) -> Result<PathBuf> {
    match reproduce {
        None => resolve_blueprint_path_in_dir(explicit, cwd),
        Some(lockfile_path) => resolve_reproduce_blueprint_path(explicit, lockfile_path, cwd),
    }
}

fn resolve_reproduce_blueprint_path(
    explicit: Option<&Path>,
    lockfile_path: &Path,
    cwd: &Path,
) -> Result<PathBuf> {
    let lock_yaml = read_text_file(lockfile_path, "lockfile")?;
    let lockfile = agentenv_core::lockfile::Lockfile::from_yaml(&lock_yaml)
        .with_context(|| format!("failed to parse lockfile `{}`", lockfile_path.display()))?;

    let mut candidates = Vec::new();
    if let Some(path) = explicit {
        candidates.push(path.to_path_buf());
    }
    if let Some(stem) = lockfile_path.file_stem().and_then(|stem| stem.to_str()) {
        let dir = lockfile_path.parent().unwrap_or_else(|| Path::new("."));
        candidates.push(dir.join(format!("{stem}.blueprint.yaml")));
        candidates.push(dir.join(format!("{stem}.yaml")));
    }
    candidates.push(cwd.join("agentenv.yaml"));

    for candidate in candidates {
        if candidate.is_file() && blueprint_matches_lockfile(&candidate, &lockfile)? {
            return Ok(candidate);
        }
    }

    bail!(
        "no blueprint content matched lockfile `{}`",
        lockfile_path.display()
    );
}

fn blueprint_matches_lockfile(
    path: &Path,
    lockfile: &agentenv_core::lockfile::Lockfile,
) -> Result<bool> {
    let yaml = read_text_file(path, "blueprint")?;
    let frozen = agentenv_core::lifecycle::freeze_from_blueprint_yaml(&yaml)
        .with_context(|| format!("failed to freeze candidate blueprint `{}`", path.display()))?;
    let candidate = agentenv_core::lockfile::Lockfile::from_yaml(&frozen).with_context(|| {
        format!(
            "failed to parse generated lockfile for `{}`",
            path.display()
        )
    })?;
    Ok(candidate.blueprint_hash == lockfile.blueprint_hash)
}

fn derive_reproduced_env_name(path: &Path) -> String {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    for suffix in [".lock.yaml", ".lock.yml", ".yaml", ".yml", ".lock"] {
        if let Some(stripped) = file_name.strip_suffix(suffix) {
            if !stripped.is_empty() {
                return stripped.to_string();
            }
        }
    }

    path.file_stem()
        .and_then(|stem| stem.to_str())
        .filter(|stem| !stem.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| "reproduced-env".to_string())
}

fn overlay_from_dockerfile(yaml: &str, from: &Path, cwd: &Path) -> Result<String> {
    let dockerfile_path = resolve_dockerfile_path(from, cwd)?;
    let mut value: serde_yaml::Value =
        serde_yaml::from_str(yaml).context("failed to parse blueprint YAML")?;
    let root = value
        .as_mapping_mut()
        .context("blueprint YAML root must be a mapping")?;
    let sandbox_key = serde_yaml::Value::String("sandbox".to_owned());
    let sandbox = root
        .get_mut(&sandbox_key)
        .and_then(serde_yaml::Value::as_mapping_mut)
        .context("blueprint must contain a sandbox mapping")?;

    let mut image = serde_yaml::Mapping::new();
    image.insert(
        serde_yaml::Value::String("source".to_owned()),
        serde_yaml::Value::String("byo".to_owned()),
    );
    image.insert(
        serde_yaml::Value::String("dockerfile".to_owned()),
        serde_yaml::Value::String(dockerfile_path.display().to_string()),
    );
    sandbox.insert(
        serde_yaml::Value::String("image".to_owned()),
        serde_yaml::Value::Mapping(image),
    );

    serde_yaml::to_string(&value).context("failed to render blueprint YAML")
}

fn resolve_dockerfile_path(path: &Path, cwd: &Path) -> Result<PathBuf> {
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };
    let canonical = fs::canonicalize(&candidate)
        .with_context(|| format!("failed to resolve Dockerfile `{}`", candidate.display()))?;
    if !canonical.is_file() {
        bail!("Dockerfile `{}` is not a file", canonical.display());
    }
    Ok(canonical)
}

fn read_text_file(path: &Path, description: &str) -> Result<String> {
    fs::read_to_string(path)
        .with_context(|| format!("failed to read {description} file `{}`", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentenv_core::runtime::CredentialProvider;
    use agentenv_credstore::CredentialStoreConfig;
    use agentenv_proto::{CredentialKind, CredentialRequirement, ValidatorSpec};
    use std::{
        env,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn cli_includes_commands() {
        let command = Cli::command();
        let subcommands = command
            .get_subcommands()
            .map(|subcommand| subcommand.get_name().to_string())
            .collect::<Vec<_>>();

        assert_eq!(
            subcommands,
            vec![
                "create".to_string(),
                "enter".to_string(),
                "resume".to_string(),
                "sessions".to_string(),
                "list".to_string(),
                "destroy".to_string(),
                "uninstall".to_string(),
                "describe".to_string(),
                "status".to_string(),
                "logs".to_string(),
                "stats".to_string(),
                "audit".to_string(),
                "metrics".to_string(),
                "approvals".to_string(),
                "term".to_string(),
                "snapshot".to_string(),
                "fork".to_string(),
                "exec".to_string(),
                "blueprint".to_string(),
                "credentials".to_string(),
                "drivers".to_string(),
                "verify-blueprint".to_string(),
                "verify".to_string(),
                "freeze".to_string(),
                "reproduce".to_string(),
            ]
        );
    }

    #[test]
    fn reproduce_default_name_uses_portable_lockfile_name() {
        let temp_dir = make_temp_dir("reproduce-success");
        let out_path = temp_dir.join("demo.lock.yaml");
        let rendered = r#"
version: 0.2.0
driver_protocol_version: "1.0"
name: demo-portable
blueprint_hash: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
composition:
  version: 0.1.0
  min_agentenv_version: 0.0.1-alpha0
  sandbox:
    driver: openshell
    version: 0.0.1-alpha0
  agent:
    driver: codex
    version: 0.0.1-alpha0
  context:
    driver: filesystem
    version: 0.0.1-alpha0
  policy:
    tier: restricted
    presets: []
policy:
  declared:
    tier: restricted
    presets: []
  resolved:
    network:
      reloadability: hot_reload
    filesystem:
      reloadability: locked_at_create
    process:
      reloadability: locked_at_create
      run_as_user: sandbox
      run_as_group: sandbox
      profile: restricted
    inference:
      reloadability: hot_reload
drivers:
  sandbox:
    kind: sandbox
    name: openshell
    version: 0.0.1-alpha0
    source: built-in
    digest: sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
  agent:
    kind: agent
    name: codex
    version: 0.0.1-alpha0
    source: built-in
    digest: sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
  context:
    kind: context
    name: filesystem
    version: 0.0.1-alpha0
    source: built-in
    digest: sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
"#;
        fs::write(&out_path, rendered).unwrap();

        assert_eq!(
            default_reproduce_env_name(&out_path, rendered),
            "demo-portable"
        );
    }

    #[test]
    fn reproduce_env_name_comes_from_lockfile_path() {
        assert_eq!(
            derive_reproduced_env_name(Path::new("/tmp/demo.lock.yaml")),
            "demo"
        );
        assert_eq!(
            derive_reproduced_env_name(Path::new("/tmp/agentenv.lock")),
            "agentenv"
        );
    }

    #[test]
    fn create_from_dockerfile_overlay_sets_byo_image() {
        let temp_dir = make_temp_dir("create-from-overlay");
        let dockerfile_dir = temp_dir.join("enterprise-sandbox");
        fs::create_dir_all(&dockerfile_dir).unwrap();
        let dockerfile = dockerfile_dir.join("Containerfile");
        fs::write(&dockerfile, "FROM alpine:3.20\n").unwrap();
        let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: filesystem
  mount: ~/projects
policy:
  tier: restricted
  presets: []
"#;

        let rendered = overlay_from_dockerfile(
            yaml,
            Path::new("enterprise-sandbox/Containerfile"),
            &temp_dir,
        )
        .unwrap();
        let value: serde_yaml::Value = serde_yaml::from_str(&rendered).unwrap();
        let image = value["sandbox"]["image"].as_mapping().unwrap();

        assert_eq!(
            image
                .get(serde_yaml::Value::String("source".to_owned()))
                .and_then(serde_yaml::Value::as_str),
            Some("byo")
        );
        assert_eq!(
            image
                .get(serde_yaml::Value::String("dockerfile".to_owned()))
                .and_then(serde_yaml::Value::as_str),
            Some(
                fs::canonicalize(&dockerfile)
                    .unwrap()
                    .to_string_lossy()
                    .as_ref()
            )
        );
        assert!(
            image
                .get(serde_yaml::Value::String("expected_digest".to_owned()))
                .is_none(),
            "CLI --from should not invent an expected digest"
        );
    }

    #[test]
    fn optional_credential_validator_errors_are_preserved() {
        let store_root = make_temp_dir("optional-credential-validation");
        let name = format!(
            "AGENTENV_OPTIONAL_TOKEN_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        fs::write(
            store_root.join("credentials.json"),
            serde_json::json!({
                "values": {
                    name.clone(): "bad-token"
                }
            })
            .to_string(),
        )
        .unwrap();
        let store = CredentialStore::new(CredentialStoreConfig::from_root_dir(&store_root))
            .expect("credential store");
        let mut provider = CliCredentialProvider {
            store,
            non_interactive: true,
            prompter: Box::new(StaticCredentialPrompt {
                value: SecretString::new("unused"),
            }),
        };
        let requirement = CredentialRequirement {
            name,
            kind: CredentialKind::ApiKey,
            required: false,
            description: "optional test token".to_owned(),
            validator: Some(ValidatorSpec::Regex {
                pattern: "^sk-".to_owned(),
            }),
        };

        let error = CredentialProvider::resolve(&mut provider, &requirement)
            .expect_err("optional validator failures must not be suppressed");

        assert!(
            error.to_string().contains("failed validation"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn events_sink_webhook_rejects_loopback_with_ssrf_validation() {
        let root = make_temp_dir("events-sink-webhook-ssrf");
        let options = agentenv_core::runtime::RuntimeOptions {
            root,
            log_level: agentenv_proto::LogLevel::Info,
            non_interactive: true,
        };
        let sinks = vec!["webhook:https://127.0.0.1/events".to_owned()];

        let error = match build_event_dispatcher(&options, None, &sinks) {
            Ok(_) => panic!("webhook sink loopback URL must be rejected"),
            Err(error) => error,
        };

        let rendered = format!("{error:#}");
        assert!(
            rendered.contains("outbound URL"),
            "unexpected error: {rendered}"
        );
    }

    #[tokio::test]
    async fn create_time_events_do_not_materialize_final_env_dir() {
        let root = make_temp_dir("create-time-events-global-only");
        let options = agentenv_core::runtime::RuntimeOptions {
            root: root.clone(),
            log_level: agentenv_proto::LogLevel::Info,
            non_interactive: true,
        };
        let env_dir = root.join("envs").join("demo");
        let dispatcher = build_event_dispatcher(&options, Some("demo"), &[]).unwrap();
        let emitter = AuditingEventEmitter::new(
            dispatcher.emitter(),
            audit_signing_key_path(&options),
            audit_write_db_paths(&options, Some("demo")).unwrap(),
        );

        emitter.emit(
            ActivityEvent::new(
                "2026-04-26T12:00:00Z",
                ActivityKind::CredentialInjected,
                ActivityResult::Ok,
                "trace-create-event",
            )
            .with_env("demo")
            .with_subject_value("name", serde_json::json!("OPENAI_API_KEY")),
        );
        emitter.check_audit().unwrap();
        dispatcher.flush().await.unwrap();

        assert!(
            !env_dir.exists(),
            "create-time observability must not create `{}` before runtime commit",
            env_dir.display()
        );
        assert!(global_events_db_path(&options).is_file());
    }

    #[tokio::test]
    async fn destroy_time_events_do_not_recreate_removed_env_dir() {
        let root = make_temp_dir("destroy-time-events-global-only");
        let options = agentenv_core::runtime::RuntimeOptions {
            root: root.clone(),
            log_level: agentenv_proto::LogLevel::Info,
            non_interactive: true,
        };
        let env_dir = root.join("envs").join("demo");
        fs::create_dir_all(&env_dir).unwrap();
        let dispatcher = build_destroy_event_dispatcher(&options, &[]).unwrap();
        let emitter = AuditingEventEmitter::new(
            dispatcher.emitter(),
            audit_signing_key_path(&options),
            audit_destroy_write_db_paths(&options).unwrap(),
        );

        emitter.emit(
            ActivityEvent::new(
                "2026-04-26T12:00:00Z",
                ActivityKind::SandboxDestroy,
                ActivityResult::Ok,
                "trace-destroy-event",
            )
            .with_env("demo"),
        );
        emitter.check_audit().unwrap();
        fs::remove_dir_all(&env_dir).unwrap();
        dispatcher.flush().await.unwrap();

        assert!(
            !env_dir.exists(),
            "destroy-time observability must not recreate `{}` after runtime removal",
            env_dir.display()
        );
        assert!(global_events_db_path(&options).is_file());
    }

    #[test]
    fn cli_event_timestamps_are_rfc3339() {
        let ts = now_event_ts();

        assert!(
            ts.contains('T') && ts.ends_with('Z') && !ts.starts_with("unix:"),
            "timestamp must be RFC3339 UTC, got `{ts}`"
        );
    }

    #[tokio::test]
    async fn events_sink_otel_registers_dispatcher_sink_when_supported() {
        let root = make_temp_dir("events-sink-otel");
        let options = agentenv_core::runtime::RuntimeOptions {
            root,
            log_level: agentenv_proto::LogLevel::Info,
            non_interactive: true,
        };
        let sinks = vec!["otel:grpc://collector:4317".to_owned()];

        let dispatcher = match build_event_dispatcher(&options, None, &sinks) {
            Ok(dispatcher) => dispatcher,
            Err(error) => {
                let rendered = format!("{error:#}");
                assert!(
                    rendered.contains("events sink requires feature `otel`"),
                    "unexpected error: {rendered}"
                );
                return;
            }
        };

        let sink_names = dispatcher
            .counters()
            .sink_snapshots()
            .into_iter()
            .map(|snapshot| snapshot.name)
            .collect::<Vec<_>>();
        assert!(
            sink_names.contains(&"otel"),
            "dispatcher sinks did not include otel: {sink_names:?}"
        );
        dispatcher.flush().await.unwrap();
    }

    #[test]
    fn interactive_provider_prompts_and_stores_missing_required_credential() {
        let store_root = make_temp_dir("interactive-credential-prompt");
        let name = format!("AGENTENV_PROMPTED_TOKEN_{}", unique_test_suffix());
        let store = CredentialStore::new(CredentialStoreConfig::from_root_dir(&store_root))
            .expect("credential store");
        let mut provider = CliCredentialProvider {
            store,
            non_interactive: false,
            prompter: Box::new(StaticCredentialPrompt {
                value: SecretString::new("sk-from-prompt"),
            }),
        };
        let requirement = CredentialRequirement {
            name: name.clone(),
            kind: CredentialKind::ApiKey,
            required: true,
            description: "prompted test token".to_owned(),
            validator: Some(ValidatorSpec::Regex {
                pattern: "^sk-".to_owned(),
            }),
        };

        let secret = CredentialProvider::resolve(&mut provider, &requirement)
            .expect("prompted credential should resolve")
            .expect("required credential should be present");

        assert_eq!(secret.expose_secret(), "sk-from-prompt");
        let stored = provider
            .store
            .resolve(&name, &requirement)
            .expect("prompted credential should be stored");
        assert_eq!(stored.expose_secret(), "sk-from-prompt");
    }

    struct StaticCredentialPrompt {
        value: SecretString,
    }

    impl super::CredentialPrompter for StaticCredentialPrompt {
        fn prompt(
            &mut self,
            _requirement: &CredentialRequirement,
        ) -> agentenv_core::runtime::RuntimeResult<SecretString> {
            Ok(self.value.clone())
        }
    }

    fn make_temp_dir(prefix: &str) -> PathBuf {
        let unique = format!("{prefix}-{}", unique_test_suffix());
        let path = env::temp_dir().join(unique);
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn unique_test_suffix() -> String {
        format!(
            "{}-{}",
            process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )
    }
}
