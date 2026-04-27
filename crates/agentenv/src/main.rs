use std::{
    collections::BTreeMap,
    fs,
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use agentenv_core::admission::{AdmissionReport, AdmissionStatus, ReasonCode};
use agentenv_core::driver_catalog::{DiscoveredDriver, DriverCatalog};
use agentenv_credstore::{CredentialStore, CredentialStoreError, SecretString};
use agentenv_events::{
    audit::{AuditPolicy, AuditSigningKey, AuditStore},
    metrics::{render_prometheus, EnvMetricRow, MetricsSnapshot, SinkCounterMetric},
    sink::{JsonlSink, SqliteSink},
    store::{EventQuery, SqliteEventStore, StoredEvent},
    ActivityEvent, ActivityKind, ActivityResult, EventDispatcher, EventEmitter, EventSink,
    SinkConfig,
};
use anyhow::{bail, Context, Result};
use clap::{Args, CommandFactory, Parser, Subcommand};
use hyper::{Method, StatusCode};
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing_subscriber::EnvFilter;

mod builtin_factory;
mod render;

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
    List(ListArgs),
    Destroy(DestroyArgs),
    Describe(DescribeArgs),
    Status(StatusArgs),
    Logs(LogsArgs),
    Stats(StatsArgs),
    Audit(AuditArgs),
    Metrics(MetricsArgs),
    Exec(ExecArgs),
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
        Some(Commands::List(args)) => run_list(args),
        Some(Commands::Destroy(args)) => run_destroy(args, &cli.events_sink).await,
        Some(Commands::Describe(args)) => run_describe(args),
        Some(Commands::Status(args)) => run_status(args).await,
        Some(Commands::Logs(args)) => run_logs(args).await,
        Some(Commands::Stats(args)) => run_stats(args),
        Some(Commands::Audit(args)) => run_audit(args),
        Some(Commands::Metrics(args)) => run_metrics(args).await,
        Some(Commands::Exec(args)) => run_exec(args, &cli.events_sink).await,
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
        {
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
        let emitter = AuditingEventEmitter::new(
            dispatcher.emitter(),
            audit_signing_key_path(&options),
            audit_write_db_paths(&options, Some(&args.name))?,
        );
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
            &emitter,
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
                render::print_error_json(&error);
                exit_process(render::exit_for_error(&error).code());
            }
            Err(error) => {
                flush_dispatcher_best_effort(&dispatcher).await;
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
    let dispatcher = build_event_dispatcher(&options, Some(&args.name), event_sink_args)?;
    let emitter = AuditingEventEmitter::new(
        dispatcher.emitter(),
        audit_signing_key_path(&options),
        audit_write_db_paths(&options, Some(&args.name))?,
    );
    let report = match agentenv_core::runtime::destroy_env_observed(
        &options,
        &builtin_factory::BuiltInDriverFactory,
        &args.name,
        &emitter,
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
    if let Some(env) = args.env.as_deref() {
        agentenv_core::runtime::describe_env(&options, env)?;
    }
    let db_path = activity_reader_db_path(&options, args.env.as_deref())?;
    let store = SqliteEventStore::open(&db_path)
        .with_context(|| format!("open activity database `{}`", db_path.display()))?;

    let scope = args.env.as_deref().unwrap_or("global");
    println!("activity summary for {scope}");
    println!("kind/result counts:");
    for row in store.counts_by_kind_result()? {
        if args
            .env
            .as_deref()
            .is_none_or(|env| row.env.as_deref() == Some(env))
        {
            println!(
                "  {} {} {}",
                activity_kind_label(row.kind),
                activity_result_label(row.result),
                row.count
            );
        }
    }

    println!("policy blocks:");
    for row in store.policy_blocks_by_kind_driver()? {
        println!(
            "  {} {} {}",
            row.kind,
            row.driver.as_deref().unwrap_or("-"),
            row.count
        );
    }

    println!("pending approvals: {}", store.approvals_pending_count()?);
    let latency_rows = store.sandbox_latency_rows()?;
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
                AuditFormat::Jsonl => {
                    store.export_jsonl_range(&mut handle, from.as_deref(), to.as_deref())?
                }
                AuditFormat::Csv => {
                    store.export_csv_range(&mut handle, from.as_deref(), to.as_deref())?
                }
            }
            Ok(())
        }
        AuditCommand::Verify { env } => {
            let store = AuditStore::open(audit_reader_db_path(&options, env.as_deref())?)
                .with_context(|| audit_store_context(env.as_deref()))?;
            let report = store.verify()?;
            if report.valid {
                println!("valid: {} entries checked", report.checked_entries);
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

async fn run_exec(args: ExecArgs, event_sink_args: &[String]) -> Result<()> {
    let options = runtime_options(true)?;
    let dispatcher = build_event_dispatcher(&options, Some(&args.name), event_sink_args)?;
    let emitter = AuditingEventEmitter::new(
        dispatcher.emitter(),
        audit_signing_key_path(&options),
        audit_write_db_paths(&options, Some(&args.name))?,
    );
    let result = match agentenv_core::runtime::exec_env_observed(
        &options,
        &builtin_factory::BuiltInDriverFactory,
        &args.name,
        args.cmd,
        &emitter,
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
            return Err(error.into());
        }
    };
    print!("{}", result.stdout);
    eprint!("{}", result.stderr);
    io::stdout().flush().context("flush forwarded stdout")?;
    io::stderr().flush().context("flush forwarded stderr")?;
    process::exit(result.status);
}

fn exit_json_error(reason_code: ReasonCode, error: impl std::fmt::Display) -> ! {
    render::print_error_body_json(reason_code, error.to_string());
    exit_process(render::exit_for_reason(reason_code).code());
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
    agentenv_core::runtime::describe_env(options, name)?;
    let kind = parse_activity_kind_opt(kind_filter)?;
    let db_path = env_events_db_path(options, name)?;
    if db_path.is_file() {
        match print_sqlite_activity_logs(&db_path, name, kind, json, None) {
            Ok(after_id) => {
                if follow {
                    return follow_sqlite_activity_logs(&db_path, name, kind, json, after_id).await;
                }
                return Ok(());
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

    let global_db_path = global_events_db_path(options);
    if global_db_path.is_file() {
        match print_sqlite_activity_logs(&global_db_path, name, kind, json, None) {
            Ok(after_id) => {
                if follow {
                    return follow_sqlite_activity_logs(
                        &global_db_path,
                        name,
                        kind,
                        json,
                        after_id,
                    )
                    .await;
                }
                return Ok(());
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
        let Ok(event) = serde_json::from_str::<ActivityEvent>(line) else {
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
            SinkConfig::OtelGrpc { .. } | SinkConfig::Webhook { .. } => {}
        }
    }
    Ok(EventDispatcher::with_sinks(1024, sinks))
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
        sinks.push(Box::new(SqliteSink::new(env_db_path)));
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

fn audit_reader_db_path(
    options: &agentenv_core::runtime::RuntimeOptions,
    env: Option<&str>,
) -> Result<PathBuf> {
    if let Some(env) = env {
        agentenv_core::runtime::describe_env(options, env)?;
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
        paths.push(env_events_db_path(options, env)?);
    }
    Ok(paths)
}

fn env_events_db_path(
    options: &agentenv_core::runtime::RuntimeOptions,
    name: &str,
) -> Result<PathBuf> {
    let env_name = agentenv_core::env::validate_env_name(name)?;
    let paths = agentenv_core::env::EnvPaths::new(options.root.clone(), env_name);
    Ok(paths.env_dir().join("events.db"))
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
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => format!("unix:{}", duration.as_secs()),
        Err(_) => "unix:0".to_owned(),
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
                "list".to_string(),
                "destroy".to_string(),
                "describe".to_string(),
                "status".to_string(),
                "logs".to_string(),
                "stats".to_string(),
                "audit".to_string(),
                "metrics".to_string(),
                "exec".to_string(),
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
