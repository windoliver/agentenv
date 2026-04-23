use std::{
    fs,
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process, thread,
    time::Duration,
};

use agentenv_core::admission::{AdmissionReport, AdmissionStatus, ReasonCode};
use agentenv_core::driver_catalog::{DiscoveredDriver, DriverCatalog};
use agentenv_credstore::{CredentialStore, CredentialStoreError, SecretString};
use anyhow::{bail, Context, Result};
use clap::{Args, CommandFactory, Parser, Subcommand};
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
    name: String,
    #[arg(long)]
    follow: bool,
    #[arg(long)]
    driver: Option<String>,
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
        Some(Commands::Create(args)) => run_create(args).await,
        Some(Commands::Enter(args)) => run_enter(args).await,
        Some(Commands::List(args)) => run_list(args),
        Some(Commands::Destroy(args)) => run_destroy(args).await,
        Some(Commands::Describe(args)) => run_describe(args),
        Some(Commands::Status(args)) => run_status(args).await,
        Some(Commands::Logs(args)) => run_logs(args).await,
        Some(Commands::Exec(args)) => run_exec(args).await,
        Some(Commands::Credentials(command)) => run_credentials(command),
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

async fn run_create(args: CreateArgs) -> Result<()> {
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
        let store = CredentialStore::from_default_paths().context("initialize credential store")?;
        let mut provider = CliCredentialProvider {
            store,
            non_interactive: args.non_interactive,
            prompter: Box::new(TerminalCredentialPrompter),
        };
        match agentenv_core::runtime::create_env(
            &options,
            &factory,
            &mut provider,
            &args.name,
            &blueprint_yaml,
        )
        .await
        {
            Ok(result) if args.json => {
                render::print_json(&result.admission)?;
                exit_if_rejected(&result.admission);
                Ok(())
            }
            Ok(result) => {
                render::print_admission_text(&result.admission);
                exit_if_rejected(&result.admission);
                println!("Next: agentenv enter {}", args.name);
                Ok(())
            }
            Err(error) if args.json => {
                render::print_error_json(&error);
                exit_process(render::exit_for_error(&error).code());
            }
            Err(error) => Err(error.into()),
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

async fn run_destroy(args: DestroyArgs) -> Result<()> {
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
    let report = agentenv_core::runtime::destroy_env(
        &options,
        &builtin_factory::BuiltInDriverFactory,
        &args.name,
    )
    .await?;
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
    if let Some(driver) = args.driver.as_deref().filter(|driver| *driver != "sandbox") {
        print_event_logs(&options, &args.name, Some(driver), args.follow)?;
        return Ok(());
    }
    if args.follow {
        let _guard = agentenv_core::runtime::start_logs_stream_env(
            &options,
            &builtin_factory::BuiltInDriverFactory,
            &args.name,
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
        &args.name,
        args.follow,
    )
    .await?;
    for entry in logs.entries {
        println!("{} {:?} {}", entry.ts, entry.level, entry.msg);
    }
    Ok(())
}

async fn run_exec(args: ExecArgs) -> Result<()> {
    let options = runtime_options(true)?;
    let result = agentenv_core::runtime::exec_env(
        &options,
        &builtin_factory::BuiltInDriverFactory,
        &args.name,
        args.cmd,
    )
    .await?;
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

fn run_credentials(args: CredentialsArgs) -> Result<()> {
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
