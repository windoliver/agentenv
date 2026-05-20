use std::{
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::{self, Command, Stdio},
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

use agentenv_core::eval::{
    build_eval_plan, eval_status_from_runners, load_eval_suite_from_yaml, EvalPlan, EvalPlanInput,
    EvalReport, EvalRunnerReport, EvalRunnerStatus,
};
use anyhow::Result;
use clap::Args;
use serde::Serialize;

#[derive(Debug, Args)]
pub(crate) struct EvalArgs {
    pub(crate) blueprint: PathBuf,
    #[arg(long, value_name = "FILE")]
    pub(crate) suite: PathBuf,
    #[arg(long, value_name = "NAME")]
    pub(crate) env: Option<String>,
    #[arg(long, value_name = "FILE")]
    pub(crate) output: Option<PathBuf>,
    #[arg(long)]
    pub(crate) json: bool,
    #[arg(long)]
    pub(crate) keep_env: bool,
    #[arg(
        long,
        env = "AGENTENV_NON_INTERACTIVE",
        action = clap::ArgAction::SetTrue,
        value_parser = clap::builder::BoolishValueParser::new()
    )]
    pub(crate) non_interactive: bool,
}

#[derive(Debug, Serialize)]
struct EvalErrorJson {
    status: &'static str,
    error: String,
}

const EVAL_RUNNER_LOG_LIMIT_BYTES: usize = 1024 * 1024;
const EVAL_RUNNER_LOG_TRUNCATED_MARKER: &[u8] = b"\n[agentenv log truncated]\n";

pub(crate) async fn run_eval(args: EvalArgs) -> Result<()> {
    match run_eval_inner(args).await {
        Ok(report) => exit_for_report(&report),
        Err(error) => {
            if error.json {
                print_json(&EvalErrorJson {
                    status: "infrastructure-error",
                    error: error.message.clone(),
                })?;
            }
            eprintln!("error: {}", error.message);
            process::exit(2);
        }
    }
}

struct EvalCliError {
    message: String,
    json: bool,
}

impl EvalCliError {
    fn new(message: impl Into<String>, json: bool) -> Self {
        Self {
            message: message.into(),
            json,
        }
    }
}

async fn run_eval_inner(args: EvalArgs) -> Result<EvalReport, EvalCliError> {
    let options = crate::runtime_options(args.non_interactive)
        .map_err(|error| EvalCliError::new(format!("{error:#}"), args.json))?;
    let suite_yaml = fs::read_to_string(&args.suite).map_err(|error| {
        EvalCliError::new(
            format!(
                "failed to read eval suite file `{}`: {error}",
                args.suite.display()
            ),
            args.json,
        )
    })?;
    let suite = load_eval_suite_from_yaml(&suite_yaml)
        .map_err(|error| EvalCliError::new(error.to_string(), args.json))?;
    let blueprint_yaml = fs::read_to_string(&args.blueprint).map_err(|error| {
        EvalCliError::new(
            format!(
                "failed to read blueprint file `{}`: {error}",
                args.blueprint.display()
            ),
            args.json,
        )
    })?;
    agentenv_core::lifecycle::verify_blueprint_yaml(&blueprint_yaml).map_err(|error| {
        EvalCliError::new(
            format!(
                "failed to verify blueprint `{}`: {error}",
                args.blueprint.display()
            ),
            args.json,
        )
    })?;

    let run_id = new_eval_run_id();
    let _keep_env = args.keep_env;
    let run_root = options.root.join("evals");
    let plan = build_eval_plan(EvalPlanInput {
        suite,
        suite_path: &args.suite,
        blueprint_path: &args.blueprint,
        run_root: &run_root,
        env_override: args.env.as_deref(),
        output_override: args.output.as_deref(),
        run_id: &run_id,
    })
    .map_err(|error| EvalCliError::new(error.to_string(), args.json))?;
    ensure_existing_env(&options, &plan, args.json)?;

    fs::create_dir_all(&plan.run_dir).map_err(|error| {
        EvalCliError::new(
            format!(
                "failed to create eval run directory `{}`: {error}",
                plan.run_dir.display()
            ),
            args.json,
        )
    })?;

    let mut runner_reports = Vec::new();
    for runner in &plan.runners {
        let report = run_promptfoo_runner(runner, &plan, args.json)?;
        runner_reports.push(report);
    }
    let statuses = runner_reports
        .iter()
        .map(|runner| runner.status)
        .collect::<Vec<_>>();
    let status = eval_status_from_runners(&statuses);
    let report = EvalReport {
        suite: plan.suite_name.clone(),
        blueprint: plan.blueprint_path.clone(),
        status,
        run_id,
        report_path: plan.report_path.clone(),
        runners: runner_reports,
    };
    write_report(&plan.report_path, &report, args.json)?;
    render_report(&report, args.json)?;
    Ok(report)
}

fn run_promptfoo_runner(
    runner: &agentenv_core::eval::EvalRunnerPlan,
    plan: &EvalPlan,
    json: bool,
) -> Result<EvalRunnerReport, EvalCliError> {
    let log_slug = safe_runner_log_slug(&runner.id);
    let stdout_path = plan.run_dir.join(format!("{log_slug}-stdout.log"));
    let stderr_path = plan.run_dir.join(format!("{log_slug}-stderr.log"));
    let config = runner.config.as_ref().ok_or_else(|| {
        EvalCliError::new(
            format!("runner `{}` has no Promptfoo config", runner.id),
            json,
        )
    })?;
    let mut command = Command::new(&runner.command);
    command
        .arg("eval")
        .arg("--config")
        .arg(config)
        .arg("--output")
        .arg(&runner.output)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    apply_minimal_runner_process_env(&mut command);
    for (name, value) in &runner.env {
        command.env(name, value);
    }
    command
        .env("AGENTENV_EVAL_ENV", &plan.env_name)
        .env("AGENTENV_EVAL_RUN_DIR", &plan.run_dir)
        .env("AGENTENV_EVAL_BLUEPRINT", &plan.blueprint_path);

    let mut child = command.spawn().map_err(|error| {
        EvalCliError::new(
            format!("failed to start runner `{}`: {error}", runner.id),
            json,
        )
    })?;
    let stdout = child.stdout.take().ok_or_else(|| {
        EvalCliError::new(
            format!("failed to capture runner `{}` stdout", runner.id),
            json,
        )
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        EvalCliError::new(
            format!("failed to capture runner `{}` stderr", runner.id),
            json,
        )
    })?;
    let stdout_capture = spawn_bounded_log_capture(&runner.id, "stdout", stdout_path, stdout, json);
    let stderr_capture = spawn_bounded_log_capture(&runner.id, "stderr", stderr_path, stderr, json);
    let status_result = child.wait().map_err(|error| {
        EvalCliError::new(
            format!("failed to wait for runner `{}`: {error}", runner.id),
            json,
        )
    });
    join_log_capture(stdout_capture, &runner.id, "stdout", json)?;
    join_log_capture(stderr_capture, &runner.id, "stderr", json)?;
    let status = status_result?;
    let exit_code = status.code();
    let runner_status = if status.success() {
        EvalRunnerStatus::Passed
    } else {
        EvalRunnerStatus::Failed
    };
    Ok(EvalRunnerReport {
        id: runner.id.clone(),
        runner_type: runner.runner_type.clone(),
        status: runner_status,
        exit_code,
        artifact: runner.output.clone(),
    })
}

fn apply_minimal_runner_process_env(command: &mut Command) {
    command.env_clear();
    for name in minimal_runner_process_env_names() {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
}

#[cfg(windows)]
fn minimal_runner_process_env_names() -> &'static [&'static str] {
    &["PATH", "PATHEXT", "SystemRoot", "WINDIR", "ComSpec"]
}

#[cfg(not(windows))]
fn minimal_runner_process_env_names() -> &'static [&'static str] {
    &["PATH"]
}

fn spawn_bounded_log_capture<R>(
    runner_id: &str,
    stream_name: &'static str,
    path: PathBuf,
    reader: R,
    json: bool,
) -> thread::JoinHandle<Result<(), EvalCliError>>
where
    R: Read + Send + 'static,
{
    let runner_id = runner_id.to_owned();
    thread::spawn(move || {
        capture_bounded_log(reader, &path).map_err(|error| {
            EvalCliError::new(
                format!(
                    "failed to capture runner `{runner_id}` {stream_name} log `{}`: {error}",
                    path.display()
                ),
                json,
            )
        })
    })
}

fn capture_bounded_log<R: Read>(mut reader: R, path: &Path) -> io::Result<()> {
    let mut file = fs::File::create(path)?;
    let mut written = 0usize;
    let mut truncated = false;
    let mut buffer = [0u8; 8192];

    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let allowed = EVAL_RUNNER_LOG_LIMIT_BYTES
            .saturating_sub(written)
            .min(read);
        if allowed > 0 {
            file.write_all(&buffer[..allowed])?;
            written += allowed;
        }
        if allowed < read {
            truncated = true;
        }
    }

    if truncated {
        file.write_all(EVAL_RUNNER_LOG_TRUNCATED_MARKER)?;
    }
    file.flush()
}

fn join_log_capture(
    handle: thread::JoinHandle<Result<(), EvalCliError>>,
    runner_id: &str,
    stream_name: &str,
    json: bool,
) -> Result<(), EvalCliError> {
    match handle.join() {
        Ok(result) => result,
        Err(_) => Err(EvalCliError::new(
            format!("runner `{runner_id}` {stream_name} log capture thread panicked"),
            json,
        )),
    }
}

fn safe_runner_log_slug(id: &str) -> String {
    let mut slug = String::new();
    let mut last_was_separator = false;
    for ch in id.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
            slug.push(ch);
            last_was_separator = false;
        } else if !last_was_separator {
            slug.push('-');
            last_was_separator = true;
        }
    }
    let slug = slug.trim_matches('-').to_owned();
    if slug.is_empty() {
        "runner".to_owned()
    } else {
        slug
    }
}

fn ensure_existing_env(
    options: &agentenv_core::runtime::RuntimeOptions,
    plan: &EvalPlan,
    json: bool,
) -> Result<(), EvalCliError> {
    match agentenv_core::runtime::describe_env(options, &plan.env_name) {
        Ok(_) => Ok(()),
        Err(agentenv_core::runtime::RuntimeError::Env(
            agentenv_core::env::EnvError::NotFound { .. },
        )) => Err(EvalCliError::new(
            format!("environment `{}` was not found", plan.env_name),
            json,
        )),
        Err(error) => Err(EvalCliError::new(
            format!("failed to inspect environment `{}`: {error}", plan.env_name),
            json,
        )),
    }
}

fn write_report(path: &Path, report: &EvalReport, json: bool) -> Result<(), EvalCliError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            EvalCliError::new(
                format!(
                    "failed to create report directory `{}`: {error}",
                    parent.display()
                ),
                json,
            )
        })?;
    }
    let rendered = serde_json::to_string_pretty(report).map_err(|error| {
        EvalCliError::new(format!("failed to serialize eval report: {error}"), json)
    })?;
    fs::write(path, rendered).map_err(|error| {
        EvalCliError::new(
            format!("failed to write eval report `{}`: {error}", path.display()),
            json,
        )
    })
}

fn render_report(report: &EvalReport, json: bool) -> Result<(), EvalCliError> {
    if json {
        print_json(report).map_err(|error| EvalCliError::new(format!("{error:#}"), true))?;
    } else {
        println!("eval suite: {}", report.suite);
        println!("blueprint: {}", report.blueprint.display());
        println!("status: {}", status_label(report.status));
        println!("report: {}", report.report_path.display());
        println!("runners:");
        for runner in &report.runners {
            println!("  {} {}", runner.id, status_label(runner.status));
        }
    }
    Ok(())
}

fn print_json<T: Serialize>(value: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn exit_for_report(report: &EvalReport) -> Result<()> {
    match report.status {
        EvalRunnerStatus::Passed => Ok(()),
        EvalRunnerStatus::Failed => process::exit(1),
        EvalRunnerStatus::InfrastructureError => process::exit(2),
    }
}

fn status_label(status: EvalRunnerStatus) -> &'static str {
    match status {
        EvalRunnerStatus::Passed => "passed",
        EvalRunnerStatus::Failed => "failed",
        EvalRunnerStatus::InfrastructureError => "infrastructure-error",
    }
}

fn new_eval_run_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    format!("eval-{}-{nanos}", process::id())
}
