use std::{
    fs,
    path::{Path, PathBuf},
    process,
    time::{SystemTime, UNIX_EPOCH},
};

use agentenv_core::eval::{
    build_eval_plan, load_eval_suite_from_yaml, EvalPlan, EvalPlanInput, EvalReport,
    EvalRunnerStatus,
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

    let report_path = args
        .output
        .clone()
        .unwrap_or_else(|| plan.run_dir.join("report.json"));
    let report = EvalReport {
        suite: plan.suite_name.clone(),
        blueprint: plan.blueprint_path.clone(),
        status: EvalRunnerStatus::Passed,
        run_id,
        report_path: report_path.clone(),
        runners: Vec::new(),
    };
    write_report(&report_path, &report, args.json)?;
    render_report(&report, args.json)?;
    Ok(report)
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
