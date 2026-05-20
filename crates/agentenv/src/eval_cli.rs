use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

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

pub(crate) async fn run_eval(_args: EvalArgs) -> Result<()> {
    anyhow::bail!("eval runner is not wired yet")
}
