use std::time::Duration;

#[derive(Debug, Clone)]
pub struct TermOptions {
    pub no_color: bool,
    pub refresh_interval: Duration,
}

pub async fn run_terminal<B>(_backend: B, _options: TermOptions) -> anyhow::Result<()>
where
    B: crate::backend::OpsBackend,
{
    Ok(())
}
