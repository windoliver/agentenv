use std::path::PathBuf;

use anyhow::{Context, Result};

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let first = args
        .next()
        .context("usage: driver-conformance [--context] <driver-path>")?;
    if first == "--context" {
        let driver_path = args
            .next()
            .map(PathBuf::from)
            .context("usage: driver-conformance --context <driver-path>")?;
        driver_conformance::run_context_suite(&driver_path)?;
        driver_conformance::run_schema_mismatch_suite(&driver_path)?;
        return Ok(());
    }

    let driver_path = PathBuf::from(first);
    driver_conformance::run_standard_suite(&driver_path)?;
    driver_conformance::run_schema_mismatch_suite(&driver_path)?;
    Ok(())
}
