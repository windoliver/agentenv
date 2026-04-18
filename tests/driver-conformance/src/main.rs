use std::path::PathBuf;

use anyhow::{Context, Result};

fn main() -> Result<()> {
    let driver_path = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .context("usage: driver-conformance <driver-path>")?;

    driver_conformance::run_standard_suite(&driver_path)?;
    driver_conformance::run_schema_mismatch_suite(&driver_path)?;
    Ok(())
}
