use std::path::Path;

use driver_conformance::{run_schema_mismatch_suite, run_standard_suite};

#[test]
fn mock_driver_passes_standard_conformance_suite() {
    run_standard_suite(Path::new(env!("CARGO_BIN_EXE_mock-driver")))
        .expect("mock driver should satisfy the standard conformance suite");
}

#[test]
fn mock_driver_reports_schema_mismatch_cleanly() {
    run_schema_mismatch_suite(Path::new(env!("CARGO_BIN_EXE_mock-driver")))
        .expect("mock driver should report schema mismatches clearly");
}
