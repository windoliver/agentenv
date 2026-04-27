use std::io::BufReader;
use std::path::Path;
use std::process::{Command, Stdio};

use driver_conformance::{
    read_framed_json, run_schema_mismatch_suite, run_standard_suite, write_framed_json,
};
use serde_json::json;

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

#[test]
fn mock_driver_emits_log_and_activity_notifications_before_preflight_response() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_mock-driver"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn mock driver");
    let mut stdin = child.stdin.take().expect("mock driver stdin");
    let stdout = child.stdout.take().expect("mock driver stdout");
    let mut stdout = BufReader::new(stdout);

    write_framed_json(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "schema_version": agentenv_proto::SCHEMA_VERSION,
                "core_version": "0.0.1",
                "workdir": "/tmp/agentenv",
                "log_level": "info"
            }
        }),
    )
    .expect("send initialize request");
    let initialize = read_framed_json(&mut stdout).expect("read initialize response");
    assert_eq!(initialize["jsonrpc"], json!("2.0"));
    assert_eq!(initialize["id"], json!(1));
    assert!(initialize["result"].is_object());

    write_framed_json(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "preflight",
            "params": {}
        }),
    )
    .expect("send preflight request");
    let log_notification = read_framed_json(&mut stdout).expect("read log notification");
    let activity_notification = read_framed_json(&mut stdout).expect("read activity notification");
    let preflight = read_framed_json(&mut stdout).expect("read preflight response");

    assert_eq!(log_notification["method"], json!("event/log"));
    assert_eq!(
        log_notification["params"]["kv"]["driver"],
        json!("mock-driver")
    );
    assert_eq!(activity_notification["method"], json!("event/activity"));
    assert_eq!(
        activity_notification["params"]["kind"],
        json!("sandbox_create")
    );
    assert_eq!(
        activity_notification["params"]["trace_id"],
        json!("trace-mock-driver")
    );
    assert_eq!(preflight["id"], json!(2));
    assert_eq!(preflight["result"]["ok"], json!(true));

    write_framed_json(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "shutdown",
            "params": {}
        }),
    )
    .expect("send shutdown request");
    let shutdown = read_framed_json(&mut stdout).expect("read shutdown response");
    assert_eq!(shutdown["id"], json!(3));
    assert!(shutdown["result"].is_object());
    let status = child.wait().expect("wait for mock driver");
    assert!(status.success());
}
