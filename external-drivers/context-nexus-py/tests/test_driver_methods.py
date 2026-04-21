import signal
import subprocess

import agentenv_context_nexus.driver as driver_module
import agentenv_context_nexus.nexus as nexus_module
from agentenv_context_nexus.driver import HandleState, NexusContextDriver
from agentenv_context_nexus.protocol import (
    ERROR_RESOURCE_NOT_FOUND,
    ERROR_SCHEMA_VERSION_INCOMPATIBLE,
    JSON_RPC_INVALID_PARAMS,
)


def call(driver, method, params):
    return driver.handle({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})


def test_initialize_reports_context_capabilities():
    response = call(
        NexusContextDriver(),
        "initialize",
        {"schema_version": "1.0", "core_version": "0.0.1", "workdir": "/tmp/agentenv", "log_level": "info"},
    )

    assert response["result"]["driver"]["name"] == "nexus"
    assert response["result"]["driver"]["kind"] == "context"
    assert response["result"]["capabilities"]["supports_zones"] is True


def test_initialize_rejects_schema_major_mismatch():
    response = call(
        NexusContextDriver(),
        "initialize",
        {"schema_version": "2.0", "core_version": "0.0.1", "workdir": "/tmp/agentenv", "log_level": "info"},
    )

    assert response["error"]["code"] == ERROR_SCHEMA_VERSION_INCOMPATIBLE


def test_credential_requirements_declares_nexus_token():
    response = call(NexusContextDriver(), "credential_requirements", {})

    requirement = response["result"]["requirements"][0]
    assert requirement["name"] == "NEXUS_TOKEN"
    assert requirement["kind"] == "token"
    assert requirement["required"] is False


def test_hub_provision_requires_hub_url():
    response = call(NexusContextDriver(), "provision", {"config": {"mode": "hub"}})

    assert response["error"]["code"] == -32602
    assert "hub_url" in response["error"]["message"]


def test_hub_network_rules_parse_host_scheme_and_port():
    driver = NexusContextDriver()
    provision = call(
        driver,
        "provision",
        {"config": {"mode": "hub", "hub_url": "https://nexus.example.com:8443", "zones": ["eng"]}},
    )
    handle = provision["result"]["handle"]

    response = call(driver, "required_network_rules", {"handle": handle})

    target = response["result"]["rules"][0]["target"]
    assert target["kind"] == "host"
    assert target["host"] == "nexus.example.com"
    assert target["scheme"] == "https"
    assert target["port"] == 8443


def test_hub_network_rules_default_https_port():
    driver = NexusContextDriver()
    provision = call(driver, "provision", {"config": {"mode": "hub", "hub_url": "https://nexus.example.com"}})
    handle = provision["result"]["handle"]

    response = call(driver, "required_network_rules", {"handle": handle})

    target = response["result"]["rules"][0]["target"]
    assert target["scheme"] == "https"
    assert target["port"] == 443


def test_hub_mcp_endpoint_uses_hub_url_without_headers():
    driver = NexusContextDriver()
    provision = call(driver, "provision", {"config": {"mode": "hub", "hub_url": "https://nexus.example.com"}})
    handle = provision["result"]["handle"]

    response = call(driver, "mcp_endpoint", {"handle": handle})

    assert response["result"]["url"] == "https://nexus.example.com"
    assert response["result"]["transport"] == "http"
    assert response["result"]["headers"] == {}


def test_start_lite_process_starts_new_session_and_discards_stderr(monkeypatch):
    captured = {}
    sentinel = object()

    def fake_popen(args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return sentinel

    monkeypatch.setattr(nexus_module.subprocess, "Popen", fake_popen)

    process = nexus_module.start_lite_process("/tmp/nexus-data", 8765)

    assert process is sentinel
    assert captured["args"] == [
        "nexus",
        "mcp",
        "serve",
        "--transport",
        "http",
        "--host",
        "127.0.0.1",
        "--port",
        "8765",
    ]
    assert captured["kwargs"]["stderr"] == nexus_module.subprocess.DEVNULL
    assert captured["kwargs"]["start_new_session"] is True
    assert captured["kwargs"]["env"]["NEXUS_DATA_DIR"] == "/tmp/nexus-data"


def test_lite_teardown_signals_process_group_when_pid_available(monkeypatch):
    class FakeProcess:
        pid = 1234

        def __init__(self):
            self.calls = []

        def poll(self):
            self.calls.append(("poll",))
            return None

        def terminate(self):
            self.calls.append(("terminate",))

        def kill(self):
            self.calls.append(("kill",))

        def wait(self, timeout=None):
            self.calls.append(("wait", timeout))
            return 0

    process = FakeProcess()
    signals = []
    monkeypatch.setattr(driver_module.os, "getpgid", lambda pid: 4321)
    monkeypatch.setattr(driver_module.os, "killpg", lambda pgid, sig: signals.append((pgid, sig)))
    driver = NexusContextDriver()
    driver._handles["nexus-lite-test"] = HandleState(
        mode="lite",
        endpoint_url="http://127.0.0.1:7777",
        zones=[],
        process=process,
    )

    response = call(driver, "teardown", {"handle": "nexus-lite-test"})

    assert response["result"] == {}
    assert "nexus-lite-test" not in driver._handles
    assert signals == [(4321, signal.SIGTERM)]
    assert process.calls == [("poll",), ("wait", 5)]


def test_lite_teardown_kills_and_reaps_after_terminate_timeout():
    class FakeProcess:
        def __init__(self):
            self.calls = []
            self.wait_calls = 0

        def poll(self):
            self.calls.append(("poll",))
            return None

        def terminate(self):
            self.calls.append(("terminate",))

        def kill(self):
            self.calls.append(("kill",))

        def wait(self, timeout=None):
            self.wait_calls += 1
            self.calls.append(("wait", timeout))
            if self.wait_calls == 1:
                raise subprocess.TimeoutExpired(cmd="nexus", timeout=timeout)
            return 0

    process = FakeProcess()
    driver = NexusContextDriver()
    driver._handles["nexus-lite-test"] = HandleState(
        mode="lite",
        endpoint_url="http://127.0.0.1:7777",
        zones=[],
        process=process,
    )

    response = call(driver, "teardown", {"handle": "nexus-lite-test"})

    assert response["result"] == {}
    assert "nexus-lite-test" not in driver._handles
    assert process.calls == [("poll",), ("terminate",), ("wait", 5), ("kill",), ("wait", None)]


def test_provision_rejects_non_object_params_without_creating_handle():
    driver = NexusContextDriver()

    response = driver.handle({"jsonrpc": "2.0", "id": 1, "method": "provision", "params": []})

    assert response["error"]["code"] == JSON_RPC_INVALID_PARAMS
    assert driver._handles == {}


def test_lite_provision_rejects_falsey_malformed_config_fields(monkeypatch):
    def fail_start_lite_process(_data_dir, _port):
        raise AssertionError("start_lite_process should not be called for invalid config")

    monkeypatch.setattr(driver_module, "start_lite_process", fail_start_lite_process)

    for config in ({"zones": ""}, {"mcp_port": []}, {"data_dir": []}):
        driver = NexusContextDriver()

        response = call(driver, "provision", {"config": config})

        assert response["error"]["code"] == JSON_RPC_INVALID_PARAMS
        assert driver._handles == {}


def test_lite_provision_rejects_malformed_mcp_ports(monkeypatch):
    def fail_start_lite_process(_data_dir, _port):
        raise AssertionError("start_lite_process should not be called for invalid mcp_port")

    monkeypatch.setattr(driver_module, "start_lite_process", fail_start_lite_process)

    for mcp_port in (True, 8000.9, 0, 65536):
        driver = NexusContextDriver()

        response = call(driver, "provision", {"config": {"mcp_port": mcp_port}})

        assert response["error"]["code"] == JSON_RPC_INVALID_PARAMS
        assert driver._handles == {}


def test_handle_methods_reject_missing_and_non_string_handles():
    driver = NexusContextDriver()

    for method in ("mcp_endpoint", "required_network_rules", "status", "teardown"):
        for params in ({}, {"handle": None}, {"handle": 7}):
            response = call(driver, method, params)

            assert response["error"]["code"] == JSON_RPC_INVALID_PARAMS


def test_handle_methods_report_unknown_string_handles_as_not_found():
    driver = NexusContextDriver()

    for method in ("mcp_endpoint", "required_network_rules", "status", "teardown"):
        response = call(driver, method, {"handle": "missing"})

        assert response["error"]["code"] == ERROR_RESOURCE_NOT_FOUND
