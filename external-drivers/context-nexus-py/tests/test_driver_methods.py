from agentenv_context_nexus.driver import NexusContextDriver
from agentenv_context_nexus.protocol import ERROR_SCHEMA_VERSION_INCOMPATIBLE


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


def test_hub_mcp_endpoint_uses_hub_url_without_headers():
    driver = NexusContextDriver()
    provision = call(driver, "provision", {"config": {"mode": "hub", "hub_url": "https://nexus.example.com"}})
    handle = provision["result"]["handle"]

    response = call(driver, "mcp_endpoint", {"handle": handle})

    assert response["result"]["url"] == "https://nexus.example.com"
    assert response["result"]["transport"] == "http"
    assert response["result"]["headers"] == {}
