import yaml

import pytest

from agentenv_agent_hermes.hermes import HermesDriver
from agentenv_agent_hermes.protocol import (
    ERROR_CAPABILITY_MISSING,
    ERROR_SCHEMA_VERSION_INCOMPATIBLE,
    RpcError,
    SCHEMA_VERSION,
    assert_schema_compatible,
)


def test_schema_version_accepts_matching_major_versions():
    assert_schema_compatible(SCHEMA_VERSION)
    assert_schema_compatible("1.9")


def test_schema_version_rejects_mismatched_major_versions():
    with pytest.raises(ValueError, match="major schema versions match"):
        assert_schema_compatible("2.0")


def test_rpc_error_stringifies_to_message():
    assert str(RpcError(-32002, "schema mismatch")) == "schema mismatch"


def test_initialize_reports_agent_capabilities():
    result = HermesDriver().initialize(
        {
            "schema_version": "1.0",
            "core_version": "0.0.1-test",
            "workdir": "/tmp/agentenv",
            "log_level": "info",
        }
    )

    assert result["driver"]["name"] == "hermes"
    assert result["driver"]["kind"] == "agent"
    assert result["driver"]["protocol_version"] == "1.0"
    assert result["capabilities"] == {
        "supports_mcp": True,
        "supports_slash_commands": True,
        "supports_tui": True,
        "supports_headless": True,
    }


def test_initialize_schema_mismatch_uses_protocol_error():
    with pytest.raises(RpcError) as raised:
        HermesDriver().initialize(
            {
                "schema_version": "2.0",
                "core_version": "0.0.1-test",
                "workdir": "/tmp/agentenv",
                "log_level": "info",
            }
        )

    assert raised.value.code == ERROR_SCHEMA_VERSION_INCOMPATIBLE


def test_install_steps_use_pypi_package_with_mcp_extra():
    result = HermesDriver().install_steps({"version": None, "config": {}})

    assert result == {
        "steps": [
            {
                "name": "install-hermes",
                "content": 'RUN python3 -m pip install --no-cache-dir "hermes-agent[mcp]"',
            }
        ]
    }


def test_install_steps_pin_agent_spec_version():
    result = HermesDriver().install_steps({"version": "0.10.0", "config": {}})

    assert result["steps"][0]["content"] == (
        'RUN python3 -m pip install --no-cache-dir "hermes-agent[mcp]==0.10.0"'
    )


def test_mcp_config_path_is_hermes_config_yaml():
    assert HermesDriver().mcp_config_path({}) == {"path": "~/.hermes/config.yaml"}


def test_render_mcp_config_supports_http_sse_stdio_and_headers():
    content = HermesDriver().render_mcp_config(
        {
            "endpoints": [
                {
                    "url": "https://nexus.example.com/mcp",
                    "transport": "http",
                    "headers": {"X-Test": "value"},
                },
                {
                    "url": "https://stream.example.com/sse",
                    "transport": "http+sse",
                    "headers": {},
                },
                {
                    "url": "npx",
                    "transport": "stdio",
                    "headers": {},
                },
            ]
        }
    )["content"]

    parsed = yaml.safe_load(content)
    assert parsed == {
        "mcp_servers": {
            "endpoint_0": {
                "url": "https://nexus.example.com/mcp",
                "headers": {"X-Test": "value"},
            },
            "endpoint_1": {"url": "https://stream.example.com/sse"},
            "endpoint_2": {"command": "npx", "args": []},
        }
    }


def test_render_mcp_config_rejects_ssh_http():
    with pytest.raises(RpcError) as raised:
        HermesDriver().render_mcp_config(
            {
                "endpoints": [
                    {
                        "url": "ssh://host/mcp",
                        "transport": "ssh+http",
                        "headers": {},
                    }
                ]
            }
        )

    assert raised.value.code == ERROR_CAPABILITY_MISSING
    assert "ssh+http" in raised.value.message


def test_render_entrypoint_supports_tui_and_model_provider_flags():
    result = HermesDriver().render_entrypoint(
        {
            "version": None,
            "config": {
                "mode": "tui",
                "model": "openai/gpt-5.4",
                "provider": "openai",
            },
        }
    )

    assert result["content"] == (
        "#!/usr/bin/env sh\n"
        "set -eu\n"
        "exec hermes chat --model openai/gpt-5.4 --provider openai \"$@\"\n"
    )


def test_render_entrypoint_supports_headless_query_mode():
    result = HermesDriver().render_entrypoint(
        {
            "version": None,
            "config": {
                "mode": "headless",
                "provider": "anthropic",
            },
        }
    )

    assert result["content"] == (
        "#!/usr/bin/env sh\n"
        "set -eu\n"
        "exec hermes chat --provider anthropic --quiet --query \"$*\"\n"
    )


def test_credential_requirements_default_to_openai_key():
    result = HermesDriver().credential_requirements({"version": None, "config": {}})

    assert result["requirements"][0]["name"] == "OPENAI_API_KEY"
    assert result["requirements"][0]["kind"] == "api_key"
    assert result["requirements"][0]["required"] is True


def test_credential_requirements_follow_provider_mapping():
    result = HermesDriver().credential_requirements(
        {"version": None, "config": {"provider": "anthropic"}}
    )

    assert result["requirements"][0]["name"] == "ANTHROPIC_API_KEY"


def test_credential_requirements_for_local_provider_are_empty():
    result = HermesDriver().credential_requirements(
        {"version": None, "config": {"provider": "ollama"}}
    )

    assert result == {"requirements": []}


def test_health_check_probe_uses_hermes_version():
    result = HermesDriver().health_check_probe({"version": None, "config": {}})

    assert result == {
        "cmd": "hermes --version",
        "tty": False,
        "env": {},
        "success_exit_codes": [0],
    }
