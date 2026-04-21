# Agent Hermes Python Driver Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the standalone `agent-hermes-py` external Python driver package for issue #13.

**Architecture:** Add a self-contained Python subprocess driver under `external-drivers/agent-hermes-py/`. The package owns JSON-RPC framing, protocol validation, Hermes-specific rendering, installer/bundle scripts, and package-local tests. Keep core Rust lifecycle wiring out of scope; existing driver discovery can discover the installed manifest once the bundle is installed.

**Tech Stack:** Python 3.11, standard-library JSON-RPC server code, PyYAML for MCP config rendering, pytest for package tests, POSIX shell for install and bundle scripts, existing Rust `agentenv drivers list` for discovery verification.

---

## File Structure

- Create: `external-drivers/agent-hermes-py/pyproject.toml`
  - Defines the Python package, runtime dependency on `PyYAML`, test dependency on `pytest`, and `agentenv-driver-hermes` console script.
- Create: `external-drivers/agent-hermes-py/README.md`
  - Documents scope, install, tests, and host-integration limits.
- Create: `external-drivers/agent-hermes-py/manifest.json.in`
  - Template manifest installed into `~/.agentenv/drivers/agent-hermes/manifest.json`.
- Create: `external-drivers/agent-hermes-py/src/agentenv_agent_hermes/__init__.py`
  - Exposes package version.
- Create: `external-drivers/agent-hermes-py/src/agentenv_agent_hermes/protocol.py`
  - Owns protocol constants, schema-version compatibility, and JSON-RPC error helper types.
- Create: `external-drivers/agent-hermes-py/src/agentenv_agent_hermes/jsonrpc.py`
  - Reads and writes LSP-style JSON-RPC frames and runs the request loop.
- Create: `external-drivers/agent-hermes-py/src/agentenv_agent_hermes/hermes.py`
  - Implements Hermes-specific `AgentDriver` method behavior.
- Create: `external-drivers/agent-hermes-py/src/agentenv_agent_hermes/driver.py`
  - Maps JSON-RPC methods to `HermesDriver` methods.
- Create: `external-drivers/agent-hermes-py/src/agentenv_agent_hermes/__main__.py`
  - Runs the stdio JSON-RPC server.
- Create: `external-drivers/agent-hermes-py/scripts/install-driver.sh`
  - Installs the package and Hermes into an isolated venv under `~/.agentenv/drivers/agent-hermes/`.
- Create: `external-drivers/agent-hermes-py/scripts/build-bundle.sh`
  - Builds a bundle compatible with the top-level Python driver index installer.
- Create: `external-drivers/agent-hermes-py/scripts/run-tests.sh`
  - Runs package tests in a local venv.
- Modify: `install.sh`
  - Runs a generic extracted-bundle install hook so Python driver bundles can create isolated venvs before atomic replacement.
- Modify: `tests/install/test_install.sh`
  - Covers successful bundle hook execution and preservation of existing drivers when the hook fails.
- Create: `external-drivers/agent-hermes-py/tests/test_jsonrpc.py`
  - Covers framed JSON-RPC I/O and parse failures.
- Create: `external-drivers/agent-hermes-py/tests/test_driver_methods.py`
  - Covers Hermes driver method results and error behavior.
- Create: `external-drivers/agent-hermes-py/tests/test_subprocess_protocol.py`
  - Covers the driver as a real subprocess over stdin/stdout.

## Task 1: Package Skeleton and Protocol Constants

**Files:**
- Create: `external-drivers/agent-hermes-py/pyproject.toml`
- Create: `external-drivers/agent-hermes-py/src/agentenv_agent_hermes/__init__.py`
- Create: `external-drivers/agent-hermes-py/src/agentenv_agent_hermes/protocol.py`
- Create: `external-drivers/agent-hermes-py/tests/test_driver_methods.py`

- [ ] **Step 1: Write the failing package metadata and protocol test**

Create `external-drivers/agent-hermes-py/tests/test_driver_methods.py`:

```python
from agentenv_agent_hermes.protocol import (
    ERROR_SCHEMA_VERSION_INCOMPATIBLE,
    SCHEMA_VERSION,
    assert_schema_compatible,
)


def test_schema_version_accepts_matching_major_versions():
    assert_schema_compatible(SCHEMA_VERSION)
    assert_schema_compatible("1.9")


def test_schema_version_rejects_mismatched_major_versions():
    try:
        assert_schema_compatible("2.0")
    except ValueError as exc:
        assert "major schema versions match" in str(exc)
    else:
        raise AssertionError("schema mismatch should fail")


def test_protocol_error_codes_match_agentenv_proto():
    assert ERROR_SCHEMA_VERSION_INCOMPATIBLE == -32002
```

- [ ] **Step 2: Run the test to verify it fails**

Run:

```bash
cd external-drivers/agent-hermes-py
python3 -m pytest tests/test_driver_methods.py -q
```

Expected: FAIL with `ModuleNotFoundError: No module named 'agentenv_agent_hermes'`.

- [ ] **Step 3: Add package metadata and protocol constants**

Create `external-drivers/agent-hermes-py/pyproject.toml`:

```toml
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "agentenv-agent-hermes"
version = "0.1.0"
description = "agentenv AgentDriver adapter for Nous Research Hermes Agent"
requires-python = ">=3.11"
dependencies = [
  "PyYAML>=6.0.2,<7",
]

[project.optional-dependencies]
test = [
  "pytest>=8,<10",
]

[project.scripts]
agentenv-driver-hermes = "agentenv_agent_hermes.__main__:main"

[tool.setuptools.packages.find]
where = ["src"]

[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["src"]
```

Create `external-drivers/agent-hermes-py/src/agentenv_agent_hermes/__init__.py`:

```python
__version__ = "0.1.0"
```

Create `external-drivers/agent-hermes-py/src/agentenv_agent_hermes/protocol.py`:

```python
from dataclasses import dataclass
from typing import Any

SCHEMA_VERSION = "1.0"

JSON_RPC_PARSE_ERROR = -32700
JSON_RPC_INVALID_REQUEST = -32600
JSON_RPC_METHOD_NOT_FOUND = -32601
JSON_RPC_INVALID_PARAMS = -32602
JSON_RPC_INTERNAL_ERROR = -32603
ERROR_CAPABILITY_MISSING = -32000
ERROR_PREFLIGHT_FAILED = -32001
ERROR_SCHEMA_VERSION_INCOMPATIBLE = -32002


def _major(version: str) -> int:
    parts = version.split(".")
    if len(parts) != 2 or not parts[0].isdigit() or not parts[1].isdigit():
        raise ValueError(
            f"schema version `{version}` must use `<major>.<minor>` format"
        )
    return int(parts[0])


def assert_schema_compatible(version: str) -> None:
    expected = _major(SCHEMA_VERSION)
    actual = _major(version)
    if actual != expected:
        raise ValueError(
            "incompatible schema version: core and driver major schema versions "
            f"match only when both use major `{expected}`; got `{version}`"
        )


@dataclass
class RpcError(Exception):
    code: int
    message: str
    data: Any | None = None

    def to_response_error(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "code": self.code,
            "message": self.message,
        }
        if self.data is not None:
            payload["data"] = self.data
        return payload
```

- [ ] **Step 4: Run the test to verify it passes**

Run:

```bash
cd external-drivers/agent-hermes-py
python3 -m pytest tests/test_driver_methods.py -q
```

Expected: PASS with `3 passed`.

- [ ] **Step 5: Commit**

```bash
git add external-drivers/agent-hermes-py/pyproject.toml external-drivers/agent-hermes-py/src/agentenv_agent_hermes/__init__.py external-drivers/agent-hermes-py/src/agentenv_agent_hermes/protocol.py external-drivers/agent-hermes-py/tests/test_driver_methods.py
git commit -m "feat: scaffold hermes python driver package"
```

## Task 2: JSON-RPC Framing and Request Loop

**Files:**
- Create: `external-drivers/agent-hermes-py/src/agentenv_agent_hermes/jsonrpc.py`
- Modify: `external-drivers/agent-hermes-py/tests/test_jsonrpc.py`

- [ ] **Step 1: Write failing framing tests**

Create `external-drivers/agent-hermes-py/tests/test_jsonrpc.py`:

```python
import io

import pytest

from agentenv_agent_hermes.jsonrpc import (
    JsonRpcServer,
    read_framed_json,
    write_framed_json,
)
from agentenv_agent_hermes.protocol import JSON_RPC_METHOD_NOT_FOUND, JSON_RPC_PARSE_ERROR


def test_write_and_read_framed_json_round_trips_payload():
    stream = io.BytesIO()
    write_framed_json(stream, {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}})
    stream.seek(0)

    payload = read_framed_json(stream)

    assert payload == {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}


def test_read_framed_json_rejects_missing_content_length():
    stream = io.BytesIO(b"\r\n{}")

    with pytest.raises(ValueError, match="missing Content-Length"):
        read_framed_json(stream)


def test_server_returns_method_not_found_for_unknown_request():
    server = JsonRpcServer({})
    response = server.handle_request(
        {"jsonrpc": "2.0", "id": 7, "method": "missing", "params": {}}
    )

    assert response["jsonrpc"] == "2.0"
    assert response["id"] == 7
    assert response["error"]["code"] == JSON_RPC_METHOD_NOT_FOUND


def test_server_returns_parse_error_for_invalid_json_frame():
    stream = io.BytesIO(b"Content-Length: 1\r\n\r\n{")

    with pytest.raises(ValueError):
        read_framed_json(stream)

    assert JSON_RPC_PARSE_ERROR == -32700
```

- [ ] **Step 2: Run the tests to verify they fail**

Run:

```bash
cd external-drivers/agent-hermes-py
python3 -m pytest tests/test_jsonrpc.py -q
```

Expected: FAIL with `ModuleNotFoundError: No module named 'agentenv_agent_hermes.jsonrpc'`.

- [ ] **Step 3: Implement JSON-RPC framing and dispatch**

Create `external-drivers/agent-hermes-py/src/agentenv_agent_hermes/jsonrpc.py`:

```python
from __future__ import annotations

import json
import sys
from collections.abc import Callable
from typing import Any, BinaryIO

from .protocol import (
    JSON_RPC_INTERNAL_ERROR,
    JSON_RPC_INVALID_PARAMS,
    JSON_RPC_INVALID_REQUEST,
    JSON_RPC_METHOD_NOT_FOUND,
    JSON_RPC_PARSE_ERROR,
    RpcError,
)

Handler = Callable[[Any], Any]


def write_framed_json(stream: BinaryIO, payload: dict[str, Any]) -> None:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    stream.write(f"Content-Length: {len(body)}\r\n\r\n".encode("ascii"))
    stream.write(body)
    stream.flush()


def read_framed_json(stream: BinaryIO) -> dict[str, Any] | None:
    content_length: int | None = None

    while True:
        line = stream.readline()
        if line == b"":
            return None
        if line == b"\r\n":
            break
        if line.startswith(b"Content-Length: "):
            raw = line[len(b"Content-Length: ") :].strip()
            try:
                content_length = int(raw)
            except ValueError as exc:
                raise ValueError(f"invalid Content-Length `{raw.decode('ascii', 'replace')}`") from exc

    if content_length is None:
        raise ValueError("missing Content-Length header")

    body = stream.read(content_length)
    if len(body) != content_length:
        raise ValueError("unexpected EOF while reading JSON-RPC payload")

    try:
        value = json.loads(body.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON-RPC payload: {exc}") from exc

    if not isinstance(value, dict):
        raise ValueError("JSON-RPC payload must be an object")

    return value


class JsonRpcServer:
    def __init__(self, handlers: dict[str, Handler]):
        self._handlers = handlers

    def handle_request(self, request: dict[str, Any]) -> dict[str, Any] | None:
        request_id = request.get("id")
        is_notification = "id" not in request

        if request.get("jsonrpc") != "2.0" or not isinstance(request.get("method"), str):
            if is_notification:
                return None
            return self._error(request_id, JSON_RPC_INVALID_REQUEST, "invalid JSON-RPC request")

        method = request["method"]
        params = request.get("params", {})
        handler = self._handlers.get(method)
        if handler is None:
            if is_notification:
                return None
            return self._error(
                request_id,
                JSON_RPC_METHOD_NOT_FOUND,
                f"method `{method}` not found",
            )

        try:
            result = handler(params)
        except RpcError as exc:
            if is_notification:
                return None
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": exc.to_response_error(),
            }
        except (TypeError, ValueError) as exc:
            if is_notification:
                return None
            return self._error(
                request_id,
                JSON_RPC_INVALID_PARAMS,
                f"invalid params for `{method}`: {exc}",
            )
        except Exception as exc:
            if is_notification:
                return None
            return self._error(
                request_id,
                JSON_RPC_INTERNAL_ERROR,
                f"internal error in `{method}`: {exc}",
            )

        if is_notification:
            return None

        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    def serve(self, input_stream: BinaryIO | None = None, output_stream: BinaryIO | None = None) -> None:
        input_stream = input_stream or sys.stdin.buffer
        output_stream = output_stream or sys.stdout.buffer

        while True:
            try:
                request = read_framed_json(input_stream)
            except ValueError as exc:
                write_framed_json(
                    output_stream,
                    self._error(None, JSON_RPC_PARSE_ERROR, str(exc)),
                )
                continue

            if request is None:
                return

            response = self.handle_request(request)
            if response is None:
                continue

            write_framed_json(output_stream, response)
            if request.get("method") == "shutdown" and "error" not in response:
                return

    @staticmethod
    def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": code, "message": message},
        }
```

- [ ] **Step 4: Run the JSON-RPC tests to verify they pass**

Run:

```bash
cd external-drivers/agent-hermes-py
python3 -m pytest tests/test_jsonrpc.py -q
```

Expected: PASS with `4 passed`.

- [ ] **Step 5: Commit**

```bash
git add external-drivers/agent-hermes-py/src/agentenv_agent_hermes/jsonrpc.py external-drivers/agent-hermes-py/tests/test_jsonrpc.py
git commit -m "feat: add hermes driver jsonrpc framing"
```

## Task 3: Hermes Method Behavior

**Files:**
- Create: `external-drivers/agent-hermes-py/src/agentenv_agent_hermes/hermes.py`
- Modify: `external-drivers/agent-hermes-py/tests/test_driver_methods.py`

- [ ] **Step 1: Add failing method behavior tests**

Replace `external-drivers/agent-hermes-py/tests/test_driver_methods.py` with:

```python
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run:

```bash
cd external-drivers/agent-hermes-py
python3 -m pytest tests/test_driver_methods.py -q
```

Expected: FAIL with `ModuleNotFoundError: No module named 'agentenv_agent_hermes.hermes'`.

- [ ] **Step 3: Implement Hermes method behavior**

Create `external-drivers/agent-hermes-py/src/agentenv_agent_hermes/hermes.py`:

```python
from __future__ import annotations

import shutil
import subprocess
from typing import Any

import yaml

from . import __version__
from .protocol import (
    ERROR_CAPABILITY_MISSING,
    ERROR_SCHEMA_VERSION_INCOMPATIBLE,
    RpcError,
    SCHEMA_VERSION,
    assert_schema_compatible,
)

PROVIDER_CREDENTIALS: dict[str, str | None] = {
    "auto": "OPENAI_API_KEY",
    "openai": "OPENAI_API_KEY",
    "openai-codex": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
    "nous-api": "NOUS_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "zai": "GLM_API_KEY",
    "kimi-coding": "KIMI_API_KEY",
    "minimax": "MINIMAX_API_KEY",
    "minimax-cn": "MINIMAX_CN_API_KEY",
    "huggingface": "HF_TOKEN",
    "nvidia": "NVIDIA_API_KEY",
    "ollama-cloud": "OLLAMA_API_KEY",
    "kilocode": "KILOCODE_API_KEY",
    "ai-gateway": "AI_GATEWAY_API_KEY",
    "custom": None,
    "lmstudio": None,
    "ollama": None,
    "vllm": None,
    "llamacpp": None,
}


class HermesDriver:
    def initialize(self, params: dict[str, Any]) -> dict[str, Any]:
        try:
            assert_schema_compatible(str(params["schema_version"]))
        except (KeyError, ValueError) as exc:
            raise RpcError(ERROR_SCHEMA_VERSION_INCOMPATIBLE, str(exc)) from exc

        return {
            "driver": {
                "name": "hermes",
                "kind": "agent",
                "version": __version__,
                "protocol_version": SCHEMA_VERSION,
            },
            "capabilities": {
                "supports_mcp": True,
                "supports_slash_commands": True,
                "supports_tui": True,
                "supports_headless": True,
            },
        }

    def preflight(self, params: dict[str, Any]) -> dict[str, Any]:
        del params
        hermes = shutil.which("hermes")
        if hermes is None:
            return {
                "ok": False,
                "issues": [
                    {
                        "severity": "error",
                        "code": "hermes_missing",
                        "message": "Hermes executable was not found in PATH.",
                        "remediation": 'Install the driver venv or run `python3 -m pip install "hermes-agent[mcp]"` in it.',
                    }
                ],
            }

        completed = subprocess.run(
            [hermes, "--version"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if completed.returncode != 0:
            detail = completed.stderr.strip() or completed.stdout.strip()
            return {
                "ok": False,
                "issues": [
                    {
                        "severity": "error",
                        "code": "hermes_version_failed",
                        "message": f"`hermes --version` failed: {detail}",
                        "remediation": "Reinstall hermes-agent in the driver virtual environment.",
                    }
                ],
            }

        return {"ok": True, "issues": []}

    def install_steps(self, spec: dict[str, Any]) -> dict[str, Any]:
        version = spec.get("version")
        package = "hermes-agent[mcp]"
        if version:
            package = f"{package}=={version}"
        return {
            "steps": [
                {
                    "name": "install-hermes",
                    "content": f'RUN python3 -m pip install --no-cache-dir "{package}"',
                }
            ]
        }

    def mcp_config_path(self, params: dict[str, Any]) -> dict[str, str]:
        del params
        return {"path": "~/.hermes/config.yaml"}

    def render_mcp_config(self, params: dict[str, Any]) -> dict[str, str]:
        servers: dict[str, dict[str, Any]] = {}
        for index, endpoint in enumerate(params.get("endpoints", [])):
            transport = endpoint.get("transport")
            url = endpoint.get("url")
            headers = endpoint.get("headers") or {}
            name = f"endpoint_{index}"

            if transport == "stdio":
                server: dict[str, Any] = {"command": url, "args": []}
            elif transport in {"http", "http+sse"}:
                server = {"url": url}
                if headers:
                    server["headers"] = headers
            elif transport == "ssh+http":
                raise RpcError(
                    ERROR_CAPABILITY_MISSING,
                    "hermes mcp transport ssh+http is not supported",
                )
            else:
                raise ValueError(f"unsupported MCP transport `{transport}`")

            servers[name] = server

        return {
            "content": yaml.safe_dump(
                {"mcp_servers": servers},
                sort_keys=False,
                default_flow_style=False,
            )
        }

    def render_entrypoint(self, spec: dict[str, Any]) -> dict[str, str]:
        config = spec.get("config") or {}
        mode = config.get("mode", "tui")
        model = config.get("model")
        provider = config.get("provider")

        command = ["hermes", "chat"]
        if model:
            command.extend(["--model", str(model)])
        if provider:
            command.extend(["--provider", str(provider)])

        if mode == "tui":
            suffix = '"$@"'
        elif mode == "headless":
            command.extend(["--quiet", "--query"])
            suffix = '"$*"'
        else:
            raise ValueError(f"unsupported hermes mode `{mode}`")

        rendered = " ".join(_shell_word(part) for part in command)
        return {"content": f"#!/usr/bin/env sh\nset -eu\nexec {rendered} {suffix}\n"}

    def credential_requirements(self, spec: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
        config = spec.get("config") or {}
        provider = str(config.get("provider", "auto"))
        if provider not in PROVIDER_CREDENTIALS:
            raise ValueError(f"unsupported hermes provider `{provider}`")

        credential = PROVIDER_CREDENTIALS[provider]
        if credential is None:
            return {"requirements": []}

        return {
            "requirements": [
                {
                    "name": credential,
                    "description": f"{credential} used by Hermes provider `{provider}`.",
                    "kind": "api_key" if credential.endswith("API_KEY") else "token",
                    "required": True,
                }
            ]
        }

    def health_check_probe(self, spec: dict[str, Any]) -> dict[str, Any]:
        del spec
        return {
            "cmd": "hermes --version",
            "tty": False,
            "env": {},
            "success_exit_codes": [0],
        }

    def shutdown(self, params: dict[str, Any]) -> dict[str, Any]:
        del params
        return {}


def _shell_word(value: str) -> str:
    if value.replace("-", "").replace("_", "").replace("/", "").replace(".", "").isalnum():
        return value
    return "'" + value.replace("'", "'\"'\"'") + "'"
```

- [ ] **Step 4: Run method tests to verify they pass**

Run:

```bash
cd external-drivers/agent-hermes-py
python3 -m pytest tests/test_driver_methods.py -q
```

Expected: PASS with `15 passed`.

- [ ] **Step 5: Commit**

```bash
git add external-drivers/agent-hermes-py/src/agentenv_agent_hermes/hermes.py external-drivers/agent-hermes-py/tests/test_driver_methods.py
git commit -m "feat: implement hermes agent driver methods"
```

## Task 4: JSON-RPC Driver Entrypoint

**Files:**
- Create: `external-drivers/agent-hermes-py/src/agentenv_agent_hermes/driver.py`
- Create: `external-drivers/agent-hermes-py/src/agentenv_agent_hermes/__main__.py`
- Create: `external-drivers/agent-hermes-py/tests/test_subprocess_protocol.py`

- [ ] **Step 1: Write failing subprocess protocol tests**

Create `external-drivers/agent-hermes-py/tests/test_subprocess_protocol.py`:

```python
import json
import subprocess
import sys


def _write_frame(process: subprocess.Popen[bytes], request: dict[str, object]) -> None:
    payload = json.dumps(request, separators=(",", ":")).encode("utf-8")
    process.stdin.write(f"Content-Length: {len(payload)}\r\n\r\n".encode("ascii"))
    process.stdin.write(payload)
    process.stdin.flush()


def _read_frame(process: subprocess.Popen[bytes]) -> dict[str, object]:
    content_length = None
    while True:
        line = process.stdout.readline()
        if line == b"\r\n":
            break
        if line.startswith(b"Content-Length: "):
            content_length = int(line[len(b"Content-Length: ") :].strip())
    assert content_length is not None
    return json.loads(process.stdout.read(content_length).decode("utf-8"))


def test_driver_subprocess_handles_initialize_unknown_method_and_shutdown():
    process = subprocess.Popen(
        [sys.executable, "-m", "agentenv_agent_hermes"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdin is not None
    assert process.stdout is not None

    _write_frame(
        process,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "schema_version": "1.0",
                "core_version": "0.0.1-test",
                "workdir": "/tmp/agentenv",
                "log_level": "info",
            },
        },
    )
    init = _read_frame(process)
    assert init["result"]["driver"]["name"] == "hermes"

    _write_frame(
        process,
        {"jsonrpc": "2.0", "id": 2, "method": "driver/unknown", "params": {}},
    )
    unknown = _read_frame(process)
    assert unknown["error"]["code"] == -32601

    _write_frame(
        process,
        {"jsonrpc": "2.0", "id": 3, "method": "shutdown", "params": {}},
    )
    shutdown = _read_frame(process)
    assert shutdown["result"] == {}

    assert process.wait(timeout=5) == 0
```

- [ ] **Step 2: Run the subprocess test to verify it fails**

Run:

```bash
cd external-drivers/agent-hermes-py
python3 -m pytest tests/test_subprocess_protocol.py -q
```

Expected: FAIL because `agentenv_agent_hermes.__main__` does not exist.

- [ ] **Step 3: Add method dispatch and module entrypoint**

Create `external-drivers/agent-hermes-py/src/agentenv_agent_hermes/driver.py`:

```python
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .hermes import HermesDriver


def build_handlers(driver: HermesDriver | None = None) -> dict[str, Callable[[Any], Any]]:
    driver = driver or HermesDriver()
    return {
        "initialize": driver.initialize,
        "preflight": driver.preflight,
        "install_steps": driver.install_steps,
        "mcp_config_path": driver.mcp_config_path,
        "render_mcp_config": driver.render_mcp_config,
        "render_entrypoint": driver.render_entrypoint,
        "credential_requirements": driver.credential_requirements,
        "health_check_probe": driver.health_check_probe,
        "shutdown": driver.shutdown,
    }
```

Create `external-drivers/agent-hermes-py/src/agentenv_agent_hermes/__main__.py`:

```python
from .driver import build_handlers
from .jsonrpc import JsonRpcServer


def main() -> None:
    JsonRpcServer(build_handlers()).serve()


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run subprocess and package tests to verify they pass**

Run:

```bash
cd external-drivers/agent-hermes-py
python3 -m pytest tests/test_subprocess_protocol.py tests/test_jsonrpc.py tests/test_driver_methods.py -q
```

Expected: PASS with all tests passing.

- [ ] **Step 5: Commit**

```bash
git add external-drivers/agent-hermes-py/src/agentenv_agent_hermes/driver.py external-drivers/agent-hermes-py/src/agentenv_agent_hermes/__main__.py external-drivers/agent-hermes-py/tests/test_subprocess_protocol.py
git commit -m "feat: expose hermes driver jsonrpc entrypoint"
```

## Task 5: Manifest, Install Script, and Bundle Script

**Files:**
- Create: `external-drivers/agent-hermes-py/manifest.json.in`
- Create: `external-drivers/agent-hermes-py/scripts/install-driver.sh`
- Create: `external-drivers/agent-hermes-py/scripts/build-bundle.sh`
- Create: `external-drivers/agent-hermes-py/scripts/run-tests.sh`
- Create: `external-drivers/agent-hermes-py/tests/test_packaging_files.py`

- [ ] **Step 1: Write failing packaging file tests**

Create `external-drivers/agent-hermes-py/tests/test_packaging_files.py`:

```python
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_manifest_template_matches_agent_discovery_shape():
    manifest = json.loads((ROOT / "manifest.json.in").read_text())

    assert manifest["schema_version"] == "1.0"
    assert manifest["name"] == "hermes"
    assert manifest["kind"] == "agent"
    assert manifest["binary"] == "./bin/agentenv-driver-hermes"
    assert manifest["capabilities_preview"] == {
        "supports_mcp": True,
        "supports_slash_commands": True,
        "supports_tui": True,
        "supports_headless": True,
    }


def test_packaging_scripts_are_present():
    for path in [
        ROOT / "scripts" / "install-driver.sh",
        ROOT / "scripts" / "build-bundle.sh",
        ROOT / "scripts" / "run-tests.sh",
    ]:
        text = path.read_text()
        assert text.startswith("#!/bin/sh\n")
        assert "set -eu" in text
```

- [ ] **Step 2: Run packaging tests to verify they fail**

Run:

```bash
cd external-drivers/agent-hermes-py
python3 -m pytest tests/test_packaging_files.py -q
```

Expected: FAIL because `manifest.json.in` and scripts are missing.

- [ ] **Step 3: Add manifest template and scripts**

Create `external-drivers/agent-hermes-py/manifest.json.in`:

```json
{
  "schema_version": "1.0",
  "name": "hermes",
  "kind": "agent",
  "version": "0.1.0",
  "description": "Hermes Agent driver for agentenv",
  "binary": "./bin/agentenv-driver-hermes",
  "args": [],
  "env": {},
  "capabilities_preview": {
    "supports_mcp": true,
    "supports_slash_commands": true,
    "supports_tui": true,
    "supports_headless": true
  }
}
```

Create `external-drivers/agent-hermes-py/scripts/install-driver.sh`:

```sh
#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
if [ -f "${SCRIPT_DIR}/manifest.json" ] || [ -f "${SCRIPT_DIR}/pyproject.toml" ]; then
    DRIVER_ROOT=${SCRIPT_DIR}
else
    DRIVER_ROOT=$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)
fi
AGENTENV_HOME=${AGENTENV_HOME:-"$HOME/.agentenv"}
INSTALL_ROOT=${AGENTENV_DRIVER_INSTALL_ROOT:-"${AGENTENV_HOME}/drivers/agent-hermes"}
STAGED=${AGENTENV_DRIVER_STAGED_DIR:-}
PYTHON=${PYTHON:-python3}
TMP_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/agentenv-hermes-driver.XXXXXX")
EXTERNAL_STAGED=0

cleanup() {
    rm -rf "${TMP_ROOT}"
}

trap cleanup EXIT INT TERM

if [ -z "${STAGED}" ]; then
    STAGED="${TMP_ROOT}/agent-hermes"
    mkdir -p "${STAGED}/bin" "${STAGED}/wheels"
    "${PYTHON}" -m pip wheel --wheel-dir "${STAGED}/wheels" "${DRIVER_ROOT}"
    cp "${DRIVER_ROOT}/manifest.json.in" "${STAGED}/manifest.json"
else
    EXTERNAL_STAGED=1
fi

"${PYTHON}" -m venv "${STAGED}/venv"
"${STAGED}/venv/bin/python" -m pip install --upgrade pip
"${STAGED}/venv/bin/python" -m pip install "${STAGED}"/wheels/agentenv_agent_hermes-*.whl
"${STAGED}/venv/bin/python" -m pip install "hermes-agent[mcp]"

cat > "${STAGED}/bin/agentenv-driver-hermes" <<'LAUNCHER'
#!/bin/sh
set -eu
DIR=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
exec "$DIR/venv/bin/python" -m agentenv_agent_hermes "$@"
LAUNCHER
chmod 0755 "${STAGED}/bin/agentenv-driver-hermes"

if [ "${EXTERNAL_STAGED}" -eq 1 ]; then
    printf '%s\n' "${STAGED}"
    exit 0
fi

mkdir -p "$(dirname "${INSTALL_ROOT}")"
BACKUP="${INSTALL_ROOT}.backup.$$"
rm -rf "${BACKUP}"
if [ -e "${INSTALL_ROOT}" ]; then
    mv "${INSTALL_ROOT}" "${BACKUP}"
fi
if mv "${STAGED}" "${INSTALL_ROOT}"; then
    rm -rf "${BACKUP}"
else
    rm -rf "${INSTALL_ROOT}"
    if [ -e "${BACKUP}" ]; then
        mv "${BACKUP}" "${INSTALL_ROOT}"
    fi
    exit 1
fi

printf '%s\n' "${INSTALL_ROOT}"
```

Create `external-drivers/agent-hermes-py/scripts/build-bundle.sh`:

```sh
#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
DRIVER_ROOT=$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)
PYTHON=${PYTHON:-python3}
DIST_DIR=${DIST_DIR:-"${DRIVER_ROOT}/dist"}
TMP_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/agentenv-hermes-bundle.XXXXXX")

cleanup() {
    rm -rf "${TMP_ROOT}"
}

trap cleanup EXIT INT TERM

mkdir -p "${DIST_DIR}" "${TMP_ROOT}/agent-hermes/bin" "${TMP_ROOT}/agent-hermes/wheels"
"${PYTHON}" -m pip wheel --wheel-dir "${TMP_ROOT}/agent-hermes/wheels" "${DRIVER_ROOT}"
cp "${DRIVER_ROOT}/manifest.json.in" "${TMP_ROOT}/agent-hermes/manifest.json"
cp "${DRIVER_ROOT}/scripts/install-driver.sh" "${TMP_ROOT}/agent-hermes/install-driver.sh"
chmod 0755 "${TMP_ROOT}/agent-hermes/install-driver.sh"
cat > "${TMP_ROOT}/agent-hermes/bin/agentenv-driver-hermes" <<'LAUNCHER'
#!/bin/sh
set -eu
DIR=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
exec "$DIR/venv/bin/python" -m agentenv_agent_hermes "$@"
LAUNCHER
chmod 0755 "${TMP_ROOT}/agent-hermes/bin/agentenv-driver-hermes"

tar -C "${TMP_ROOT}/agent-hermes" -czf "${DIST_DIR}/agent-hermes-py.tar.gz" .
printf '%s\n' "${DIST_DIR}/agent-hermes-py.tar.gz"
```

Create `external-drivers/agent-hermes-py/scripts/run-tests.sh`:

```sh
#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
DRIVER_ROOT=$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)
PYTHON=${PYTHON:-python3}
VENV=${VENV:-"${DRIVER_ROOT}/.venv"}

if [ ! -x "${VENV}/bin/python" ]; then
    "${PYTHON}" -m venv "${VENV}"
fi

"${VENV}/bin/python" -m pip install -e "${DRIVER_ROOT}[test]"
"${VENV}/bin/python" -m pytest "${DRIVER_ROOT}/tests" "$@"
```

Run:

```bash
chmod 0755 external-drivers/agent-hermes-py/scripts/install-driver.sh external-drivers/agent-hermes-py/scripts/build-bundle.sh external-drivers/agent-hermes-py/scripts/run-tests.sh
```

- [ ] **Step 4: Run packaging tests to verify they pass**

Run:

```bash
cd external-drivers/agent-hermes-py
python3 -m pytest tests/test_packaging_files.py -q
```

Expected: PASS with `2 passed`.

- [ ] **Step 5: Commit**

```bash
git add external-drivers/agent-hermes-py/manifest.json.in external-drivers/agent-hermes-py/scripts/install-driver.sh external-drivers/agent-hermes-py/scripts/build-bundle.sh external-drivers/agent-hermes-py/scripts/run-tests.sh external-drivers/agent-hermes-py/tests/test_packaging_files.py
git commit -m "feat: add hermes driver packaging scripts"
```

## Task 6: Top-Level Installer Bundle Hook

**Files:**
- Modify: `install.sh`
- Modify: `tests/install/test_install.sh`

- [ ] **Step 1: Write failing installer hook tests**

Add this function above `test_choose_rc_targets_creates_profile_when_missing` in `tests/install/test_install.sh`:

```sh
test_install_python_drivers_runs_bundle_install_hook() {
    tmp_root=$(mktemp -d)

    mkdir -p "${tmp_root}/bundle/bin" "${tmp_root}/bundle/wheels" "${tmp_root}/index" "${tmp_root}/releases"
    printf '{"schema_version":"1.0","name":"hermes","kind":"agent","version":"0.1.0","binary":"./bin/agentenv-driver-hermes"}\n' > "${tmp_root}/bundle/manifest.json"
    printf '#!/bin/sh\nset -eu\nprintf hook-ran > "$AGENTENV_DRIVER_STAGED_DIR/hook.txt"\n' > "${tmp_root}/bundle/install-driver.sh"
    chmod +x "${tmp_root}/bundle/install-driver.sh"
    tar -C "${tmp_root}/bundle" -czf "${tmp_root}/releases/agent-hermes.tar.gz" .

    expected_hash=$(sha256_file "${tmp_root}/releases/agent-hermes.tar.gz")
    printf 'agent-hermes|file://%s/releases/agent-hermes.tar.gz|%s\n' "${tmp_root}" "${expected_hash}" > "${tmp_root}/index/drivers.index"

    sh -c '
        tmp_root=$1
        repo_root=$2
        AGENTENV_INSTALLER_SOURCE_ONLY=1 . "$repo_root/install.sh"
        TMP_ROOT="$tmp_root/tmp"
        mkdir -p "$TMP_ROOT"
        AGENTENV_HOME="$tmp_root/home/.agentenv"
        WITH_PYTHON_DRIVERS=1
        PYTHON_DRIVERS_INDEX_URL="file://$tmp_root/index/drivers.index"
        install_python_drivers
    ' sh "${tmp_root}" "${REPO_ROOT}"

    assert_contains "hook-ran" "${tmp_root}/home/.agentenv/drivers/agent-hermes/hook.txt" "bundle install hook should run before replacement"

    rm -rf "${tmp_root}"
    pass
}

test_install_python_drivers_preserves_existing_driver_on_hook_failure() {
    tmp_root=$(mktemp -d)

    mkdir -p "${tmp_root}/home/.agentenv/drivers/agent-hermes"
    printf '{"old":true}\n' > "${tmp_root}/home/.agentenv/drivers/agent-hermes/manifest.json"
    mkdir -p "${tmp_root}/bundle/bin" "${tmp_root}/index" "${tmp_root}/releases"
    printf '{"schema_version":"1.0","name":"hermes","kind":"agent","version":"0.1.0","binary":"./bin/agentenv-driver-hermes"}\n' > "${tmp_root}/bundle/manifest.json"
    printf '#!/bin/sh\nset -eu\nexit 7\n' > "${tmp_root}/bundle/install-driver.sh"
    chmod +x "${tmp_root}/bundle/install-driver.sh"
    tar -C "${tmp_root}/bundle" -czf "${tmp_root}/releases/agent-hermes.tar.gz" .

    expected_hash=$(sha256_file "${tmp_root}/releases/agent-hermes.tar.gz")
    printf 'agent-hermes|file://%s/releases/agent-hermes.tar.gz|%s\n' "${tmp_root}" "${expected_hash}" > "${tmp_root}/index/drivers.index"

    set +e
    sh -c '
        tmp_root=$1
        repo_root=$2
        AGENTENV_INSTALLER_SOURCE_ONLY=1 . "$repo_root/install.sh"
        TMP_ROOT="$tmp_root/tmp"
        mkdir -p "$TMP_ROOT"
        AGENTENV_HOME="$tmp_root/home/.agentenv"
        WITH_PYTHON_DRIVERS=1
        PYTHON_DRIVERS_INDEX_URL="file://$tmp_root/index/drivers.index"
        install_python_drivers
    ' sh "${tmp_root}" "${REPO_ROOT}" > "${tmp_root}/hook-failure.log" 2>&1
    rc=$?
    set -e

    assert_eq "1" "${rc}" "install_python_drivers should fail when bundle hook fails"
    assert_contains '{"old":true}' "${tmp_root}/home/.agentenv/drivers/agent-hermes/manifest.json" "existing driver manifest should survive a failed hook"

    rm -rf "${tmp_root}"
    pass
}
```

Add these calls in `main()` before `test_choose_rc_targets_creates_profile_when_missing`:

```sh
    test_install_python_drivers_runs_bundle_install_hook
    test_install_python_drivers_preserves_existing_driver_on_hook_failure
```

- [ ] **Step 2: Run installer tests to verify they fail**

Run:

```bash
sh tests/install/test_install.sh
```

Expected: FAIL because `install_python_drivers` extracts the bundle but does not run `install-driver.sh`.

- [ ] **Step 3: Add generic bundle install hook support**

Add this function above `install_python_drivers` in `install.sh`:

```sh
run_python_driver_bundle_hook() {
    staged_driver_dir=$1
    driver_dir=$2

    hook="${staged_driver_dir}/install-driver.sh"
    if [ ! -f "${hook}" ]; then
        return 0
    fi

    chmod +x "${hook}"
    AGENTENV_DRIVER_STAGED_DIR="${staged_driver_dir}" \
    AGENTENV_DRIVER_INSTALL_ROOT="${driver_dir}" \
    AGENTENV_HOME="${AGENTENV_HOME}" \
    "${hook}" || die "Python driver bundle hook failed for $(basename "${driver_dir}")"
}
```

Modify the body of `install_python_drivers` so the extraction section reads:

```sh
        tar -xzf "${archive_path}" -C "${staged_driver_dir}" || die "Could not extract Python driver bundle for ${driver_name}"
        [ -f "${staged_driver_dir}/manifest.json" ] || die "Python driver ${driver_name} did not contain manifest.json"
        run_python_driver_bundle_hook "${staged_driver_dir}" "${driver_dir}"
        [ -f "${staged_driver_dir}/manifest.json" ] || die "Python driver ${driver_name} hook removed manifest.json"
        replace_driver_dir "${staged_driver_dir}" "${driver_dir}"
```

The hook runs inside the staged directory before `replace_driver_dir`, so a hook failure leaves the existing installed driver untouched.

- [ ] **Step 4: Run installer tests to verify they pass**

Run:

```bash
sh tests/install/test_install.sh
```

Expected: PASS with all installer tests passing.

- [ ] **Step 5: Commit**

```bash
git add install.sh tests/install/test_install.sh
git commit -m "feat: run python driver bundle install hooks"
```

## Task 7: README and Reference Blueprint Notes

**Files:**
- Create: `external-drivers/agent-hermes-py/README.md`
- Modify: `blueprints/hermes+nexus+openshell.yaml`

- [ ] **Step 1: Write failing documentation checks**

Create `external-drivers/agent-hermes-py/tests/test_docs.py`:

```python
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parents[1]


def test_readme_documents_install_tests_and_host_limit():
    text = (ROOT / "README.md").read_text()

    assert "scripts/install-driver.sh" in text
    assert "scripts/run-tests.sh" in text
    assert "agentenv create" in text
    assert "subprocess AgentDriver host integration" in text


def test_reference_blueprint_names_external_driver_directory():
    text = (WORKSPACE / "blueprints" / "hermes+nexus+openshell.yaml").read_text()

    assert "agent-hermes" in text
```

- [ ] **Step 2: Run docs tests to verify they fail**

Run:

```bash
cd external-drivers/agent-hermes-py
python3 -m pytest tests/test_docs.py -q
```

Expected: FAIL because `README.md` is missing and the blueprint comment does not name `agent-hermes`.

- [ ] **Step 3: Add README and tighten blueprint comments**

Create `external-drivers/agent-hermes-py/README.md`:

````markdown
# agent-hermes-py

`agent-hermes-py` is the external Python `AgentDriver` adapter for Nous Research Hermes Agent.

It implements agentenv's JSON-RPC driver protocol over stdio and installs as the `hermes` agent driver under:

```text
~/.agentenv/drivers/agent-hermes/
```

## Install

```bash
external-drivers/agent-hermes-py/scripts/install-driver.sh
```

The installer creates an isolated virtual environment, installs this driver package, installs `hermes-agent[mcp]`, writes `manifest.json`, and atomically replaces the installed driver directory.

## Test

```bash
external-drivers/agent-hermes-py/scripts/run-tests.sh
```

The tests exercise protocol framing, driver methods, packaging files, and the real subprocess entrypoint. They do not require model API credentials.

## Current Host Limit

This package is standalone. The current agentenv core can discover the installed manifest with `agentenv drivers list`, but full `agentenv create` execution still needs subprocess AgentDriver host integration in `agentenv-core`.
````

Modify the opening comments in `blueprints/hermes+nexus+openshell.yaml`:

```yaml
# Reference blueprint — Nous Research Hermes agent in OpenShell with a shared Nexus hub.
# Uses two subprocess (Python) drivers: agent-hermes and context-nexus.
# Installed driver directories are expected at ~/.agentenv/drivers/agent-hermes/
# and ~/.agentenv/drivers/context-nexus/.
```

- [ ] **Step 4: Run docs tests to verify they pass**

Run:

```bash
cd external-drivers/agent-hermes-py
python3 -m pytest tests/test_docs.py -q
```

Expected: PASS with `2 passed`.

- [ ] **Step 5: Commit**

```bash
git add external-drivers/agent-hermes-py/README.md external-drivers/agent-hermes-py/tests/test_docs.py blueprints/hermes+nexus+openshell.yaml
git commit -m "docs: document hermes external driver"
```

## Task 8: Install Smoke Test With Existing Driver Discovery

**Files:**
- Create: `external-drivers/agent-hermes-py/tests/test_install_smoke.py`

- [ ] **Step 1: Write manifest discovery smoke test**

Create `external-drivers/agent-hermes-py/tests/test_install_smoke.py`:

```python
import json
import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parents[1]


def test_manifest_template_is_discoverable_after_minimal_staged_install(tmp_path):
    install_root = tmp_path / "home" / ".agentenv" / "drivers" / "agent-hermes"
    (install_root / "bin").mkdir(parents=True)
    launcher = install_root / "bin" / "agentenv-driver-hermes"
    launcher.write_text("#!/bin/sh\nexit 0\n")
    launcher.chmod(0o755)
    (install_root / "manifest.json").write_text((ROOT / "manifest.json.in").read_text())

    env = os.environ.copy()
    env["HOME"] = str(tmp_path / "home")

    completed = subprocess.run(
        ["cargo", "run", "-p", "agentenv", "--", "drivers", "list"],
        cwd=WORKSPACE,
        env=env,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    assert "agent" in completed.stdout
    assert "hermes" in completed.stdout
    assert "installed" in completed.stdout
    manifest = json.loads((install_root / "manifest.json").read_text())
    assert manifest["name"] == "hermes"
```

- [ ] **Step 2: Run the smoke test to verify it passes against existing discovery**

Run:

```bash
cd external-drivers/agent-hermes-py
python3 -m pytest tests/test_install_smoke.py -q
```

Expected: PASS because this test stages a manifest in the exact directory shape already supported by `agentenv drivers list`.

- [ ] **Step 3: Run the full driver package tests**

Run:

```bash
cd external-drivers/agent-hermes-py
python3 -m pytest tests -q
```

Expected: PASS with all package tests passing.

- [ ] **Step 4: Commit**

```bash
git add external-drivers/agent-hermes-py/tests/test_install_smoke.py
git commit -m "test: verify hermes manifest discovery shape"
```

## Task 9: Final Verification

**Files:**
- No new files.

- [ ] **Step 1: Run Python package verification**

Run:

```bash
external-drivers/agent-hermes-py/scripts/run-tests.sh
```

Expected: PASS with all `external-drivers/agent-hermes-py/tests` tests passing.

- [ ] **Step 2: Run Rust formatting and checks**

Run:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Expected: PASS. This work should not require Rust source changes beyond the blueprint comment, but the workspace checks protect against accidental regressions.

- [ ] **Step 3: Verify no whitespace or untracked generated files**

Run:

```bash
git diff --check
git status --short
```

Expected: `git diff --check` exits 0, and `git status --short` shows only intended source files before the final commit.

- [ ] **Step 4: Commit final verification adjustments if needed**

If verification required any small source changes, commit them:

```bash
git add external-drivers/agent-hermes-py blueprints/hermes+nexus+openshell.yaml
git commit -m "fix: finalize hermes python driver"
```

If no changes were needed after Task 8, do not create an empty commit.

- [ ] **Step 5: Summarize issue coverage**

Prepare a concise final summary with:

```text
Implemented standalone agent-hermes-py external driver package for #13.
Tests: external-drivers/agent-hermes-py/scripts/run-tests.sh; cargo fmt --check; cargo clippy --workspace --all-targets -- -D warnings; cargo test --workspace.
Known follow-up: production subprocess AgentDriver host integration is still required before agentenv create can launch Hermes end-to-end.
```
