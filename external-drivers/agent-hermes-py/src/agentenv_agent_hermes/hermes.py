from __future__ import annotations

import shutil
import subprocess
import re
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

SAFE_HERMES_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+!*-]*$")


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
                        "remediation": (
                            "Install the driver venv or run `python3 -m pip install "
                            '"hermes-agent[mcp]"` in it.'
                        ),
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
            version = str(version)
            if not SAFE_HERMES_VERSION.fullmatch(version):
                raise ValueError(f"unsafe hermes version `{version}`")
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
