import os
import tempfile
import uuid
from dataclasses import dataclass

from agentenv_context_nexus import __version__
from agentenv_context_nexus.nexus import find_free_port, nexus_cli_available, parse_http_url, stable_hub_handle, start_lite_process
from agentenv_context_nexus.protocol import (
    ERROR_RESOURCE_NOT_FOUND,
    ERROR_SCHEMA_VERSION_INCOMPATIBLE,
    JSON_RPC_INTERNAL_ERROR,
    JSON_RPC_INVALID_PARAMS,
    JSON_RPC_METHOD_NOT_FOUND,
    SCHEMA_VERSION,
    error,
    success,
)


@dataclass
class HandleState:
    mode: str
    endpoint_url: str
    zones: list[str]
    parsed_url: object | None = None
    process: object | None = None
    data_dir: str | None = None


class NexusContextDriver:
    def __init__(self):
        self._handles = {}
        self._workdir = tempfile.gettempdir()

    def handle(self, request):
        request_id = request.get("id")
        method = request.get("method")
        params = request.get("params") or {}
        try:
            if method == "initialize":
                return self._initialize(request_id, params)
            if method == "preflight":
                return self._preflight(request_id)
            if method == "provision":
                return self._provision(request_id, params)
            if method == "mcp_endpoint":
                return self._mcp_endpoint(request_id, params)
            if method == "required_network_rules":
                return self._required_network_rules(request_id, params)
            if method == "credential_requirements":
                return self._credential_requirements(request_id)
            if method == "status":
                return self._status(request_id, params)
            if method == "teardown":
                return self._teardown(request_id, params)
            if method == "shutdown":
                return self._shutdown(request_id)
            return error(request_id, JSON_RPC_METHOD_NOT_FOUND, f"method `{method}` not found")
        except ValueError as exc:
            return error(request_id, JSON_RPC_INVALID_PARAMS, str(exc))
        except Exception as exc:
            return error(request_id, JSON_RPC_INTERNAL_ERROR, str(exc))

    def _initialize(self, request_id, params):
        schema_version = str(params.get("schema_version", ""))
        if schema_version.split(".", 1)[0] != SCHEMA_VERSION.split(".", 1)[0]:
            return error(
                request_id,
                ERROR_SCHEMA_VERSION_INCOMPATIBLE,
                "driver and core major schema versions match is required",
            )
        self._workdir = params.get("workdir") or self._workdir
        return success(
            request_id,
            {
                "driver": {
                    "name": "nexus",
                    "kind": "context",
                    "version": __version__,
                    "protocol_version": SCHEMA_VERSION,
                },
                "capabilities": {
                    "is_remote": True,
                    "is_shared": True,
                    "supports_zones": True,
                    "supports_snapshots": True,
                },
            },
        )

    def _preflight(self, request_id):
        if nexus_cli_available():
            return success(request_id, {"ok": True, "issues": []})
        return success(
            request_id,
            {
                "ok": False,
                "issues": [
                    {
                        "severity": "error",
                        "code": "nexus_cli_missing",
                        "message": "Nexus CLI was not found in the driver environment",
                        "remediation": "Install the Nexus package into the context-nexus driver venv.",
                    }
                ],
            },
        )

    def _provision(self, request_id, params):
        config = params.get("config") or {}
        mode = config.get("mode", "lite")
        zones = config.get("zones") or []
        if not isinstance(zones, list) or not all(isinstance(zone, str) for zone in zones):
            raise ValueError("zones must be a list of strings")
        if mode == "hub":
            hub_url = config.get("hub_url")
            if not isinstance(hub_url, str) or not hub_url.strip():
                raise ValueError("hub_url is required in hub mode")
            parsed = parse_http_url(hub_url)
            handle = stable_hub_handle(parsed.url, zones)
            self._handles[handle] = HandleState("hub", parsed.url, zones, parsed_url=parsed)
            return success(request_id, {"handle": handle})
        if mode == "lite":
            data_dir = config.get("data_dir") or os.path.join(self._workdir, "nexus-data")
            port = int(config.get("mcp_port") or find_free_port())
            os.makedirs(data_dir, exist_ok=True)
            process = start_lite_process(data_dir, port)
            handle = f"nexus-lite-{uuid.uuid4().hex[:16]}"
            self._handles[handle] = HandleState(
                "lite",
                f"http://127.0.0.1:{port}",
                zones,
                process=process,
                data_dir=data_dir,
            )
            return success(request_id, {"handle": handle})
        raise ValueError("mode must be hub or lite")

    def _lookup(self, params):
        handle = params.get("handle")
        if handle not in self._handles:
            raise KeyError(handle)
        return handle, self._handles[handle]

    def _mcp_endpoint(self, request_id, params):
        try:
            _handle, state = self._lookup(params)
        except KeyError as exc:
            return error(request_id, ERROR_RESOURCE_NOT_FOUND, f"unknown context handle `{exc.args[0]}`")
        return success(request_id, {"url": state.endpoint_url, "transport": "http", "headers": {}})

    def _required_network_rules(self, request_id, params):
        try:
            _handle, state = self._lookup(params)
        except KeyError as exc:
            return error(request_id, ERROR_RESOURCE_NOT_FOUND, f"unknown context handle `{exc.args[0]}`")
        if state.mode == "lite":
            return success(request_id, {"rules": []})
        parsed = state.parsed_url
        return success(
            request_id,
            {
                "rules": [
                    {
                        "target": {
                            "kind": "host",
                            "host": parsed.host,
                            "port": parsed.port,
                            "scheme": parsed.scheme,
                        }
                    }
                ]
            },
        )

    def _credential_requirements(self, request_id):
        return success(
            request_id,
            {
                "requirements": [
                    {
                        "name": "NEXUS_TOKEN",
                        "description": "Nexus hub API token",
                        "kind": "token",
                        "required": False,
                    }
                ]
            },
        )

    def _status(self, request_id, params):
        try:
            _handle, state = self._lookup(params)
        except KeyError as exc:
            return error(request_id, ERROR_RESOURCE_NOT_FOUND, f"unknown context handle `{exc.args[0]}`")
        if state.process is None:
            return success(request_id, {"healthy": True, "detail": "hub mode"})
        code = state.process.poll()
        if code is None:
            return success(request_id, {"healthy": True, "detail": "lite MCP process running"})
        return success(request_id, {"healthy": False, "detail": f"lite MCP process exited with {code}"})

    def _teardown(self, request_id, params):
        try:
            handle, state = self._lookup(params)
        except KeyError as exc:
            return error(request_id, ERROR_RESOURCE_NOT_FOUND, f"unknown context handle `{exc.args[0]}`")
        if state.process is not None and state.process.poll() is None:
            state.process.terminate()
            state.process.wait(timeout=5)
        self._handles.pop(handle, None)
        return success(request_id, {})

    def _shutdown(self, request_id):
        for handle in list(self._handles):
            self._teardown(request_id, {"handle": handle})
        return success(request_id, {})
