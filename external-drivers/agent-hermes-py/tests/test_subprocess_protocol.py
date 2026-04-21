import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, BinaryIO


def _write_framed_json(stream: BinaryIO, payload: dict[str, Any]) -> None:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    stream.write(f"Content-Length: {len(body)}\r\n\r\n".encode("ascii"))
    stream.write(body)
    stream.flush()


def _read_framed_json(stream: BinaryIO) -> dict[str, Any]:
    content_length: int | None = None

    while True:
        line = stream.readline()
        if line == b"":
            raise EOFError("subprocess closed stdout before sending a response")
        if line == b"\r\n":
            break
        if line.startswith(b"Content-Length: "):
            content_length = int(line[len(b"Content-Length: ") :].strip())

    if content_length is None:
        raise ValueError("missing Content-Length header")

    body = stream.read(content_length)
    if len(body) != content_length:
        raise EOFError("subprocess closed stdout during response body")

    payload = json.loads(body.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("JSON-RPC response must be an object")
    return payload


def test_module_entrypoint_serves_jsonrpc_over_stdio():
    src_path = str(Path(__file__).resolve().parents[1] / "src")
    env = os.environ.copy()
    existing_pythonpath = env.get("PYTHONPATH")
    env["PYTHONPATH"] = (
        src_path
        if not existing_pythonpath
        else f"{src_path}{os.pathsep}{existing_pythonpath}"
    )

    process = subprocess.Popen(
        [sys.executable, "-m", "agentenv_agent_hermes"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    assert process.stdin is not None
    assert process.stdout is not None

    try:
        _write_framed_json(
            process.stdin,
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
        initialize_response = _read_framed_json(process.stdout)

        _write_framed_json(
            process.stdin,
            {"jsonrpc": "2.0", "id": 2, "method": "missing", "params": {}},
        )
        unknown_response = _read_framed_json(process.stdout)

        _write_framed_json(
            process.stdin,
            {"jsonrpc": "2.0", "id": 3, "method": "shutdown", "params": {}},
        )
        shutdown_response = _read_framed_json(process.stdout)

        assert initialize_response["result"]["driver"]["name"] == "hermes"
        assert unknown_response["error"]["code"] == -32601
        assert shutdown_response["result"] == {}
        assert process.wait(timeout=5) == 0
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
