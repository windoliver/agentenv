import json
import os
import selectors
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, BinaryIO

RESPONSE_TIMEOUT_SECONDS = 5.0


def _write_framed_json(stream: BinaryIO, payload: dict[str, Any]) -> None:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    stream.write(f"Content-Length: {len(body)}\r\n\r\n".encode("ascii"))
    stream.write(body)
    stream.flush()


def _read_framed_json_with_timeout(
    stream: BinaryIO,
    *,
    timeout: float = RESPONSE_TIMEOUT_SECONDS,
    stderr: BinaryIO | None = None,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    buffered = bytearray()

    while b"\r\n\r\n" not in buffered:
        buffered.extend(_read_available_or_timeout(stream, deadline, stderr))

    header, body = bytes(buffered).split(b"\r\n\r\n", 1)
    content_length: int | None = None

    for line in header.splitlines():
        if line.startswith(b"Content-Length: "):
            content_length = int(line[len(b"Content-Length: ") :].strip())

    if content_length is None:
        raise ValueError("missing Content-Length header")

    while len(body) < content_length:
        body += _read_available_or_timeout(stream, deadline, stderr)

    payload = json.loads(body[:content_length].decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("JSON-RPC response must be an object")
    return payload


def _read_available_or_timeout(
    stream: BinaryIO,
    deadline: float,
    stderr: BinaryIO | None,
) -> bytes:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError(_diagnostic("timed out waiting for JSON-RPC response", stderr))

    selector = selectors.DefaultSelector()
    try:
        selector.register(stream, selectors.EVENT_READ)
        if not selector.select(remaining):
            raise TimeoutError(
                _diagnostic("timed out waiting for JSON-RPC response", stderr)
            )
    finally:
        selector.close()

    chunk = os.read(stream.fileno(), 4096)
    if chunk == b"":
        raise EOFError(
            _diagnostic(
                "subprocess closed stdout before sending a complete JSON-RPC response",
                stderr,
            )
        )
    return chunk


def _diagnostic(message: str, stderr: BinaryIO | None) -> str:
    stderr_output = _read_available_text(stderr)
    if stderr_output:
        return f"{message}; stderr: {stderr_output}"
    return message


def _read_available_text(stream: BinaryIO | None) -> str:
    if stream is None:
        return ""

    chunks: list[bytes] = []
    selector = selectors.DefaultSelector()
    try:
        selector.register(stream, selectors.EVENT_READ)
        while selector.select(0):
            chunk = os.read(stream.fileno(), 4096)
            if chunk == b"":
                break
            chunks.append(chunk)
    finally:
        selector.close()

    return b"".join(chunks).decode("utf-8", "replace").strip()


def test_timeout_read_fails_for_silent_stream():
    read_fd, write_fd = os.pipe()
    try:
        with os.fdopen(read_fd, "rb", buffering=0) as reader:
            try:
                _read_framed_json_with_timeout(reader, timeout=0.01)
                raise AssertionError("read should have timed out")
            except TimeoutError as exc:
                assert "timed out waiting for JSON-RPC response" in str(exc)
    finally:
        os.close(write_fd)


def test_timeout_read_fails_for_partial_frame():
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, b"Content-Length: 10\r\n\r\n{}")
        with os.fdopen(read_fd, "rb", buffering=0) as reader:
            try:
                _read_framed_json_with_timeout(reader, timeout=0.01)
                raise AssertionError("read should have timed out")
            except TimeoutError as exc:
                assert "timed out waiting for JSON-RPC response" in str(exc)
    finally:
        os.close(write_fd)


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
    assert process.stderr is not None

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
        initialize_response = _read_framed_json_with_timeout(
            process.stdout,
            stderr=process.stderr,
        )

        _write_framed_json(
            process.stdin,
            {"jsonrpc": "2.0", "id": 2, "method": "missing", "params": {}},
        )
        unknown_response = _read_framed_json_with_timeout(
            process.stdout,
            stderr=process.stderr,
        )

        _write_framed_json(
            process.stdin,
            {"jsonrpc": "2.0", "id": 3, "method": "shutdown", "params": {}},
        )
        shutdown_response = _read_framed_json_with_timeout(
            process.stdout,
            stderr=process.stderr,
        )

        assert initialize_response["result"]["driver"]["name"] == "hermes"
        assert unknown_response["error"]["code"] == -32601
        assert shutdown_response["result"] == {}
        assert process.wait(timeout=5) == 0
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
