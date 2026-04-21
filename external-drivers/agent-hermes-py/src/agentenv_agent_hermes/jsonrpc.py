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
    invalid_content_length: str | None = None

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
            except ValueError:
                invalid_content_length = (
                    f"invalid Content-Length `{raw.decode('ascii', 'replace')}`"
                )
                continue
            if content_length < 0:
                invalid_content_length = (
                    f"invalid Content-Length `{content_length}`: must be non-negative"
                )

    if invalid_content_length is not None:
        raise ValueError(invalid_content_length)
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

    def serve(
        self,
        input_stream: BinaryIO | None = None,
        output_stream: BinaryIO | None = None,
    ) -> None:
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
