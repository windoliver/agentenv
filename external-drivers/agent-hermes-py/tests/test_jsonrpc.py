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


def test_server_returns_parse_error_for_negative_content_length():
    class NegativeContentLengthStream(io.BytesIO):
        def __init__(self):
            super().__init__(b"Content-Length: -1\r\n\r\n")
            self.read_sizes: list[int] = []

        def read(self, size: int = -1):
            self.read_sizes.append(size)
            if size == -1:
                return b"{}"
            return super().read(size)

    input_stream = NegativeContentLengthStream()
    output_stream = io.BytesIO()

    JsonRpcServer({}).serve(input_stream=input_stream, output_stream=output_stream)

    output_stream.seek(0)
    payload = read_framed_json(output_stream)

    assert payload["jsonrpc"] == "2.0"
    assert payload["id"] is None
    assert payload["error"]["code"] == JSON_RPC_PARSE_ERROR
    assert input_stream.read_sizes == []
