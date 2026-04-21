import io

from agentenv_context_nexus.jsonrpc import JsonRpcServer, read_message, write_message


def test_frame_roundtrip_preserves_message():
    stream = io.BytesIO()
    write_message(stream, {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}})
    stream.seek(0)

    assert read_message(stream) == {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}


def test_read_message_rejects_missing_content_length():
    stream = io.BytesIO(b"\r\n{}")

    try:
        read_message(stream)
    except ValueError as exc:
        assert "Content-Length" in str(exc)
    else:
        raise AssertionError("missing Content-Length should fail")


def test_read_message_rejects_negative_content_length():
    stream = io.BytesIO(b"Content-Length: -1\r\n\r\n{}")

    try:
        read_message(stream)
    except ValueError as exc:
        assert "Content-Length" in str(exc)
    else:
        raise AssertionError("negative Content-Length should fail")


def test_server_exits_on_shutdown_without_response():
    class Handler:
        def __init__(self):
            self.requests = []

        def handle(self, request):
            self.requests.append(request)
            return None

    for request in (
        {"jsonrpc": "2.0", "id": 1, "method": "shutdown"},
        {"jsonrpc": "2.0", "method": "shutdown"},
    ):
        stdin = io.BytesIO()
        stdout = io.BytesIO()
        write_message(stdin, request)
        stdin.seek(0)
        handler = Handler()

        JsonRpcServer(handler).serve(stdin=stdin, stdout=stdout)

        assert handler.requests == [request]
        assert stdout.getvalue() == b""
