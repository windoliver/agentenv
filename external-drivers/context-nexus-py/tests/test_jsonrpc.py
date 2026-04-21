import io

from agentenv_context_nexus.jsonrpc import read_message, write_message


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
