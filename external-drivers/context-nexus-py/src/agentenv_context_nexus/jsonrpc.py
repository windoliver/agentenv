import json
import sys


def read_message(stream):
    content_length = None
    while True:
        line = stream.readline()
        if line == b"":
            raise EOFError("unexpected EOF while reading JSON-RPC headers")
        if line == b"\r\n":
            break
        if line.startswith(b"Content-Length: "):
            raw = line[len(b"Content-Length: ") :].strip()
            try:
                content_length = int(raw)
            except ValueError as exc:
                raise ValueError(f"invalid Content-Length header {raw!r}") from exc
    if content_length is None:
        raise ValueError("missing Content-Length header")
    payload = stream.read(content_length)
    if len(payload) != content_length:
        raise EOFError("unexpected EOF while reading JSON-RPC payload")
    return json.loads(payload.decode("utf-8"))


def write_message(stream, message):
    payload = json.dumps(message, separators=(",", ":")).encode("utf-8")
    stream.write(f"Content-Length: {len(payload)}\r\n\r\n".encode("ascii"))
    stream.write(payload)
    stream.flush()


class JsonRpcServer:
    def __init__(self, handler):
        self._handler = handler

    def serve(self, stdin=None, stdout=None):
        stdin = stdin or sys.stdin.buffer
        stdout = stdout or sys.stdout.buffer
        while True:
            try:
                request = read_message(stdin)
            except EOFError:
                return
            response = self._handler.handle(request)
            if response is not None:
                write_message(stdout, response)
            if request.get("method") == "shutdown" and "error" not in response:
                return
