from __future__ import annotations

from .driver import build_handlers
from .jsonrpc import JsonRpcServer


def main() -> None:
    JsonRpcServer(build_handlers()).serve()


if __name__ == "__main__":
    main()
