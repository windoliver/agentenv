from dataclasses import dataclass
from typing import Any

SCHEMA_VERSION = "1.0"

JSON_RPC_PARSE_ERROR = -32700
JSON_RPC_INVALID_REQUEST = -32600
JSON_RPC_METHOD_NOT_FOUND = -32601
JSON_RPC_INVALID_PARAMS = -32602
JSON_RPC_INTERNAL_ERROR = -32603
ERROR_CAPABILITY_MISSING = -32000
ERROR_PREFLIGHT_FAILED = -32001
ERROR_SCHEMA_VERSION_INCOMPATIBLE = -32002


def _major(version: str) -> int:
    parts = version.split(".")
    if len(parts) != 2 or not parts[0].isdigit() or not parts[1].isdigit():
        raise ValueError(
            f"schema version `{version}` must use `<major>.<minor>` format"
        )
    return int(parts[0])


def assert_schema_compatible(version: str) -> None:
    expected = _major(SCHEMA_VERSION)
    actual = _major(version)
    if actual != expected:
        raise ValueError(
            "incompatible schema version: core and driver major schema versions "
            f"match only when both use major `{expected}`; got `{version}`"
        )


@dataclass
class RpcError(Exception):
    code: int
    message: str
    data: Any | None = None

    def to_response_error(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "code": self.code,
            "message": self.message,
        }
        if self.data is not None:
            payload["data"] = self.data
        return payload
