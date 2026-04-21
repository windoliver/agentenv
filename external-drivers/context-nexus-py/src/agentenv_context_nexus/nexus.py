import hashlib
import os
import shutil
import socket
import subprocess
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass
class ParsedUrl:
    url: str
    scheme: str
    host: str
    port: int | None


def parse_http_url(raw):
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("hub_url must use http or https")
    if not parsed.hostname:
        raise ValueError("hub_url must include a host")
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    return ParsedUrl(url=raw.rstrip("/"), scheme=parsed.scheme, host=parsed.hostname, port=port)


def stable_hub_handle(hub_url, zones):
    digest = hashlib.sha256((hub_url + "|" + ",".join(zones)).encode("utf-8")).hexdigest()[:16]
    return f"nexus-hub-{digest}"


def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _nexus_child_env(extra_env=None):
    env = {}
    if "PATH" in os.environ:
        env["PATH"] = os.environ["PATH"]
    if extra_env:
        env.update(extra_env)
    return env


def check_nexus_cli(timeout=5):
    nexus = shutil.which("nexus")
    if nexus is None:
        return False, "nexus_cli_missing", "Nexus CLI was not found in the driver environment"
    try:
        result = subprocess.run(
            [nexus, "--version"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=_nexus_child_env(),
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, "nexus_cli_unusable", f"Nexus CLI version check failed: {exc}"
    if result.returncode != 0:
        return False, "nexus_cli_unusable", f"Nexus CLI version check exited with {result.returncode}"
    return True, None, None


def start_lite_process(data_dir, port, extra_env=None):
    env = _nexus_child_env(extra_env)
    env["NEXUS_DATA_DIR"] = data_dir
    return subprocess.Popen(
        ["nexus", "mcp", "serve", "--transport", "http", "--host", "127.0.0.1", "--port", str(port)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
        start_new_session=True,
    )
