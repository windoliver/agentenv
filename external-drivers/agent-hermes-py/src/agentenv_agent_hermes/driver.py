from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .hermes import HermesDriver


def build_handlers(driver: HermesDriver | None = None) -> dict[str, Callable[[Any], Any]]:
    hermes = driver or HermesDriver()
    return {
        "initialize": hermes.initialize,
        "preflight": hermes.preflight,
        "install_steps": hermes.install_steps,
        "mcp_config_path": hermes.mcp_config_path,
        "render_mcp_config": hermes.render_mcp_config,
        "render_entrypoint": hermes.render_entrypoint,
        "credential_requirements": hermes.credential_requirements,
        "health_check_probe": hermes.health_check_probe,
        "shutdown": hermes.shutdown,
    }
