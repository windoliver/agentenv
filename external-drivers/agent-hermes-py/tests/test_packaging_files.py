import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_manifest_template_matches_agent_discovery_shape():
    manifest = json.loads((ROOT / "manifest.json.in").read_text())

    assert manifest["schema_version"] == "1.0"
    assert manifest["name"] == "hermes"
    assert manifest["kind"] == "agent"
    assert manifest["binary"] == "./bin/agentenv-driver-hermes"
    assert manifest["capabilities_preview"] == {
        "supports_mcp": True,
        "supports_slash_commands": True,
        "supports_tui": True,
        "supports_headless": True,
    }


def test_packaging_scripts_are_present():
    for path in [
        ROOT / "scripts" / "install-driver.sh",
        ROOT / "scripts" / "build-bundle.sh",
        ROOT / "scripts" / "run-tests.sh",
    ]:
        text = path.read_text()
        assert text.startswith("#!/bin/sh\n")
        assert "set -eu" in text
