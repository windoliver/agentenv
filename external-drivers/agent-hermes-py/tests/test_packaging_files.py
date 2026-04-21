import json
import stat
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = [
    ROOT / "scripts" / "install-driver.sh",
    ROOT / "scripts" / "build-bundle.sh",
    ROOT / "scripts" / "run-tests.sh",
]


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
    for path in SCRIPTS:
        text = path.read_text()
        assert text.startswith("#!/bin/sh\n")
        assert "set -eu" in text


def test_packaging_scripts_are_executable():
    for path in SCRIPTS:
        assert path.stat().st_mode & stat.S_IXUSR


def test_installer_uses_only_staged_wheels_after_bundle_creation():
    text = (ROOT / "scripts" / "install-driver.sh").read_text()

    assert '"hermes-agent[mcp]"' in text
    assert '--wheel-dir "${STAGED}/wheels"' in text
    assert "--no-index" in text
    assert '--find-links "${STAGED}/wheels"' in text
    assert "pip install --upgrade pip" not in text
    assert 'pip install "hermes-agent[mcp]"' not in text


def test_bundle_includes_hermes_agent_runtime_wheels():
    text = (ROOT / "scripts" / "build-bundle.sh").read_text()

    assert '"hermes-agent[mcp]"' in text
    assert '--wheel-dir "${TMP_ROOT}/agent-hermes/wheels"' in text
