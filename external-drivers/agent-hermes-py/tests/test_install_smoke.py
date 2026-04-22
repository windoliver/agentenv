import json
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parents[1]


def test_manifest_template_is_discoverable_after_minimal_staged_install(tmp_path):
    install_root = tmp_path / "home" / ".agentenv" / "drivers" / "agent-hermes"
    (install_root / "bin").mkdir(parents=True)
    launcher = install_root / "bin" / "agentenv-driver-hermes"
    launcher.write_text("#!/bin/sh\nexit 0\n")
    launcher.chmod(0o755)
    (install_root / "manifest.json").write_text((ROOT / "manifest.json.in").read_text())

    env = os.environ.copy()
    real_home = env["HOME"]
    cargo_home = Path(env.get("CARGO_HOME", Path(real_home) / ".cargo"))
    env["HOME"] = str(tmp_path / "home")
    env["PATH"] = os.pathsep.join([str(cargo_home / "bin"), env["PATH"]])
    env.setdefault("CARGO_HOME", str(cargo_home))
    env.setdefault("RUSTUP_HOME", str(Path(real_home) / ".rustup"))
    env.pop("AGENTENV_DRIVER_PATH", None)

    completed = subprocess.run(
        ["cargo", "run", "-p", "agentenv", "--", "drivers", "list"],
        cwd=WORKSPACE,
        env=env,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    assert "agent" in completed.stdout
    assert "hermes" in completed.stdout
    assert "installed" in completed.stdout
    manifest = json.loads((install_root / "manifest.json").read_text())
    assert manifest["name"] == "hermes"


def test_install_driver_rewrites_console_script_shebangs_after_move(tmp_path):
    fake_package = tmp_path / "fake-hermes-agent"
    fake_package.mkdir()
    (fake_package / "pyproject.toml").write_text(
        """[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "fake-hermes-agent"
version = "0.1.0"

[project.scripts]
hermes = "fake_hermes:main"

[tool.setuptools.packages.find]
where = ["src"]
"""
    )
    fake_module = fake_package / "src" / "fake_hermes"
    fake_module.mkdir(parents=True)
    (fake_module / "__init__.py").write_text(
        """import sys

def main():
    if sys.argv[1:] == ["--version"]:
        print("fake-hermes 0.1.0")
        return 0
    return 2
"""
    )

    home = tmp_path / "home"
    env = os.environ.copy()
    env.update(
        {
            "HOME": str(home),
            "AGENTENV_HOME": str(home / ".agentenv"),
            "HERMES_AGENT_PACKAGE": str(fake_package),
            "HERMES_AGENT_INSTALL_REQUIREMENT": "fake-hermes-agent",
            "PYTHON": sys.executable,
        }
    )

    subprocess.run(
        [str(ROOT / "scripts" / "install-driver.sh")],
        cwd=WORKSPACE,
        env=env,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    hermes = home / ".agentenv" / "drivers" / "agent-hermes" / "venv" / "bin" / "hermes"
    completed = subprocess.run(
        [str(hermes), "--version"],
        env=env,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    assert completed.stdout.strip() == "fake-hermes 0.1.0"
