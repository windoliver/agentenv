import json
import os
import subprocess
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
