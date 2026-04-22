from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parents[1]


def test_readme_documents_install_tests_and_cli_lifecycle():
    text = (ROOT / "README.md").read_text()

    assert "scripts/install-driver.sh" in text
    assert "scripts/run-tests.sh" in text
    assert "agentenv create" in text
    assert "agentenv destroy" in text


def test_reference_blueprint_names_external_driver_directory():
    text = (WORKSPACE / "blueprints" / "hermes+nexus+openshell.yaml").read_text()

    assert "agent-hermes" in text
    assert "agentenv drivers list" in text
    assert "agentenv destroy" in text
