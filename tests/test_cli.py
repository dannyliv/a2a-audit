from __future__ import annotations

import json

from typer.testing import CliRunner

from a2a_audit.cli import app
from tests.conftest import FIXTURE_DIR

runner = CliRunner()


def test_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "a2a-audit" in result.stdout


def test_paste_json_clean(tmp_path):
    card = (FIXTURE_DIR / "clean.json").read_text()
    result = runner.invoke(
        app,
        ["--paste", "--json", "--classifier", "disabled", "--no-verify-sigs"],
        input=card,
    )
    # clean card has only MEDIUM/LOW -> exit 0 with default --fail-on HIGH
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["grade"] in ("A", "B")


def test_paste_plaintext_fails_on_high():
    card = (FIXTURE_DIR / "plaintext-http.json").read_text()
    result = runner.invoke(
        app,
        ["--paste", "--json", "--classifier", "disabled", "--no-verify-sigs"],
        input=card,
    )
    # plaintext HTTP is HIGH -> non-zero exit
    assert result.exit_code == 1
    data = json.loads(result.stdout)
    assert data["max_severity"] in ("HIGH", "CRITICAL")


def test_invalid_fail_on():
    result = runner.invoke(app, ["--paste", "--fail-on", "BOGUS"], input="{}")
    assert result.exit_code == 2


def test_no_target_errors():
    result = runner.invoke(app, [])
    assert result.exit_code == 2
