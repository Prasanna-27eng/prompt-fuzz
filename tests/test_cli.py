from typer.testing import CliRunner

from promptfuzz.cli import app

runner = CliRunner()


def test_list_payloads():
    result = runner.invoke(app, ["list-payloads"])
    assert result.exit_code == 0
    assert "jailbreak_dan_01" in result.stdout
    assert "Categories:" in result.stdout


def test_list_payloads_category_filter():
    result = runner.invoke(app, ["list-payloads", "--categories", "jailbreak"])
    assert result.exit_code == 0
    assert "jailbreak_dan_01" in result.stdout
    assert "system_override_01" not in result.stdout
