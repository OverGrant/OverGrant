import json
from urllib.parse import unquote, urlsplit

import pytest

from overgrant import cli


def settings(repo, data):
    path = repo / ".claude/settings.json"
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(data))


@pytest.mark.parametrize("format", ["text", "json", "sarif"])
def test_clean_scan(format, repo, capsys):
    assert cli.main(["scan", str(repo), "--format", format]) == 0
    output = capsys.readouterr().out
    if format == "text":
        assert output.strip() == "0 finding(s)."
    elif format == "json":
        assert json.loads(output) == {"version": "0.1.0", "findings": [], "notes": []}
    else:
        sarif = json.loads(output)
        assert sarif["version"] == "2.1.0"
        assert sarif["runs"][0]["results"] == []


def test_path_defaults_to_current_directory(repo, monkeypatch, capsys):
    monkeypatch.chdir(repo)
    settings(repo, {"hooks": {}})
    assert cli.main(["scan"]) == 1
    assert "CC004" in capsys.readouterr().out


@pytest.mark.parametrize("fail_on,status", [
    ("low", 1), ("medium", 0), ("high", 0), ("critical", 0),
])
def test_fail_on_threshold(fail_on, status, repo, capsys):
    settings(repo, {"permissions": {"defaultMode": "auto"}})
    assert cli.main(["scan", str(repo), "--fail-on", fail_on]) == status
    assert "CC002" in capsys.readouterr().out


def test_default_high_threshold(repo, capsys):
    settings(repo, {"permissions": {"defaultMode": "auto"}})
    assert cli.main(["scan", str(repo)]) == 0
    settings(repo, {"hooks": {}})
    assert cli.main(["scan", str(repo)]) == 1
    capsys.readouterr()


@pytest.mark.parametrize("args", [[], ["other"], ["scan", "--format", "xml"],
                                  ["scan", "--fail-on", "urgent"], ["scan", "--unknown"]])
def test_usage_errors(args, capsys):
    with pytest.raises(SystemExit) as error:
        cli.main(args)
    assert error.value.code == 2
    assert "usage:" in capsys.readouterr().err


def test_nonexistent_repo_is_usage_error(repo, capsys):
    assert cli.main(["scan", str(repo / "does-not-exist")]) == 2
    captured = capsys.readouterr()
    assert not captured.out and "accessible repository directory" in captured.err


def test_sarif_locations_rules_fixes_and_notes(repo, capsys):
    settings(repo, {"hooks": {}})
    (repo / ".mcp.json").write_text("{")
    assert cli.main(["scan", str(repo), "--format", "sarif"]) == 1
    sarif = json.loads(capsys.readouterr().out)
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    finding = run["results"][0]
    rule = run["tool"]["driver"]["rules"][finding["ruleIndex"]]
    assert rule["id"] == finding["ruleId"] == "CC004"
    assert finding["level"] == "error"
    uri = finding["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert unquote(urlsplit(uri).path) == str(repo / ".claude/settings.json")
    assert finding["properties"]["path"] == "/hooks"
    assert finding["properties"]["severity"] == "high"
    assert finding["properties"]["source"].startswith("https://")
    assert finding["properties"]["fix"] in finding["message"]["text"]
    notes = run["invocations"][0]["toolExecutionNotifications"]
    assert len(notes) == 1 and "not valid JSON" in notes[0]["message"]["text"]


def test_version_flag_and_outputs(repo, capsys):
    from overgrant import __version__
    with pytest.raises(SystemExit) as exit:
        cli.main(["--version"])
    assert exit.value.code == 0
    assert capsys.readouterr().out.strip() == f"overgrant {__version__}" == "overgrant 0.1.0"
    cli.main(["scan", str(repo), "--format", "json"])
    assert json.loads(capsys.readouterr().out)["version"] == __version__
    cli.main(["scan", str(repo), "--format", "sarif"])
    driver = json.loads(capsys.readouterr().out)["runs"][0]["tool"]["driver"]
    assert driver["version"] == __version__
