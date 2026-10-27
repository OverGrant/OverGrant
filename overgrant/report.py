"""Render a redacted scan result as text, JSON, or SARIF 2.1.0."""

import json
from urllib.parse import quote

from . import __version__
from .rules import RULES


def to_text(result):
    lines = []
    for finding in result["findings"]:
        lines.extend((
            f'{finding["severity"].upper()} {finding["rule_id"]} '
            f'{finding["file"]}:{finding["path"] or "$"}',
            f'  Why: {finding["why"]}',
            f'  Fix: {finding["fix"]}',
            f'  Source: {finding["source"]}',
        ))
        if finding["details"]:
            lines.append(f'  Details: {finding["details"]}')
    lines.extend(f"Note: {note}" for note in result["notes"])
    lines.append(f'{len(result["findings"])} finding(s).')
    return "\n".join(lines)


def to_json(result):
    return json.dumps({"version": __version__, **result}, indent=2, ensure_ascii=False)


def to_sarif(result):
    ids = sorted({finding["rule_id"] for finding in result["findings"]})
    indexes = {rule_id: index for index, rule_id in enumerate(ids)}
    rules = []
    for rule_id in ids:
        severity, why, fix, source = RULES[rule_id]
        rules.append({
            "id": rule_id, "shortDescription": {"text": why},
            "fullDescription": {"text": f"{why} {fix}"}, "helpUri": source,
            "defaultConfiguration": {"level": _level(severity)},
            "properties": {"severity": severity},
        })
    results = []
    for finding in result["findings"]:
        message = f'{finding["why"]} Fix: {finding["fix"]}'
        if finding["details"]:
            message += f' Details: {finding["details"]}'
        results.append({
            "ruleId": finding["rule_id"], "ruleIndex": indexes[finding["rule_id"]],
            "level": _level(finding["severity"]), "message": {"text": message},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "file://" + quote(
                    finding["file"], safe="/", encoding="utf-8", errors="backslashreplace")},
            }, "logicalLocations": [{"fullyQualifiedName": finding["path"] or "$"}]}],
            "properties": {
                "severity": finding["severity"], "path": finding["path"],
                "fix": finding["fix"], "source": finding["source"],
            },
        })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "overgrant", "version": __version__, "rules": rules}},
            "results": results,
            "invocations": [{
                "executionSuccessful": True,
                "toolExecutionNotifications": [
                    {"level": "warning", "message": {"text": note}} for note in result["notes"]
                ],
            }],
        }],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)


def _level(severity):
    return {"critical": "error", "high": "error", "medium": "warning", "low": "note"}[severity]


def render(result, format):
    rendered = {"text": to_text, "json": to_json, "sarif": to_sarif}[format](result)
    return rendered.encode("utf-8", errors="backslashreplace").decode("utf-8")
