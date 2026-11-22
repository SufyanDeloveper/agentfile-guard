from __future__ import annotations

import json
from pathlib import Path

from .models import ScanResult
from .rules import ALL_RULE_METADATA

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"


def to_sarif(result: ScanResult) -> dict:
    rules = []
    for rule in ALL_RULE_METADATA:
        rules.append(
            {
                "id": rule.id,
                "name": rule.name,
                "shortDescription": {"text": rule.description},
                "fullDescription": {"text": rule.description},
                "defaultConfiguration": {"level": _sarif_level(rule.severity.value)},
                "properties": {"severity": rule.severity.value},
            }
        )

    results = []
    for f in result.findings:
        rel = _rel(f.path, result.root)
        results.append(
            {
                "ruleId": f.rule.id,
                "level": _sarif_level(f.severity.value),
                "message": {"text": f.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": rel, "uriBaseId": "%SRCROOT%"},
                            "region": {
                                "startLine": f.line,
                                "startColumn": f.column,
                                "endLine": f.end_line or f.line,
                                "endColumn": f.end_column or (f.column + 1),
                            },
                        }
                    }
                ],
            }
        )

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "agentfile-guard",
                        "informationUri": "https://github.com/SufyanDeloveper/agentfile-guard",
                        "rules": rules,
                    }
                },
                "originalUriBaseIds": {"%SRCROOT%": {"uri": _file_uri(result.root) + "/"}},
                "results": results,
            }
        ],
    }


def dumps_sarif(result: ScanResult) -> str:
    return json.dumps(to_sarif(result), indent=2, ensure_ascii=False) + "\n"


def _sarif_level(severity: str) -> str:
    if severity == "error":
        return "error"
    if severity == "warning":
        return "warning"
    return "note"


def _rel(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return path.as_posix()


def _file_uri(path: Path) -> str:
    # Path.as_uri() handles Windows drive letters.
    return path.resolve().as_uri()
