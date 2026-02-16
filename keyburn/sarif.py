from __future__ import annotations

import os
from typing import Iterable

from . import __version__
from .scanner import Finding


_LEVEL = {"high": "error", "medium": "warning", "low": "note"}


def findings_to_sarif(findings: Iterable[Finding]) -> dict:
    rules: list[dict] = []
    rule_index: dict[str, int] = {}
    results: list[dict] = []

    for f in findings:
        if f.pattern_id not in rule_index:
            rule_index[f.pattern_id] = len(rules)
            help_text = f.remediation or "Remove the secret from git history and rotate/revoke it."
            rules.append(
                {
                    "id": f.pattern_id,
                    "name": f.pattern_id,
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": "Potential secret detected. Rotate/revoke if real."},
                    "help": {"text": help_text},
                    "properties": {"tags": ["secret"], "severity": f.severity.value},
                }
            )

        results.append(
            {
                "ruleId": f.pattern_id,
                "ruleIndex": rule_index[f.pattern_id],
                "level": _LEVEL.get(f.severity.value, "warning"),
                "message": {"text": f.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.path.replace(os.sep, "/")},
                            "region": {"startLine": f.line, "startColumn": f.column},
                        }
                    }
                ],
                "properties": {"fingerprint": f.fingerprint},
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "keyburn",
                        "version": __version__,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }

