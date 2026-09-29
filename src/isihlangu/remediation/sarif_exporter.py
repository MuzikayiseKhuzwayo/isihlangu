"""SARIF 2.1.0 Exporter: Standardized vulnerability reporting for CI/CD pipelines."""

from typing import Any

from isihlangu.core.types import Severity, VulnerabilityReport


class SARIFExporter:
    """Exports findings to SARIF (Static Analysis Results Interchange Format) v2.1.0."""

    @staticmethod
    def to_sarif(
        vulnerabilities: list[VulnerabilityReport],
        target_name: str = "Agentic SaaS Target",
    ) -> dict[str, Any]:
        rules: dict[str, dict[str, Any]] = {}
        results: list[dict[str, Any]] = []

        level_map = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "none",
        }

        for vuln in vulnerabilities:
            rule_id = vuln.owasp_category.value.split(":")[0]
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": vuln.owasp_category.value,
                    "shortDescription": {"text": vuln.owasp_category.value},
                    "defaultConfiguration": {"level": level_map.get(vuln.severity, "warning")},
                }

            results.append(
                {
                    "ruleId": rule_id,
                    "message": {"text": f"{vuln.title}: {vuln.description}"},
                    "level": level_map.get(vuln.severity, "warning"),
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": f"mcp://{vuln.evidence.get('tool_name', 'target')}"},
                                "region": {"startLine": 1},
                            }
                        }
                    ],
                    "fixes": [
                        {
                            "description": {"text": "Isihlangu synthesized remediation patch"},
                            "artifactChanges": [],
                        }
                    ],
                    "properties": {
                        "severity": vuln.severity.value,
                        "remediationPatch": vuln.remediation_patch,
                    },
                }
            )

        sarif_document = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Isihlangu",
                            "version": "0.1.0",
                            "informationUri": "https://github.com/isihlangu/isihlangu",
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }

        return sarif_document
