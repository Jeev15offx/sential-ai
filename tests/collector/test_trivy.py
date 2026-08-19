import json

from src.collector.trivy import collect_trivy_evidence


def test_collect_trivy_evidence(tmp_path):
    report = {
        "Results": [
            {
                "Target": "sentinal-ai:ci",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-1234",
                        "PkgName": "express",
                        "Severity": "HIGH",
                        "InstalledVersion": "4.17.1",
                        "FixedVersion": "4.17.2",
                        "Title": "Regular Expression Denial of Service",
                    }
                ],
            }
        ]
    }

    report_path = tmp_path / "trivy-report.json"

    report_path.write_text(
        json.dumps(report),
        encoding="utf-8",
    )

    evidence = collect_trivy_evidence(report_path)

    assert len(evidence) == 1

    item = evidence[0]

    assert item.source == "trivy"
    assert item.type == "container_vulnerability"
    assert item.severity == "HIGH"

    assert item.metadata["vulnerability_id"] == "CVE-2023-1234"
    assert item.metadata["package"] == "express"
    assert item.metadata["installed_version"] == "4.17.1"
    assert item.metadata["fixed_version"] == "4.17.2"
    assert item.metadata["target"] == "sentinal-ai:ci"
