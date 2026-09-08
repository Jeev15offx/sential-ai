import json
from pathlib import Path

from src.collector.trivy import collect_trivy_evidence

FIXTURE_PATH = Path("tests/fixtures/trivy/sample-report.json")


def test_collect_real_trivy_report():
    evidence = collect_trivy_evidence(FIXTURE_PATH)

    assert len(evidence) == 192

    for item in evidence:
        assert item.source == "trivy"
        assert item.type == "container_vulnerability"
        assert item.severity in {
            "UNKNOWN",
            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL",
        }

        assert item.id
        assert item.message
        assert item.metadata["vulnerability_id"]
        assert item.metadata["package"]
        assert item.metadata["target"]


def test_real_trivy_report_contains_debian_and_python_findings():
    with FIXTURE_PATH.open("r", encoding="utf-8") as file:
        data = json.load(file)

    results = data["Results"]

    assert len(results) == 2

    targets = {result["Target"] for result in results}

    assert "sentinal-ai:v2 (debian 13.5)" in targets
    assert "Python" in targets


def test_evidence_ids_are_unique():
    evidence = collect_trivy_evidence(FIXTURE_PATH)

    ids = [item.id for item in evidence]

    assert len(ids) == len(set(ids))
