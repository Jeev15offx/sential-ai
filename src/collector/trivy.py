import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.schemas.evidence import Evidence


def _generate_evidence_id(
    vulnerability_id: str,
    package_name: str,
    target: str,
) -> str:
    """
    Generate a deterministic ID for a vulnerability evidence record.

    The same vulnerability + package + target combination
    will always produce the same ID.
    """
    raw_id = f"{vulnerability_id}:{package_name}:{target}"

    return hashlib.sha256(raw_id.encode("utf-8")).hexdigest()[:16]


def _build_message(vulnerability: dict[str, Any]) -> str:
    """
    Build a concise human-readable message from a Trivy vulnerability.
    """
    vulnerability_id = vulnerability.get(
        "VulnerabilityID",
        "Unknown vulnerability",
    )

    package_name = vulnerability.get(
        "PkgName",
        "unknown package",
    )

    title = vulnerability.get(
        "Title",
        "Vulnerability detected",
    )

    return f"{vulnerability_id}: {title} in package {package_name}"


def collect_trivy_evidence(
    report_path: str | Path,
) -> list[Evidence]:
    """
    Parse a Trivy JSON report and convert vulnerabilities
    into Sentinel-AI Evidence objects.

    Args:
        report_path: Path to the Trivy JSON report.

    Returns:
        A list of Evidence objects.

    Raises:
        FileNotFoundError:
            If the report does not exist.

        json.JSONDecodeError:
            If the report contains invalid JSON.

        ValueError:
            If the report structure is invalid.
    """

    report_path = Path(report_path)

    if not report_path.is_file():
        raise FileNotFoundError(f"Trivy report not found: {report_path}")

    with report_path.open(
        "r",
        encoding="utf-8",
    ) as file:
        data = json.load(file)

    if not isinstance(data, dict):
        raise TypeError("Invalid Trivy report: expected a JSON object.")

    results = data.get("Results", [])

    if not isinstance(results, list):
        raise TypeError("Invalid Trivy report: 'Results' must be a list.")

    evidence_list: list[Evidence] = []

    collection_time = datetime.now(timezone.utc)

    for result in results:

        if not isinstance(result, dict):
            continue

        target = result.get("Target", "unknown")

        vulnerabilities = result.get(
            "Vulnerabilities",
            [],
        )

        if not isinstance(vulnerabilities, list):
            continue

        for vulnerability in vulnerabilities:

            if not isinstance(vulnerability, dict):
                continue

            vulnerability_id = vulnerability.get(
                "VulnerabilityID",
                "UNKNOWN",
            )

            package_name = vulnerability.get(
                "PkgName",
                "unknown",
            )

            severity = vulnerability.get(
                "Severity",
                "UNKNOWN",
            ).upper()

            evidence_id = _generate_evidence_id(
                vulnerability_id=vulnerability_id,
                package_name=package_name,
                target=target,
            )

            evidence = Evidence(
                id=evidence_id,
                source="trivy",
                type="container_vulnerability",
                timestamp=collection_time,
                severity=severity,
                message=_build_message(vulnerability),
                metadata={
                    "vulnerability_id": vulnerability_id,
                    "package": package_name,
                    "installed_version": vulnerability.get("InstalledVersion"),
                    "fixed_version": vulnerability.get("FixedVersion"),
                    "title": vulnerability.get("Title"),
                    "target": target,
                    "primary_url": vulnerability.get("PrimaryURL"),
                    "references": vulnerability.get(
                        "References",
                        [],
                    ),
                    "published_date": vulnerability.get("PublishedDate"),
                    "last_modified_date": vulnerability.get("LastModifiedDate"),
                },
            )

            evidence_list.append(evidence)

    return evidence_list
