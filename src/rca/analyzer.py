from src.schemas.correlation import CorrelationGroup
from src.schemas.evidence import Evidence
from src.schemas.root_cause import RootCause


def _calculate_confidence(
    evidence_list: list[Evidence],
) -> float:
    severity_confidence = {
        "CRITICAL": 0.95,
        "HIGH": 0.85,
        "MEDIUM": 0.70,
        "LOW": 0.50,
        "UNKNOWN": 0.30,
    }

    highest_confidence = 0.0

    for evidence in evidence_list:
        confidence = severity_confidence.get(
            evidence.severity.upper(),
            0.30,
        )

        highest_confidence = max(
            highest_confidence,
            confidence,
        )

    return highest_confidence


def analyze_root_causes(
    evidence_list: list[Evidence],
    correlation_groups: list[CorrelationGroup],
) -> list[RootCause]:
    evidence_by_id = {
        evidence.id: evidence
        for evidence in evidence_list
    }

    root_causes: list[RootCause] = []

    severity_rank = {
        "UNKNOWN": 0,
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }

    for index, group in enumerate(
        correlation_groups,
        start=1,
    ):
        group_evidence = [
            evidence_by_id[evidence_id]
            for evidence_id in group.evidence_ids
        ]

        primary_evidence = max(
            group_evidence,
            key=lambda evidence: severity_rank.get(
                evidence.severity.upper(),
                0,
            ),
        )

        package = primary_evidence.metadata.get(
            "package",
            "unknown package",
        )

        fixed_version = primary_evidence.metadata.get(
            "fixed_version"
        )

        if fixed_version:
            remediation_hint = (
                f"Upgrade {package} to version {fixed_version}."
            )
        else:
            remediation_hint = (
                f"Upgrade {package} or rebuild with "
                "an updated base image."
            )

        root_causes.append(
            RootCause(
                root_cause_id=f"rca-{index:03d}",
                correlation_group_id=group.group_id,
                root_cause_type="container_vulnerability",
                summary=(
                    f"Vulnerable {package} package detected"
                ),
                explanation=(
                    f"The container contains a vulnerable "
                    f"version of {package}."
                ),
                confidence=_calculate_confidence(
                    group_evidence
                ),
                evidence_ids=group.evidence_ids,
                remediation_hint=remediation_hint,
            )
        )

    return root_causes
