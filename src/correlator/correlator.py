from src.schemas.correlation import CorrelationGroup
from src.schemas.evidence import Evidence


def correlate_evidence(
    evidence_list: list[Evidence],
) -> list[CorrelationGroup]:
    groups: dict[tuple[str, str], list[Evidence]] = {}

    for evidence in evidence_list:
        target = evidence.metadata.get("target", "unknown")
        package = evidence.metadata.get("package", "unknown")

        key = (target, package)

        if key not in groups:
            groups[key] = []

        groups[key].append(evidence)

    correlation_groups: list[CorrelationGroup] = []

    for index, evidence_group in enumerate(groups.values(), start=1):
        correlation_groups.append(
            CorrelationGroup(
                group_id=f"group-{index:03d}",
                evidence_ids=[evidence.id for evidence in evidence_group],
                correlation_reason="Same target and same package",
                score=2,
                primary_evidence=evidence_group[0].id,
            )
        )

    return correlation_groups
