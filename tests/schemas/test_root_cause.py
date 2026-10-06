from src.schemas.root_cause import RootCause


def test_root_cause_creation():
    root_cause = RootCause(
        root_cause_id="rca-001",
        correlation_group_id="group-001",
        root_cause_type="container_vulnerability",
        summary="Vulnerable openssl package detected",
        explanation="The container contains a vulnerable version of openssl.",
        confidence=0.95,
        evidence_ids=["evidence-001"],
        remediation_hint="Upgrade openssl or rebuild with an updated base image.",
    )

    assert root_cause.root_cause_id == "rca-001"
    assert root_cause.correlation_group_id == "group-001"
    assert root_cause.root_cause_type == "container_vulnerability"
    assert root_cause.summary == "Vulnerable openssl package detected"
    assert root_cause.explanation == (
        "The container contains a vulnerable version of openssl."
    )
    assert root_cause.confidence == 0.95
    assert root_cause.evidence_ids == ["evidence-001"]
    assert root_cause.remediation_hint == (
        "Upgrade openssl or rebuild with an updated base image."
    )
