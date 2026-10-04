from src.schemas.correlation import CorrelationGroup


def test_correlation_group_creation():
    group = CorrelationGroup(
        group_id="group-001",
        evidence_ids=["evidence-001", "evidence-002"],
        correlation_reason="Same target and same package",
        score=2,
        primary_evidence="evidence-001",
    )

    assert group.group_id == "group-001"
    assert group.evidence_ids == [
        "evidence-001",
        "evidence-002",
    ]
    assert group.correlation_reason == "Same target and same package"
    assert group.score == 2
    assert group.primary_evidence == "evidence-001"
