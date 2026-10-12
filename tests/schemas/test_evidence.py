from datetime import UTC, datetime

from src.schemas.evidence import Evidence


def test_evidence_creation():
    timestamp = datetime.now(UTC)

    evidence = Evidence(
        id="EV-001",
        source="trivy",
        type="vulnerability",
        timestamp=timestamp,
        severity="CRITICAL",
        message="openssl vulnerability detected",
    )

    assert evidence.id == "EV-001"
    assert evidence.source == "trivy"
    assert evidence.type == "vulnerability"
    assert evidence.timestamp == timestamp
    assert evidence.severity == "CRITICAL"
    assert evidence.message == "openssl vulnerability detected"
    assert evidence.metadata == {}
