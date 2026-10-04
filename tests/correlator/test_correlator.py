from datetime import datetime, timezone

from src.correlator.correlator import correlate_evidence
from src.schemas.evidence import Evidence


def test_same_target_and_package_are_correlated():
    timestamp = datetime.now(timezone.utc)

    evidence_a = Evidence(
        id="evidence-001",
        source="trivy",
        type="container_vulnerability",
        timestamp=timestamp,
        severity="HIGH",
        message="CVE-001 in openssl",
        metadata={
            "target": "Debian",
            "package": "openssl",
        },
    )

    evidence_b = Evidence(
        id="evidence-002",
        source="trivy",
        type="container_vulnerability",
        timestamp=timestamp,
        severity="MEDIUM",
        message="CVE-002 in openssl",
        metadata={
            "target": "Debian",
            "package": "openssl",
        },
    )

    groups = correlate_evidence([evidence_a, evidence_b])

    assert len(groups) == 1

    group = groups[0]

    assert group.evidence_ids == [
        "evidence-001",
        "evidence-002",
    ]

    assert group.correlation_reason == ("Same target and same package")


def test_different_packages_are_not_correlated():
    timestamp = datetime.now(timezone.utc)

    evidence_a = Evidence(
        id="evidence-001",
        source="trivy",
        type="container_vulnerability",
        timestamp=timestamp,
        severity="HIGH",
        message="CVE-001 in openssl",
        metadata={
            "target": "Debian",
            "package": "openssl",
        },
    )

    evidence_b = Evidence(
        id="evidence-002",
        source="trivy",
        type="container_vulnerability",
        timestamp=timestamp,
        severity="MEDIUM",
        message="CVE-002 in curl",
        metadata={
            "target": "Debian",
            "package": "curl",
        },
    )

    groups = correlate_evidence([evidence_a, evidence_b])

    assert len(groups) == 2


def test_different_targets_are_not_correlated():
    timestamp = datetime.now(timezone.utc)

    evidence_a = Evidence(
        id="evidence-001",
        source="trivy",
        type="container_vulnerability",
        timestamp=timestamp,
        severity="HIGH",
        message="CVE-001 in openssl",
        metadata={
            "target": "Debian",
            "package": "openssl",
        },
    )

    evidence_b = Evidence(
        id="evidence-002",
        source="trivy",
        type="container_vulnerability",
        timestamp=timestamp,
        severity="MEDIUM",
        message="CVE-002 in openssl",
        metadata={
            "target": "Python",
            "package": "openssl",
        },
    )

    groups = correlate_evidence([evidence_a, evidence_b])

    assert len(groups) == 2


def test_every_evidence_item_is_preserved():
    timestamp = datetime.now(timezone.utc)

    evidence_a = Evidence(
        id="evidence-001",
        source="trivy",
        type="container_vulnerability",
        timestamp=timestamp,
        severity="HIGH",
        message="CVE-001 in openssl",
        metadata={
            "target": "Debian",
            "package": "openssl",
        },
    )

    evidence_b = Evidence(
        id="evidence-002",
        source="trivy",
        type="container_vulnerability",
        timestamp=timestamp,
        severity="MEDIUM",
        message="CVE-002 in curl",
        metadata={
            "target": "Debian",
            "package": "curl",
        },
    )

    evidence_c = Evidence(
        id="evidence-003",
        source="trivy",
        type="container_vulnerability",
        timestamp=timestamp,
        severity="LOW",
        message="CVE-003 in pip",
        metadata={
            "target": "Python",
            "package": "pip",
        },
    )

    evidence_d = Evidence(
        id="evidence-004",
        source="trivy",
        type="container_vulnerability",
        timestamp=timestamp,
        severity="CRITICAL",
        message="CVE-004 in openssl",
        metadata={
            "target": "Debian",
            "package": "openssl",
        },
    )

    groups = correlate_evidence(
        [
            evidence_a,
            evidence_b,
            evidence_c,
            evidence_d,
        ]
    )

    assert len(groups) == 3

    all_evidence_ids = [
        evidence_id for group in groups for evidence_id in group.evidence_ids
    ]

    assert set(all_evidence_ids) == {
        "evidence-001",
        "evidence-002",
        "evidence-003",
        "evidence-004",
    }

    assert len(all_evidence_ids) == 4


def test_correlation_group_metadata_is_valid():
    timestamp = datetime.now(timezone.utc)

    evidence_a = Evidence(
        id="evidence-001",
        source="trivy",
        type="container_vulnerability",
        timestamp=timestamp,
        severity="HIGH",
        message="CVE-001 in openssl",
        metadata={
            "target": "Debian",
            "package": "openssl",
        },
    )

    evidence_b = Evidence(
        id="evidence-002",
        source="trivy",
        type="container_vulnerability",
        timestamp=timestamp,
        severity="MEDIUM",
        message="CVE-002 in openssl",
        metadata={
            "target": "Debian",
            "package": "openssl",
        },
    )

    groups = correlate_evidence([evidence_a, evidence_b])

    assert len(groups) == 1

    group = groups[0]

    assert group.group_id == "group-001"
    assert group.score == 2
    assert group.correlation_reason == ("Same target and same package")
    assert group.primary_evidence in group.evidence_ids
