from datetime import datetime, timezone

from src.rca.analyzer import analyze_root_causes
from src.schemas.correlation import CorrelationGroup
from src.schemas.evidence import Evidence


def test_vulnerable_package_produces_root_cause():
    evidence = [
        Evidence(
            id="evidence-001",
            source="trivy",
            type="container_vulnerability",
            timestamp=datetime.now(timezone.utc),
            severity="HIGH",
            message="CVE-2026-0001: Vulnerability detected in package openssl",
            metadata={
                "target": "sentinal-ai:v2",
                "package": "openssl",
                "vulnerability_id": "CVE-2026-0001",
            },
        )
    ]

    correlation_group = CorrelationGroup(
        group_id="group-001",
        evidence_ids=["evidence-001"],
        correlation_reason="Same target and same package",
        score=2,
        primary_evidence="evidence-001",
    )

    root_causes = analyze_root_causes(
        evidence_list=evidence,
        correlation_groups=[correlation_group],
    )

    assert len(root_causes) == 1

    root_cause = root_causes[0]

    assert root_cause.root_cause_type == "container_vulnerability"
    assert "openssl" in root_cause.summary
    assert root_cause.evidence_ids == ["evidence-001"]


def test_multiple_vulnerabilities_same_package_produce_one_root_cause():
    evidence = [
        Evidence(
            id="evidence-001",
            source="trivy",
            type="container_vulnerability",
            timestamp=datetime.now(timezone.utc),
            severity="HIGH",
            message="CVE-2026-0001: Vulnerability detected in package openssl",
            metadata={
                "target": "sentinal-ai:v2",
                "package": "openssl",
                "vulnerability_id": "CVE-2026-0001",
            },
        ),
        Evidence(
            id="evidence-002",
            source="trivy",
            type="container_vulnerability",
            timestamp=datetime.now(timezone.utc),
            severity="CRITICAL",
            message="CVE-2026-0002: Vulnerability detected in package openssl",
            metadata={
                "target": "sentinal-ai:v2",
                "package": "openssl",
                "vulnerability_id": "CVE-2026-0002",
            },
        ),
    ]

    correlation_group = CorrelationGroup(
        group_id="group-001",
        evidence_ids=[
            "evidence-001",
            "evidence-002",
        ],
        correlation_reason="Same target and same package",
        score=2,
        primary_evidence="evidence-001",
    )

    root_causes = analyze_root_causes(
        evidence_list=evidence,
        correlation_groups=[correlation_group],
    )

    assert len(root_causes) == 1

    root_cause = root_causes[0]

    assert root_cause.root_cause_type == "container_vulnerability"
    assert root_cause.evidence_ids == [
        "evidence-001",
        "evidence-002",
    ]
    assert "openssl" in root_cause.summary


def test_different_packages_produce_separate_root_causes():
    evidence = [
        Evidence(
            id="evidence-001",
            source="trivy",
            type="container_vulnerability",
            timestamp=datetime.now(timezone.utc),
            severity="HIGH",
            message="CVE-2026-0001: Vulnerability detected in package openssl",
            metadata={
                "target": "sentinal-ai:v2",
                "package": "openssl",
                "vulnerability_id": "CVE-2026-0001",
            },
        ),
        Evidence(
            id="evidence-002",
            source="trivy",
            type="container_vulnerability",
            timestamp=datetime.now(timezone.utc),
            severity="CRITICAL",
            message="CVE-2026-0002: Vulnerability detected in package curl",
            metadata={
                "target": "sentinal-ai:v2",
                "package": "curl",
                "vulnerability_id": "CVE-2026-0002",
            },
        ),
    ]

    correlation_groups = [
        CorrelationGroup(
            group_id="group-001",
            evidence_ids=["evidence-001"],
            correlation_reason="Same target and same package",
            score=2,
            primary_evidence="evidence-001",
        ),
        CorrelationGroup(
            group_id="group-002",
            evidence_ids=["evidence-002"],
            correlation_reason="Same target and same package",
            score=2,
            primary_evidence="evidence-002",
        ),
    ]

    root_causes = analyze_root_causes(
        evidence_list=evidence,
        correlation_groups=correlation_groups,
    )

    assert len(root_causes) == 2

    root_cause_types = {root_cause.root_cause_type for root_cause in root_causes}

    assert root_cause_types == {"container_vulnerability"}

    summaries = {root_cause.summary for root_cause in root_causes}

    assert "Vulnerable openssl package detected" in summaries
    assert "Vulnerable curl package detected" in summaries


def test_root_cause_preserves_all_evidence_ids():
    evidence = [
        Evidence(
            id="evidence-001",
            source="trivy",
            type="container_vulnerability",
            timestamp=datetime.now(timezone.utc),
            severity="HIGH",
            message="CVE-2026-0001: Vulnerability detected in package openssl",
            metadata={
                "target": "sentinal-ai:v2",
                "package": "openssl",
                "vulnerability_id": "CVE-2026-0001",
            },
        ),
        Evidence(
            id="evidence-002",
            source="trivy",
            type="container_vulnerability",
            timestamp=datetime.now(timezone.utc),
            severity="CRITICAL",
            message="CVE-2026-0002: Vulnerability detected in package openssl",
            metadata={
                "target": "sentinal-ai:v2",
                "package": "openssl",
                "vulnerability_id": "CVE-2026-0002",
            },
        ),
        Evidence(
            id="evidence-003",
            source="trivy",
            type="container_vulnerability",
            timestamp=datetime.now(timezone.utc),
            severity="MEDIUM",
            message="CVE-2026-0003: Vulnerability detected in package openssl",
            metadata={
                "target": "sentinal-ai:v2",
                "package": "openssl",
                "vulnerability_id": "CVE-2026-0003",
            },
        ),
    ]

    correlation_group = CorrelationGroup(
        group_id="group-001",
        evidence_ids=[
            "evidence-001",
            "evidence-002",
            "evidence-003",
        ],
        correlation_reason="Same target and same package",
        score=2,
        primary_evidence="evidence-001",
    )

    root_causes = analyze_root_causes(
        evidence_list=evidence,
        correlation_groups=[correlation_group],
    )

    assert len(root_causes) == 1

    root_cause = root_causes[0]

    assert root_cause.evidence_ids == [
        "evidence-001",
        "evidence-002",
        "evidence-003",
    ]


def test_critical_vulnerability_has_higher_confidence_than_low():
    evidence = [
        Evidence(
            id="evidence-low",
            source="trivy",
            type="container_vulnerability",
            timestamp=datetime.now(timezone.utc),
            severity="LOW",
            message="LOW vulnerability in openssl",
            metadata={
                "target": "sentinal-ai:v2",
                "package": "openssl",
                "vulnerability_id": "CVE-LOW",
            },
        ),
        Evidence(
            id="evidence-critical",
            source="trivy",
            type="container_vulnerability",
            timestamp=datetime.now(timezone.utc),
            severity="CRITICAL",
            message="CRITICAL vulnerability in curl",
            metadata={
                "target": "sentinal-ai:v2",
                "package": "curl",
                "vulnerability_id": "CVE-CRITICAL",
            },
        ),
    ]

    correlation_groups = [
        CorrelationGroup(
            group_id="group-low",
            evidence_ids=["evidence-low"],
            correlation_reason="Same target and same package",
            score=2,
            primary_evidence="evidence-low",
        ),
        CorrelationGroup(
            group_id="group-critical",
            evidence_ids=["evidence-critical"],
            correlation_reason="Same target and same package",
            score=2,
            primary_evidence="evidence-critical",
        ),
    ]

    root_causes = analyze_root_causes(
        evidence_list=evidence,
        correlation_groups=correlation_groups,
    )

    low_confidence = next(
        root_cause.confidence
        for root_cause in root_causes
        if root_cause.correlation_group_id == "group-low"
    )

    critical_confidence = next(
        root_cause.confidence
        for root_cause in root_causes
        if root_cause.correlation_group_id == "group-critical"
    )

    assert critical_confidence > low_confidence


def test_fixed_version_is_used_in_remediation_hint():
    evidence = [
        Evidence(
            id="evidence-openssl",
            source="trivy",
            type="container_vulnerability",
            timestamp=datetime.now(timezone.utc),
            severity="HIGH",
            message="HIGH vulnerability in openssl",
            metadata={
                "target": "sentinal-ai:v2",
                "package": "openssl",
                "vulnerability_id": "CVE-2026-1234",
                "installed_version": "3.0.2",
                "fixed_version": "3.0.17",
            },
        ),
    ]

    correlation_groups = [
        CorrelationGroup(
            group_id="group-openssl",
            evidence_ids=["evidence-openssl"],
            correlation_reason="Same target and same package",
            score=2,
            primary_evidence="evidence-openssl",
        ),
    ]

    root_causes = analyze_root_causes(
        evidence_list=evidence,
        correlation_groups=correlation_groups,
    )

    assert len(root_causes) == 1

    root_cause = root_causes[0]

    assert "3.0.17" in root_cause.remediation_hint


def test_missing_fixed_version_uses_generic_remediation():
    evidence = [
        Evidence(
            id="evidence-openssl",
            source="trivy",
            type="container_vulnerability",
            timestamp=datetime.now(timezone.utc),
            severity="HIGH",
            message="HIGH vulnerability in openssl",
            metadata={
                "target": "sentinal-ai:v2",
                "package": "openssl",
                "vulnerability_id": "CVE-2026-1234",
                "installed_version": "3.0.2",
                "fixed_version": None,
            },
        ),
    ]

    correlation_groups = [
        CorrelationGroup(
            group_id="group-openssl",
            evidence_ids=["evidence-openssl"],
            correlation_reason="Same target and same package",
            score=2,
            primary_evidence="evidence-openssl",
        ),
    ]

    root_causes = analyze_root_causes(
        evidence_list=evidence,
        correlation_groups=correlation_groups,
    )

    assert len(root_causes) == 1

    root_cause = root_causes[0]

    assert "None" not in root_cause.remediation_hint
    assert "openssl" in root_cause.remediation_hint
