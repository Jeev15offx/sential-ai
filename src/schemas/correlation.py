from dataclasses import dataclass


@dataclass
class CorrelationGroup:
    group_id: str
    evidence_ids: list[str]
    correlation_reason: str
    score: int
    primary_evidence: str
