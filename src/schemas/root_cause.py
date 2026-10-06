from dataclasses import dataclass


@dataclass
class RootCause:
    root_cause_id: str
    correlation_group_id: str
    root_cause_type: str
    summary: str
    explanation: str
    confidence: float
    evidence_ids: list[str]
    remediation_hint: str
