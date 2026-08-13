from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class Evidence:
    id: str
    source: str
    type: str
    timestamp: datetime
    severity: str
    message: str
    metadata: dict[str, Any] = field(default_factory=dict)
