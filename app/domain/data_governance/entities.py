from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class DataSourceProfile:
    id: str
    name: str
    source_type: str
    provenance: str
    enabled: bool = True
    trust_tier: str = "baseline"
    sanitization_level: str = "standard"


@dataclass
class TrustScore:
    score: float
    confidence: float
    reasons: List[str] = field(default_factory=list)


@dataclass
class SanitizationResult:
    source_id: str
    stripped_payloads: int
    redacted_fields: List[str] = field(default_factory=list)
    quarantined: bool = False
    sanitized_payload: Optional[dict] = None
