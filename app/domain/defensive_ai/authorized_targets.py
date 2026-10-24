from dataclasses import dataclass, field
from typing import List


@dataclass
class AuthorizedTargetProfile:
    target_id: str
    target_type: str
    authorization_mode: str
    evidence_reference: str
    allowed_operations: List[str] = field(default_factory=list)
    constraints: List[str] = field(default_factory=list)
