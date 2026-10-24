import json
import re
import uuid
from dataclasses import asdict
from typing import Any, Dict, List

from app.domain.data_governance import DataSourceProfile, SanitizationResult, TrustScore


class DataGovernanceService:
    SECRET_PATTERNS = [
        re.compile(r"(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{6,})"),
        re.compile(r"AKIA[0-9A-Z]{16}"),
    ]
    PROMPT_INJECTION_PATTERNS = [
        re.compile(r"(?i)ignore\s+previous\s+instructions"),
        re.compile(r"(?i)system\s+prompt"),
        re.compile(r"(?i)exfiltrate"),
        re.compile(r"(?i)<script[^>]*>"),
    ]

    def __init__(self, sovereign_db_service):
        self.sovereign_db = sovereign_db_service

    def register_source(
        self,
        name: str,
        source_type: str,
        provenance: str,
        trust_tier: str = "baseline",
        sanitization_level: str = "standard",
    ) -> Dict[str, Any]:
        profile = DataSourceProfile(
            id=str(uuid.uuid4()),
            name=name,
            source_type=source_type,
            provenance=provenance,
            trust_tier=trust_tier,
            sanitization_level=sanitization_level,
        )
        stored = self.sovereign_db.create_data_source_profile(asdict(profile))
        return stored

    def list_sources(self) -> List[Dict[str, Any]]:
        return self.sovereign_db.list_data_source_profiles()

    def assess_payload(self, source_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        profile = self.sovereign_db.get_data_source_profile(source_id)
        if not profile:
            raise ValueError(f"Unknown data source profile: {source_id}")

        sanitized, stripped_payloads, redacted_fields, suspicious_markers = self._sanitize_payload(payload)
        trust = self._score_trust(profile, payload, suspicious_markers)
        result = SanitizationResult(
            source_id=source_id,
            stripped_payloads=stripped_payloads,
            redacted_fields=redacted_fields,
            quarantined=trust.score < 0.45 or len(suspicious_markers) >= 2,
            sanitized_payload=sanitized,
        )

        event = {
            "id": str(uuid.uuid4()),
            "source_id": source_id,
            "trust_score": trust.score,
            "confidence": trust.confidence,
            "quarantined": result.quarantined,
            "redacted_fields": result.redacted_fields,
            "stripped_payloads": result.stripped_payloads,
            "reasons": trust.reasons,
            "sanitized_payload": sanitized,
        }
        self.sovereign_db.store_data_governance_event(event)

        return {
            "profile": profile,
            "trust": asdict(trust),
            "sanitization": asdict(result),
            "suspicious_markers": suspicious_markers,
        }

    def _sanitize_payload(self, payload: Dict[str, Any]):
        raw = json.dumps(payload)
        stripped_payloads = 0
        redacted_fields: List[str] = []
        suspicious_markers: List[str] = []
        sanitized = json.loads(json.dumps(payload))

        def walk(node: Any, path: str = ""):
            nonlocal stripped_payloads
            if isinstance(node, dict):
                for key, value in list(node.items()):
                    current_path = f"{path}.{key}" if path else key
                    if isinstance(value, str):
                        lowered = value.lower()
                        if any(pattern.search(value) for pattern in self.PROMPT_INJECTION_PATTERNS):
                            suspicious_markers.append(current_path)
                        if any(pattern.search(value) for pattern in self.SECRET_PATTERNS):
                            node[key] = "[REDACTED]"
                            redacted_fields.append(current_path)
                        elif "<script" in lowered or "javascript:" in lowered:
                            node[key] = value.replace("<", "&lt;").replace(">", "&gt;")
                            stripped_payloads += 1
                            suspicious_markers.append(current_path)
                    else:
                        walk(value, current_path)
            elif isinstance(node, list):
                for index, item in enumerate(node):
                    walk(item, f"{path}[{index}]")

        walk(sanitized)
        return sanitized, stripped_payloads, redacted_fields, suspicious_markers

    def _score_trust(self, profile: Dict[str, Any], payload: Dict[str, Any], suspicious_markers: List[str]) -> TrustScore:
        score = 0.7
        reasons = [f"base:{profile.get('trust_tier', 'baseline')}"]

        provenance = str(profile.get("provenance", "")).lower()
        if provenance.startswith("official") or "cisa" in provenance or "nist" in provenance:
            score += 0.2
            reasons.append("official-source")
        elif provenance.startswith("community"):
            score -= 0.05
            reasons.append("community-source")

        if suspicious_markers:
            score -= min(0.4, 0.15 * len(suspicious_markers))
            reasons.append(f"suspicious-markers:{len(suspicious_markers)}")

        if payload.get("manually_curated"):
            score += 0.05
            reasons.append("manual-review")

        score = max(0.0, min(1.0, score))
        confidence = min(1.0, 0.55 + (0.1 * len(reasons)))
        return TrustScore(score=score, confidence=confidence, reasons=reasons)
