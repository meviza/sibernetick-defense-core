from typing import List, Dict, Set

# High-Risk Permission Combinations
# These are patterns often used by malicious or overly-intrusive extensions.
RISK_PATTERNS = [
    {
        "id": "full_surveillance",
        "permissions": {"webRequest", "webRequestBlocking", "<all_urls>"},
        "severity": "CRITICAL",
        "description": "Full traffic interception capability. Can read and modify all data on all websites."
    },
    {
        "id": "tab_injection",
        "permissions": {"tabs", "scripting", "<all_urls>"},
        "severity": "HIGH",
        "description": "Can inject custom scripts into any open tab. Potential for session hijacking."
    },
    {
        "id": "cookie_theft",
        "permissions": {"cookies", "<all_urls>"},
        "severity": "HIGH",
        "description": "Can read session cookies for all websites. High risk of account takeover."
    },
    {
        "id": "storage_leak",
        "permissions": {"storage", "identity"},
        "severity": "MEDIUM",
        "description": "Can store local data and access user identity profile. Risk of PII leakage."
    }
]

class PermissionValidator:
    """
    Rule-based engine to validate browser extension permissions.
    """
    
    def analyze(self, permissions: List[str]) -> List[Dict]:
        """
        Analyzes a list of permissions and returns identified risks.
        """
        detected_risks = []
        perm_set = set(permissions)
        
        for pattern in RISK_PATTERNS:
            # Check if all permissions in the pattern are present
            # pattern["permissions"] is a set
            if pattern["permissions"].issubset(perm_set):
                detected_risks.append({
                    "id": pattern["id"],
                    "severity": pattern["severity"],
                    "description": pattern["description"]
                })
                
        return detected_risks

permission_validator = PermissionValidator()
