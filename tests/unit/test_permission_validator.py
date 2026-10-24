from app.modules.supply_chain.permission_validator import permission_validator

def test_permission_validator_critical_risk():
    """Test that critical permission combinations are flagged."""
    permissions = ["webRequest", "webRequestBlocking", "<all_urls>", "tabs"]
    risks = permission_validator.analyze(permissions)
    
    # Check for Critical surveillance risk
    critical_risks = [r for r in risks if r["severity"] == "CRITICAL"]
    assert len(critical_risks) >= 1
    assert any("Full traffic interception" in r["description"] for r in critical_risks)

def test_permission_validator_low_risk():
    """Test that benign permissions result in no risks."""
    permissions = ["storage", "alarms"]
    risks = permission_validator.analyze(permissions)
    assert len(risks) == 0
