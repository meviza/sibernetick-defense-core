"""
Tests for KEYMAKER Rate Limiter — app.core.rate_limiter
"""
import pytest
import time

from app.core.rate_limiter import (
    RateLimitConfig,
    RateLimiter,
    _Bucket,
)


# ---------------------------------------------------------------------------
# RateLimitConfig
# ---------------------------------------------------------------------------
class TestRateLimitConfig:
    def test_max_tokens(self):
        c = RateLimitConfig(requests_per_minute=60, burst=10)
        assert c.max_tokens == 70

    def test_refill_rate(self):
        c = RateLimitConfig(requests_per_minute=60)
        assert c.refill_rate == 1.0  # 60/60

    def test_zero_burst(self):
        c = RateLimitConfig(requests_per_minute=100)
        assert c.burst == 0
        assert c.max_tokens == 100


# ---------------------------------------------------------------------------
# Token bucket
# ---------------------------------------------------------------------------
class TestBucket:
    def test_consume_success(self):
        b = _Bucket(tokens=5.0, max_tokens=10, refill_rate=1.0)
        allowed, reset, remaining = b.consume()
        assert allowed is True
        assert remaining >= 3  # consumed 1 from 5

    def test_consume_exhausted(self):
        b = _Bucket(tokens=0.0, max_tokens=10, refill_rate=1.0)
        now = time.monotonic()
        allowed, _, remaining = b.consume(now=now)
        assert allowed is False
        assert remaining == 0

    def test_refill_over_time(self):
        now = 1000.0
        b = _Bucket(tokens=0.0, max_tokens=10, refill_rate=1.0, last_refill=now)
        # Simulate 5 seconds later → 5 tokens refilled
        allowed, _, remaining = b.consume(now=now + 5)
        assert allowed is True
        assert remaining >= 3  # 5 refilled - 1 consumed = 4, int(4.x) >= 3

    def test_max_cap(self):
        now = 1000.0
        b = _Bucket(tokens=9.0, max_tokens=10, refill_rate=1.0, last_refill=now)
        # 100 seconds later — should cap at 10
        b.consume(now=now + 100)
        # tokens = min(10, 9 + 100*1.0) - 1 = 9
        assert b.tokens <= 10


# ---------------------------------------------------------------------------
# RateLimiter engine
# ---------------------------------------------------------------------------
class TestRateLimiter:
    def test_basic_allow(self):
        rl = RateLimiter()
        allowed, headers = rl.check("tenant-1", "api")
        assert allowed is True
        assert "X-RateLimit-Limit" in headers
        assert "X-RateLimit-Remaining" in headers
        assert "X-RateLimit-Reset" in headers

    def test_exhaust_and_deny(self):
        config = RateLimitConfig(requests_per_minute=3, burst=0)
        rl = RateLimiter(limits={"test": config})
        now = time.monotonic()
        results = []
        for i in range(5):
            allowed, _ = rl.check("t1", "test", now=now)
            results.append(allowed)
        # First 3 should be allowed, rest denied
        assert results[:3] == [True, True, True]
        assert not all(results[3:])

    def test_per_tenant_isolation(self):
        config = RateLimitConfig(requests_per_minute=2, burst=0)
        rl = RateLimiter(limits={"api": config})
        now = time.monotonic()
        # Exhaust tenant A
        rl.check("A", "api", now=now)
        rl.check("A", "api", now=now)
        allowed_a, _ = rl.check("A", "api", now=now)
        assert allowed_a is False
        # Tenant B still has quota
        allowed_b, _ = rl.check("B", "api", now=now)
        assert allowed_b is True

    def test_burst_allowance(self):
        config = RateLimitConfig(requests_per_minute=2, burst=3)
        rl = RateLimiter(limits={"api": config})
        now = time.monotonic()
        # Should allow up to 5 (2 + 3 burst)
        results = [rl.check("t1", "api", now=now)[0] for _ in range(6)]
        assert sum(results) == 5

    def test_refill_after_wait(self):
        config = RateLimitConfig(requests_per_minute=60, burst=0)  # 1/sec
        rl = RateLimiter(limits={"api": config})
        now = 1000.0
        # Exhaust all 60 tokens
        for _ in range(60):
            rl.check("t1", "api", now=now)
        allowed, _ = rl.check("t1", "api", now=now)
        assert allowed is False
        # Wait 5 seconds → 5 tokens
        allowed, _ = rl.check("t1", "api", now=now + 5)
        assert allowed is True

    def test_headers_format(self):
        rl = RateLimiter()
        _, headers = rl.check("t1", "api")
        assert headers["X-RateLimit-Limit"].isdigit()
        # Remaining should be numeric
        int(headers["X-RateLimit-Remaining"])
        float(headers["X-RateLimit-Reset"])

    def test_reset_all(self):
        rl = RateLimiter()
        rl.check("t1", "api")
        rl.check("t2", "api")
        rl.reset()
        assert len(rl._buckets) == 0

    def test_reset_single_tenant(self):
        rl = RateLimiter()
        rl.check("t1", "api")
        rl.check("t2", "api")
        rl.reset(tenant_id="t1")
        keys = [k[0] for k in rl._buckets]
        assert "t1" not in keys
        assert "t2" in keys


# ---------------------------------------------------------------------------
# Path classification
# ---------------------------------------------------------------------------
class TestPathClassification:
    def test_auth_path(self):
        assert RateLimiter.classify_path("/api/v1/auth/login") == "auth"

    def test_reports_path(self):
        assert RateLimiter.classify_path("/api/v1/reports/weekly") == "reports"

    def test_generic_api(self):
        assert RateLimiter.classify_path("/api/v1/threats") == "api"

    def test_auth_suffix(self):
        assert RateLimiter.classify_path("/api/v1/auth") == "auth"


# ---------------------------------------------------------------------------
# Custom limits via set_limit
# ---------------------------------------------------------------------------
class TestCustomLimits:
    def test_set_and_use_custom(self):
        rl = RateLimiter()
        rl.set_limit("special", RateLimitConfig(requests_per_minute=1, burst=0))
        now = time.monotonic()
        a1, _ = rl.check("t1", "special", now=now)
        a2, _ = rl.check("t1", "special", now=now)
        assert a1 is True
        assert a2 is False
