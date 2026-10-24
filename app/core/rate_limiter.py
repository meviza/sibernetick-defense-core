"""
KEYMAKER — Per-Tenant Rate Limiter
====================================
Token-bucket algorithm with configurable limits per endpoint group,
burst allowance, and standard rate-limit response headers.
"""
from __future__ import annotations

import time
import logging
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

logger = logging.getLogger("keymaker.rate_limiter")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
@dataclass
class RateLimitConfig:
    """Defines rate-limit parameters for an endpoint group."""
    requests_per_minute: int
    burst: int = 0  # extra tokens above the steady-state bucket

    @property
    def max_tokens(self) -> int:
        return self.requests_per_minute + self.burst

    @property
    def refill_rate(self) -> float:
        """Tokens added per second."""
        return self.requests_per_minute / 60.0


# Default endpoint-group configs
DEFAULT_LIMITS: Dict[str, RateLimitConfig] = {
    "auth": RateLimitConfig(requests_per_minute=10, burst=5),
    "api": RateLimitConfig(requests_per_minute=100, burst=20),
    "reports": RateLimitConfig(requests_per_minute=20, burst=5),
}


# ---------------------------------------------------------------------------
# Token bucket
# ---------------------------------------------------------------------------
@dataclass
class _Bucket:
    tokens: float
    max_tokens: int
    refill_rate: float
    last_refill: float = field(default_factory=time.monotonic)

    def consume(self, now: Optional[float] = None) -> Tuple[bool, float, int]:
        """
        Try to consume one token.

        Returns (allowed, reset_seconds, remaining_tokens).
        """
        now = now or time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.max_tokens, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now

        remaining = int(self.tokens)
        reset_seconds = (self.max_tokens - self.tokens) / self.refill_rate if self.refill_rate > 0 else 0

        if self.tokens >= 1:
            self.tokens -= 1
            return True, round(reset_seconds, 1), max(int(self.tokens), 0)
        return False, round(reset_seconds, 1), 0


# ---------------------------------------------------------------------------
# RateLimiter engine
# ---------------------------------------------------------------------------
class RateLimiter:
    """
    Per-tenant, per-group token-bucket rate limiter.

    Buckets are keyed by ``(tenant_id, group)``.
    """

    def __init__(self, limits: Optional[Dict[str, RateLimitConfig]] = None) -> None:
        self._limits = limits or dict(DEFAULT_LIMITS)
        self._buckets: Dict[Tuple[str, str], _Bucket] = {}

    # -- configuration helpers ------------------------------------------------
    def set_limit(self, group: str, config: RateLimitConfig) -> None:
        self._limits[group] = config

    def get_config(self, group: str) -> RateLimitConfig:
        return self._limits.get(group, self._limits.get("api", RateLimitConfig(100, 20)))

    # -- classification -------------------------------------------------------
    @staticmethod
    def classify_path(path: str) -> str:
        """Map a URL path to an endpoint group name."""
        if "/auth/" in path or path.endswith("/auth"):
            return "auth"
        if "/reports" in path:
            return "reports"
        return "api"

    # -- core check -----------------------------------------------------------
    def check(
        self,
        tenant_id: str,
        group: str,
        *,
        now: Optional[float] = None,
    ) -> Tuple[bool, Dict[str, str]]:
        """
        Check (and consume) a rate-limit token.

        Returns ``(allowed, headers_dict)``.
        """
        config = self.get_config(group)
        key = (tenant_id, group)

        effective_now = now or time.monotonic()
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = _Bucket(
                tokens=float(config.max_tokens),
                max_tokens=config.max_tokens,
                refill_rate=config.refill_rate,
                last_refill=effective_now,
            )
            self._buckets[key] = bucket

        allowed, reset_secs, remaining = bucket.consume(now=now)

        headers = {
            "X-RateLimit-Limit": str(config.requests_per_minute),
            "X-RateLimit-Remaining": str(remaining),
            "X-RateLimit-Reset": str(reset_secs),
        }
        return allowed, headers

    def reset(self, tenant_id: Optional[str] = None) -> None:
        """Clear buckets, optionally for a single tenant."""
        if tenant_id is None:
            self._buckets.clear()
        else:
            self._buckets = {
                k: v for k, v in self._buckets.items() if k[0] != tenant_id
            }


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
rate_limiter = RateLimiter()


# ---------------------------------------------------------------------------
# FastAPI / Starlette middleware
# ---------------------------------------------------------------------------
class RateLimitMiddleware(BaseHTTPMiddleware):
    """Applies per-tenant rate limiting to every request."""

    def __init__(self, app, *, limiter_instance: Optional[RateLimiter] = None) -> None:
        super().__init__(app)
        self._limiter = limiter_instance or rate_limiter

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Determine tenant from request state, header, or fall back to IP
        tenant_id = "anonymous"
        if hasattr(request.state, "user"):
            tenant_id = request.state.user.get("tenant_id", tenant_id)
        if tenant_id == "anonymous":
            tenant_id = request.headers.get("X-Tenant-ID", tenant_id)
        if tenant_id == "anonymous" and request.client:
            tenant_id = f"ip:{request.client.host}"

        group = self._limiter.classify_path(request.url.path)
        allowed, headers = self._limiter.check(tenant_id, group)

        if not allowed:
            logger.warning("Rate limit exceeded: tenant=%s group=%s", tenant_id, group)
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Try again later."},
                headers=headers,
            )

        response = await call_next(request)
        for k, v in headers.items():
            response.headers[k] = v
        return response
