"""Security middleware stack for NexusSOC: headers, rate-limiting, audit logging, sanitization."""
import asyncio
import ipaddress
import logging
import os
import re
import time
from urllib.parse import urlparse

from fastapi import Request
from fastapi.responses import JSONResponse
from jose import JWTError, jwt
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)

_JWT_SECRET = os.getenv("JWT_SECRET", "")
_JWT_ALGO   = "HS256"

# ── SECURITY HEADERS ─────────────────────────────────────────────────────────

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add OWASP-recommended security headers to every response."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        h = response.headers
        h["X-Content-Type-Options"]  = "nosniff"
        h["X-Frame-Options"]         = "DENY"
        h["X-XSS-Protection"]        = "1; mode=block"
        h["Referrer-Policy"]         = "strict-origin-when-cross-origin"
        h["Permissions-Policy"]      = "camera=(), microphone=(), geolocation=()"
        h["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline';"
        )
        if os.getenv("HTTPS_ONLY", "false").lower() == "true":
            h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response


# ── REQUEST SIZE LIMIT ────────────────────────────────────────────────────────

class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject requests whose Content-Length exceeds 1 MB."""

    _MAX = 1 * 1024 * 1024  # 1 MB

    async def dispatch(self, request: Request, call_next):
        cl = request.headers.get("content-length")
        if cl and int(cl) > self._MAX:
            return JSONResponse(
                status_code=413,
                content={"detail": "Request body exceeds 1 MB limit"},
            )
        return await call_next(request)


# ── RATE LIMITING (Redis-backed, per-path + per-IP) ───────────────────────────

# path_prefix → (max_requests, window_seconds)
_RATE_LIMITS: dict[str, tuple[int, int]] = {
    "/auth/login":   (5,   60),   # brute-force guard
    "/analyze-case": (30,  60),
    "/ingest":       (100, 60),
    "/feedback":     (60,  60),
}
_RATE_DEFAULT = (200, 60)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Sliding-window rate limiter backed by Redis. Degrades gracefully when Redis is absent."""

    async def dispatch(self, request: Request, call_next):
        redis = getattr(request.app.state, "redis", None)
        if not redis:
            return await call_next(request)

        path = request.url.path
        max_req, window = _RATE_DEFAULT
        for prefix, cfg in _RATE_LIMITS.items():
            if path.startswith(prefix):
                max_req, window = cfg
                break

        ip    = request.client.host if request.client else "unknown"
        key   = f"nexussoc:rl:{path}:{ip}"
        count = await redis.incr(key)
        if count == 1:
            await redis.expire(key, window)

        if count > max_req:
            return JSONResponse(
                status_code=429,
                content={"detail": f"Too many requests — limit {max_req}/{window}s"},
                headers={"Retry-After": str(window)},
            )

        return await call_next(request)


# ── AUDIT LOGGING ─────────────────────────────────────────────────────────────

_AUDIT_SKIP = frozenset({
    "/health", "/metrics", "/", "/docs",
    "/openapi.json", "/redoc", "/favicon.ico",
})


async def _write_audit(
    pool, user_id, username, method, endpoint,
    status_code, duration_ms, client_ip, user_agent,
):
    try:
        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO audit_logs
                    (user_id, username, method, endpoint,
                     status_code, duration_ms, client_ip, user_agent)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                """,
                user_id, username, method, endpoint,
                status_code, duration_ms, client_ip, user_agent,
            )
    except Exception as exc:
        logger.warning("Audit log write failed: %s", exc)


class AuditLogMiddleware(BaseHTTPMiddleware):
    """Log every meaningful API call to the audit_logs table (fire-and-forget)."""

    async def dispatch(self, request: Request, call_next):
        start    = time.perf_counter()
        response = await call_next(request)
        duration_ms = int((time.perf_counter() - start) * 1000)

        if request.url.path in _AUDIT_SKIP:
            return response

        # Best-effort JWT extraction — never blocks the response
        user_id, username = None, None
        auth = request.headers.get("authorization", "")
        if auth.startswith("Bearer ") and _JWT_SECRET:
            try:
                p        = jwt.decode(auth[7:], _JWT_SECRET, algorithms=[_JWT_ALGO])
                user_id  = int(p.get("sub", 0)) or None
                username = p.get("username")
            except (JWTError, Exception):
                pass

        pool = getattr(request.app.state, "db_pool", None)
        if pool:
            asyncio.create_task(_write_audit(
                pool,
                user_id,
                username,
                request.method,
                str(request.url.path),
                response.status_code,
                duration_ms,
                request.client.host if request.client else None,
                request.headers.get("user-agent", "")[:512],
            ))

        return response


# ── INPUT SANITIZATION ────────────────────────────────────────────────────────

_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


def sanitize_str(value: str) -> str:
    """Strip null bytes and ASCII control characters from a string."""
    return _CTRL.sub("", value) if value else value


def is_safe_webhook_url(url: str) -> bool:
    """Return False for localhost, RFC1918, or non-http(s) URLs — SSRF guard."""
    if not url:
        return False
    try:
        p = urlparse(url)
        if p.scheme not in ("http", "https"):
            return False
        host = p.hostname or ""
        if not host or host.lower() in ("localhost", "127.0.0.1", "::1"):
            return False
        try:
            addr = ipaddress.ip_address(host)
            return not any(addr in net for net in _PRIVATE_NETS)
        except ValueError:
            return True  # domain name — allow
    except Exception:
        return False
