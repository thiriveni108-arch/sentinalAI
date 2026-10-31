"""Fail-closed HTTP boundary for temporary public demonstrations."""

from __future__ import annotations

import hmac
import os

from fastapi import Request
from fastapi.responses import JSONResponse


DEMO_MODE_ENV = "SENTINEL_PUBLIC_DEMO_MODE"
DEMO_SECRET_ENV = "SENTINEL_DEMO_API_SECRET"
_MIN_SECRET_LENGTH = 32
_GOVERNANCE_MUTATIONS = (
    "/api/shield/learning/policies/rollback",
)


def public_demo_enabled() -> bool:
    return os.environ.get(DEMO_MODE_ENV, "false").strip().lower() in {"1", "true", "yes", "on"}


def validated_demo_secret() -> str | None:
    if not public_demo_enabled():
        return None
    secret = os.environ.get(DEMO_SECRET_ENV, "")
    if len(secret) < _MIN_SECRET_LENGTH:
        raise RuntimeError(
            f"{DEMO_SECRET_ENV} must contain at least {_MIN_SECRET_LENGTH} characters when {DEMO_MODE_ENV} is enabled."
        )
    return secret


def _is_governance_mutation(path: str) -> bool:
    return path in _GOVERNANCE_MUTATIONS or (
        path.startswith("/api/shield/learning/policies/")
        and (path.endswith("/approve") or path.endswith("/activate"))
    )


def _error(status_code: int, code: str, message: str) -> JSONResponse:
    response = JSONResponse(status_code=status_code, content={"error": {"code": code, "message": message}})
    response.headers["cache-control"] = "no-store"
    if status_code == 401:
        response.headers["www-authenticate"] = "Bearer"
    return response


async def enforce_public_demo_boundary(request: Request, call_next, secret: str | None):
    """Authenticate all API calls and disable public mutations in demo mode."""
    if secret is None or not request.url.path.startswith("/api/"):
        return await call_next(request)

    authorization = request.headers.get("authorization", "")
    scheme, separator, credential = authorization.partition(" ")
    if separator != " " or scheme.lower() != "bearer" or not credential or not hmac.compare_digest(credential, secret):
        return _error(401, "demo_authentication_required", "Valid demo API credentials are required.")

    if request.method.upper() not in {"GET", "HEAD", "OPTIONS"} and not _is_governance_mutation(request.url.path):
        return _error(403, "public_demo_mutation_disabled", "State-changing operations are disabled in public demo mode.")

    response = await call_next(request)
    response.headers["cache-control"] = "no-store"
    return response
