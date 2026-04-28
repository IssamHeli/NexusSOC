"""JWT authentication, RBAC, and user management for NexusSOC."""
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ── CONFIG ────────────────────────────────────────────────────────────────────

JWT_SECRET   = os.getenv("JWT_SECRET", "")
JWT_ALGO     = "HS256"
ACCESS_TTL   = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
REFRESH_TTL  = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))
AUTH_ENABLED = os.getenv("AUTH_ENABLED", "false").lower() == "true"
API_KEY      = os.getenv("API_KEY", "").strip()

if AUTH_ENABLED:
    if not JWT_SECRET:
        raise ValueError("JWT_SECRET must be set when AUTH_ENABLED=true")
    if len(JWT_SECRET) < 32:
        raise ValueError("JWT_SECRET must be at least 32 characters")

# ── RBAC ──────────────────────────────────────────────────────────────────────

# viewer  → read-only dashboards
# analyst → read + analyze cases + give feedback
# admin   → full access (users, audit logs, delete skills/playbooks)
_HIERARCHY   = {"viewer": 0, "analyst": 1, "admin": 2}
_SYSTEM_USER = {"id": 0,  "username": "system", "role": "admin"}
_WORKER_USER = {"id": -1, "username": "worker",  "role": "analyst"}

# ── CRYPTO ────────────────────────────────────────────────────────────────────

pwd_context   = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer_scheme = HTTPBearer(auto_error=False)


def hash_password(plain: str) -> str:
    return pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


# ── TOKENS ────────────────────────────────────────────────────────────────────

def _encode(payload: dict, ttl: timedelta) -> str:
    now = datetime.now(timezone.utc)
    payload = {**payload, "iat": now, "exp": now + ttl, "jti": str(uuid.uuid4())}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)


def create_access_token(user_id: int, username: str, role: str) -> str:
    return _encode(
        {"sub": str(user_id), "username": username, "role": role, "type": "access"},
        timedelta(minutes=ACCESS_TTL),
    )


def create_refresh_token(user_id: int) -> str:
    return _encode({"sub": str(user_id), "type": "refresh"}, timedelta(days=REFRESH_TTL))


def _decode(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except JWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid token: {exc}")


# ── AUTH DEPENDENCY ───────────────────────────────────────────────────────────

async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> dict:
    """Return current user dict. Full bypass when AUTH_ENABLED=false (dev mode)."""
    if not AUTH_ENABLED:
        return _SYSTEM_USER

    # Machine-to-machine: X-API-Key header (worker, automation scripts)
    if API_KEY and request.headers.get("X-API-Key") == API_KEY:
        return _WORKER_USER

    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")

    payload = _decode(credentials.credentials)
    if payload.get("type") != "access":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Expected access token")

    # Check Redis revocation blocklist (logout / token rotation)
    redis = getattr(request.app.state, "redis", None)
    if redis:
        jti = payload.get("jti", "")
        if await redis.exists(f"nexussoc:revoked:{jti}"):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token revoked")

    return {
        "id":       int(payload.get("sub", 0)),
        "username": payload.get("username", ""),
        "role":     payload.get("role", "viewer"),
    }


def require_role(min_role: str):
    """Dependency factory — raises 403 if the user's role is below min_role."""
    async def _guard(user: dict = Depends(get_current_user)) -> dict:
        if _HIERARCHY.get(user["role"], -1) < _HIERARCHY.get(min_role, 99):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{user['role']}' insufficient — requires '{min_role}'",
            )
        return user
    return _guard


# ── DB HELPERS ────────────────────────────────────────────────────────────────

async def get_user_by_username(pool, username: str) -> Optional[dict]:
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id, username, password_hash, role, is_active FROM soc_users WHERE username = $1",
            username,
        )
    return dict(row) if row else None


async def seed_admin(pool) -> None:
    """Create the initial admin account from env vars if it doesn't exist yet."""
    username = os.getenv("ADMIN_USERNAME", "admin")
    password = os.getenv("ADMIN_PASSWORD", "")
    if not password:
        logger.warning("ADMIN_PASSWORD not set — skipping admin seed (set ADMIN_PASSWORD in .env)")
        return
    existing = await get_user_by_username(pool, username)
    if not existing:
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO soc_users (username, password_hash, role) VALUES ($1, $2, 'admin')",
                username,
                hash_password(password),
            )
        logger.info("Admin user '%s' created", username)
    else:
        logger.info("Admin user '%s' already exists — skipping seed", username)


# ── ROUTER ────────────────────────────────────────────────────────────────────

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=128)


class TokenResponse(BaseModel):
    access_token:  str
    refresh_token: str
    token_type:    str = "bearer"
    role:          str
    username:      str


class RefreshRequest(BaseModel):
    refresh_token: str


@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest, request: Request):
    pool = request.app.state.db_pool
    user = await get_user_by_username(pool, body.username)
    if not user or not user["is_active"] or not verify_password(body.password, user["password_hash"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    access  = create_access_token(user["id"], user["username"], user["role"])
    refresh = create_refresh_token(user["id"])
    logger.info("User '%s' logged in (role=%s)", user["username"], user["role"])
    return TokenResponse(
        access_token=access, refresh_token=refresh,
        role=user["role"], username=user["username"],
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(body: RefreshRequest, request: Request):
    pool  = request.app.state.db_pool
    redis = getattr(request.app.state, "redis", None)

    payload = _decode(body.refresh_token)
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Expected refresh token")

    if redis and await redis.exists(f"nexussoc:revoked:{payload.get('jti', '')}"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token revoked")

    user_id = int(payload["sub"])
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id, username, role, is_active FROM soc_users WHERE id = $1", user_id
        )
    if not row or not row["is_active"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")

    # Rotate: revoke the used refresh token, issue a new pair
    if redis and payload.get("jti"):
        exp = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
        ttl = max(1, int((exp - datetime.now(timezone.utc)).total_seconds()))
        await redis.setex(f"nexussoc:revoked:{payload['jti']}", ttl, "1")

    access      = create_access_token(row["id"], row["username"], row["role"])
    new_refresh = create_refresh_token(row["id"])
    return TokenResponse(
        access_token=access, refresh_token=new_refresh,
        role=row["role"], username=row["username"],
    )


@router.post("/logout")
async def logout(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
):
    redis = getattr(request.app.state, "redis", None)
    if redis and credentials:
        try:
            payload = _decode(credentials.credentials)
            jti = payload.get("jti", "")
            exp = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
            ttl = max(1, int((exp - datetime.now(timezone.utc)).total_seconds()))
            await redis.setex(f"nexussoc:revoked:{jti}", ttl, "1")
        except Exception:
            pass
    return {"message": "Logged out"}


@router.get("/me")
async def get_me(user: dict = Depends(get_current_user)):
    return user


# ── USER MANAGEMENT ROUTER ────────────────────────────────────────────────────

user_router = APIRouter(prefix="/admin/users", tags=["users"])

VALID_ROLES = {"viewer", "analyst", "admin"}


class CreateUserRequest(BaseModel):
    username: str = Field(..., min_length=2, max_length=64, pattern=r"^[a-zA-Z0-9_\-]+$")
    password: str = Field(..., min_length=8, max_length=128)
    role:     str = Field("analyst", pattern=r"^(viewer|analyst|admin)$")


class UpdateRoleRequest(BaseModel):
    role: str = Field(..., pattern=r"^(viewer|analyst|admin)$")


class ChangePasswordRequest(BaseModel):
    password: str = Field(..., min_length=8, max_length=128)


class UserResponse(BaseModel):
    id:         int
    username:   str
    role:       str
    is_active:  bool
    created_at: str


@user_router.get("", summary="List all users (admin only)")
async def list_users(
    request: Request,
    _admin: dict = Depends(require_role("admin")),
):
    async with request.app.state.db_pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT id, username, role, is_active, created_at FROM soc_users ORDER BY id"
        )
    return {
        "total": len(rows),
        "users": [
            {
                "id":         r["id"],
                "username":   r["username"],
                "role":       r["role"],
                "is_active":  r["is_active"],
                "created_at": r["created_at"].isoformat(),
            }
            for r in rows
        ],
    }


@user_router.post("", status_code=201, summary="Create a new user (admin only)")
async def create_user(
    body: CreateUserRequest,
    request: Request,
    _admin: dict = Depends(require_role("admin")),
):
    pool = request.app.state.db_pool
    existing = await get_user_by_username(pool, body.username)
    if existing:
        raise HTTPException(status_code=409, detail=f"Username '{body.username}' already exists")
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "INSERT INTO soc_users (username, password_hash, role) VALUES ($1, $2, $3) RETURNING id, username, role, is_active, created_at",
            body.username,
            hash_password(body.password),
            body.role,
        )
    logger.info("Admin created user '%s' (role=%s)", body.username, body.role)
    return {"created": {"id": row["id"], "username": row["username"], "role": row["role"]}}


@user_router.patch("/{username}/role", summary="Change a user's role (admin only)")
async def update_role(
    username: str,
    body: UpdateRoleRequest,
    request: Request,
    admin: dict = Depends(require_role("admin")),
):
    if username == admin["username"] and body.role != "admin":
        raise HTTPException(status_code=400, detail="Cannot demote your own account")
    pool = request.app.state.db_pool
    async with pool.acquire() as conn:
        result = await conn.execute(
            "UPDATE soc_users SET role=$1, updated_at=NOW() WHERE username=$2 AND is_active=TRUE",
            body.role, username,
        )
    if result == "UPDATE 0":
        raise HTTPException(status_code=404, detail=f"User '{username}' not found")
    logger.info("Admin '%s' changed role of '%s' to '%s'", admin["username"], username, body.role)
    return {"username": username, "role": body.role}


@user_router.patch("/{username}/password", summary="Reset a user's password (admin only)")
async def reset_password(
    username: str,
    body: ChangePasswordRequest,
    request: Request,
    _admin: dict = Depends(require_role("admin")),
):
    pool = request.app.state.db_pool
    async with pool.acquire() as conn:
        result = await conn.execute(
            "UPDATE soc_users SET password_hash=$1, updated_at=NOW() WHERE username=$2 AND is_active=TRUE",
            hash_password(body.password), username,
        )
    if result == "UPDATE 0":
        raise HTTPException(status_code=404, detail=f"User '{username}' not found")
    logger.info("Password reset for user '%s'", username)
    return {"username": username, "message": "Password updated"}


@user_router.delete("/{username}", summary="Deactivate a user (admin only)")
async def delete_user(
    username: str,
    request: Request,
    admin: dict = Depends(require_role("admin")),
):
    if username == admin["username"]:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    pool = request.app.state.db_pool
    # Ensure at least one active admin remains
    async with pool.acquire() as conn:
        target = await conn.fetchrow(
            "SELECT role FROM soc_users WHERE username=$1 AND is_active=TRUE", username
        )
        if not target:
            raise HTTPException(status_code=404, detail=f"User '{username}' not found")
        if target["role"] == "admin":
            count = await conn.fetchval(
                "SELECT COUNT(*) FROM soc_users WHERE role='admin' AND is_active=TRUE"
            )
            if count <= 1:
                raise HTTPException(status_code=400, detail="Cannot delete the last admin account")
        await conn.execute(
            "UPDATE soc_users SET is_active=FALSE, updated_at=NOW() WHERE username=$1", username
        )
    logger.info("Admin '%s' deactivated user '%s'", admin["username"], username)
    return {"username": username, "message": "User deactivated"}
