import logging

import redis
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.redis_client import consume_refresh_token, revoke_refresh_token, store_refresh_token
from app.core.rate_limit import enforce_login_rate_limit, enforce_refresh_rate_limit
from app.core.security import create_access_token, hash_password, verify_password
from app.db.models import Tenant, TenantType, User
from app.db.session import get_db
from app.schemas import CredentialChange, Token
from app.api.deps import get_current_user

router = APIRouter(prefix="/auth", tags=["auth"])
logger = logging.getLogger("finsecai.auth")


class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    refresh_token: str


def _active_user(db: Session, email: str) -> User:
    user = db.query(User).filter(User.email == email.strip().lower()).first()
    if not user or user.status != "ACTIVE":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Incorrect email or password")
    if user.tenant_id and (user.role or "").strip().lower() != "owner":
        tenant = db.query(Tenant).filter(Tenant.id == user.tenant_id).first()
        if tenant is None or tenant.status != "ACTIVE":
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Incorrect email or password")
    return user


def _check_context(user: User, context: str, db: Session) -> None:
    role = (user.role or "").strip().lower()
    if context == "owner" and role != "owner":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Incorrect email or password")
    if context == "tenant" and (role == "owner" or not user.tenant_id):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Incorrect email or password")
    if context == "demo":
        tenant = db.query(Tenant).filter(Tenant.id == user.tenant_id).first()
        if user.email != "demo@finsecai.com" or tenant is None or tenant.tenant_type != TenantType.DEMO.value:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Incorrect email or password")


def _token(user: User) -> Token:
    return Token(
        access_token=create_access_token(user.email, user.role, user.tenant_id),
        email=user.email,
        role=user.role,
        tenant_id=user.tenant_id,
        must_change_password=user.must_change_password,
        refresh_token=_issue_refresh_token_or_none(user.email),
    )


def _issue_refresh_token_or_none(email: str) -> str | None:
    """Login remains usable during a brief Redis outage, but without renewal."""
    try:
        return store_refresh_token(email)
    except redis.RedisError:
        logger.warning("Redis unavailable during login; issuing access-token-only session")
        return None


def _login(request: Request, form: OAuth2PasswordRequestForm, db: Session, context: str | None = None):
    enforce_login_rate_limit(request, form.username)
    user = _active_user(db, form.username)
    if context:
        _check_context(user, context, db)

    try:
        password_ok = verify_password(form.password, user.hashed_password)
    except Exception:
        logger.warning("Password hash verification failed for account %s", user.email)
        password_ok = False
    if not password_ok:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Incorrect email or password")

    return _token(user)


@router.post("/login", response_model=Token)
def login(request: Request, form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    return _login(request, form, db)


@router.post("/owner/login", response_model=Token)
def owner_login(request: Request, form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    return _login(request, form, db, "owner")


@router.post("/tenant/login", response_model=Token)
def tenant_login(request: Request, form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    return _login(request, form, db, "tenant")


@router.post("/demo/login", response_model=Token)
def demo_login(request: Request, form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    return _login(request, form, db, "demo")


@router.post("/credentials", response_model=Token)
def change_credentials(
    payload: CredentialChange,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if not verify_password(payload.current_password, user.hashed_password):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Incorrect email or password")
    new_email = (payload.new_email or user.email).strip().lower()
    if new_email != user.email and db.query(User.id).filter(User.email == new_email).first():
        raise HTTPException(status.HTTP_409_CONFLICT, "An account with this email already exists")
    user.email = new_email
    user.hashed_password = hash_password(payload.new_password)
    user.must_change_password = False
    db.commit()
    db.refresh(user)
    return _token(user)


@router.post("/refresh", response_model=Token)
def refresh(request: Request, payload: RefreshRequest, db: Session = Depends(get_db)):
    enforce_refresh_rate_limit(request)
    try:
        email = consume_refresh_token(payload.refresh_token)
    except redis.RedisError as exc:
        raise HTTPException(503, "Token refresh is temporarily unavailable. Please log in again.") from exc
    if email is None:
        raise HTTPException(401, "Invalid, expired, or already-used refresh token")

    # Refresh tokens hold only an opaque identity. Revalidate that identity
    # against the live database before granting another access token.
    user = db.query(User).filter(User.email == email).first()
    if user is None or user.status != "ACTIVE":
        raise HTTPException(401, "User no longer exists")
    if user.tenant_id and (user.role or "").strip().lower() != "owner":
        tenant = db.query(Tenant).filter(Tenant.id == user.tenant_id).first()
        if tenant is None or tenant.status != "ACTIVE":
            raise HTTPException(401, "Tenant is not active")
    try:
        refresh_token = store_refresh_token(user.email)
    except redis.RedisError as exc:
        raise HTTPException(503, "Token refresh is temporarily unavailable. Please log in again.") from exc

    return Token(
        access_token=create_access_token(user.email, user.role, user.tenant_id),
        email=user.email,
        role=user.role,
        tenant_id=user.tenant_id,
        must_change_password=user.must_change_password,
        refresh_token=refresh_token,
    )


@router.post("/logout")
def logout(payload: LogoutRequest):
    try:
        revoke_refresh_token(payload.refresh_token)
    except redis.RedisError:
        logger.warning("Redis unavailable during logout; refresh token will expire at its TTL")
    return {"status": "logged_out"}
