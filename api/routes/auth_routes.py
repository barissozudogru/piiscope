"""Authentication and user management routes.

These endpoints handle login and CRUD operations on user accounts.  A
token‑based (JWT) authentication scheme is used.  Only Super Admins
may create or delete users.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from .. import auth, models, schemas, utils
from ..audit import log_audit_event
from ..database import get_db

router = APIRouter()


@router.post("/login", response_model=schemas.Token)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)
) -> schemas.Token:  # noqa: E501
    """Authenticate a user and return a JWT access token.

    The client should supply ``username`` and ``password`` as form fields.
    If authentication fails, a 401 error is returned.
    """
    token = await auth.login_for_access_token(form_data, db)
    # Log login event (username may not yet be in DB if login fails)
    user = db.query(models.User).filter(models.User.username == form_data.username).first()
    if user:
        log_audit_event(
            db, user.id, action="login", target=None, details={"username": form_data.username}
        )  # noqa: E501
    return token


@router.get("/me", response_model=schemas.UserOut)
async def read_current_user(
    current_user: models.User = Depends(auth.get_current_user),
) -> schemas.UserOut:  # noqa: E501
    """Retrieve the profile of the currently authenticated user."""
    return schemas.UserOut.model_validate(current_user)


@router.post("/users", response_model=schemas.UserOut, status_code=status.HTTP_201_CREATED)
async def create_user(
    user_in: schemas.UserCreate,
    db: Session = Depends(get_db),
    _: models.User = Depends(auth.role_required(models.RoleEnum.SUPER_ADMIN)),
) -> schemas.UserOut:
    """Create a new user account.

    Only Super Admins may call this endpoint.  The password will be
    hashed before storage.  Attempting to create a user with an
    existing username returns a 400 error.
    """
    existing = db.query(models.User).filter(models.User.username == user_in.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")
    password_hash = utils.get_password_hash(user_in.password)
    user = models.User(username=user_in.username, password_hash=password_hash, role=user_in.role)
    db.add(user)
    db.commit()
    db.refresh(user)
    # Audit log
    log_audit_event(
        db,
        _.id if _ else None,
        action="create_user",
        target=f"user:{user.id}",
        details={"created_username": user.username},
    )  # noqa: E501
    return schemas.UserOut.model_validate(user)


@router.get("/users", response_model=list[schemas.UserOut])
async def list_users(
    db: Session = Depends(get_db),
    _: models.User = Depends(auth.role_required(models.RoleEnum.SUPER_ADMIN)),
) -> list[schemas.UserOut]:
    """List all user accounts (Super Admin only)."""
    users = db.query(models.User).all()
    return [schemas.UserOut.model_validate(u) for u in users]
