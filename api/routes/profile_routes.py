"""Profile management endpoints.

Profiles define sensitivity rules, dictionaries and weights used by the
detection engine.  Administrators can create, update and delete
profiles.  Normal users may read profiles but cannot modify them.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from .. import auth, models, schemas
from ..audit import log_audit_event
from ..database import get_db

router = APIRouter()


@router.get("/", response_model=list[schemas.ProfileOut])
async def list_profiles(
    db: Session = Depends(get_db),
    _: models.User = Depends(
        auth.role_required(models.RoleEnum.USER, models.RoleEnum.ADMIN, models.RoleEnum.SUPER_ADMIN)
    ),  # noqa: E501
) -> list[schemas.ProfileOut]:
    """Return all profiles sorted by name."""
    profiles = db.query(models.Profile).order_by(models.Profile.name).all()
    return [schemas.ProfileOut.model_validate(p) for p in profiles]


@router.post("/", response_model=schemas.ProfileOut, status_code=status.HTTP_201_CREATED)
async def create_profile(
    profile_in: schemas.ProfileCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(
        auth.role_required(models.RoleEnum.ADMIN, models.RoleEnum.SUPER_ADMIN)
    ),  # noqa: E501
) -> schemas.ProfileOut:
    """Create a new sensitivity profile.

    Only Admins and Super Admins may create profiles.  Profile names must
    be unique; attempts to reuse a name will raise a 400 error.
    """
    if db.query(models.Profile).filter(models.Profile.name == profile_in.name).first():
        raise HTTPException(status_code=400, detail="Profile with this name already exists")
    profile = models.Profile(
        name=profile_in.name,
        version=profile_in.version,
        description=profile_in.description,
        definition=profile_in.definition,
        created_by_id=current_user.id,
    )
    db.add(profile)
    db.commit()
    db.refresh(profile)
    log_audit_event(
        db,
        current_user.id,
        action="create_profile",
        target=f"profile:{profile.id}",
        details={"name": profile.name},
    )  # noqa: E501
    return schemas.ProfileOut.model_validate(profile)


@router.get("/{profile_id}", response_model=schemas.ProfileOut)
async def get_profile(
    profile_id: int,
    db: Session = Depends(get_db),
    _: models.User = Depends(
        auth.role_required(models.RoleEnum.USER, models.RoleEnum.ADMIN, models.RoleEnum.SUPER_ADMIN)
    ),  # noqa: E501
) -> schemas.ProfileOut:
    """Retrieve a profile by ID."""
    profile = db.query(models.Profile).get(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    return schemas.ProfileOut.model_validate(profile)


@router.put("/{profile_id}", response_model=schemas.ProfileOut)
async def update_profile(
    profile_id: int,
    profile_in: schemas.ProfileCreate,
    db: Session = Depends(get_db),
    _: models.User = Depends(
        auth.role_required(models.RoleEnum.ADMIN, models.RoleEnum.SUPER_ADMIN)
    ),  # noqa: E501
) -> schemas.ProfileOut:
    """Update an existing profile (admin/superadmin only)."""
    profile = db.query(models.Profile).get(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    # Check for name collision if changed
    if (
        profile_in.name != profile.name
        and db.query(models.Profile).filter(models.Profile.name == profile_in.name).first()
    ):  # noqa: E501
        raise HTTPException(status_code=400, detail="Profile with this name already exists")
    profile.name = profile_in.name
    profile.version = profile_in.version
    profile.description = profile_in.description
    profile.definition = profile_in.definition
    db.commit()
    db.refresh(profile)
    log_audit_event(
        db,
        _.id,
        action="update_profile",
        target=f"profile:{profile.id}",
        details={"name": profile.name},
    )  # noqa: E501
    return schemas.ProfileOut.model_validate(profile)


@router.delete("/{profile_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def delete_profile(
    profile_id: int,
    db: Session = Depends(get_db),
    _: models.User = Depends(auth.role_required(models.RoleEnum.SUPER_ADMIN)),
):
    """Delete a profile (super admin only)."""
    profile = db.query(models.Profile).get(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    db.delete(profile)
    db.commit()
    log_audit_event(
        db,
        _.id,
        action="delete_profile",
        target=f"profile:{profile.id}",
        details={"name": profile.name},
    )  # noqa: E501
    return None
