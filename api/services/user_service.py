"""User management service.

This module handles user-related business logic including authentication,
authorization, and user profile management.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from .. import models, schemas, utils
from ..exceptions import AuthenticationError, AuthorizationError, DatabaseError, ValidationError
from ..logging_config import log_audit_event, log_security_event
from ..validators import validate_email, validate_password, validate_username


class UserService:
    """Service for managing users and authentication."""

    def __init__(self, db: Session):
        self.db = db

    def create_user(
        self, user_data: schemas.UserCreate, created_by: models.User | None = None
    ) -> models.User:  # noqa: E501
        """Create a new user."""
        try:
            # Validate input data
            validated_username = validate_username(user_data.username)
            validated_password = validate_password(user_data.password)
            validated_email = None

            if user_data.email:
                validated_email = validate_email(user_data.email)

            # Check if username already exists
            existing_user = (
                self.db.query(models.User)
                .filter(models.User.username == validated_username)
                .first()
            )

            if existing_user:
                raise ValidationError(f"Username '{validated_username}' already exists")

            # Check if email already exists
            if validated_email:
                existing_email = (
                    self.db.query(models.User).filter(models.User.email == validated_email).first()
                )

                if existing_email:
                    raise ValidationError(f"Email '{validated_email}' already exists")

            # Create user
            user = models.User(
                username=validated_username,
                email=validated_email,
                password_hash=utils.get_password_hash(validated_password),
                role=user_data.role or models.RoleEnum.USER,
            )

            self.db.add(user)
            self.db.commit()
            self.db.refresh(user)

            # Log audit event
            log_audit_event(
                action="user_created",
                user_id=created_by.id if created_by else None,
                target=f"user:{user.id}",
                details={
                    "new_username": user.username,
                    "new_role": user.role.value,
                    "has_email": bool(user.email),
                },
            )

            return user

        except SQLAlchemyError as e:
            self.db.rollback()
            raise DatabaseError(f"Failed to create user: {str(e)}") from e

    def authenticate_user(self, username: str, password: str, client_ip: str = None) -> models.User:
        """Authenticate a user by username and password."""
        try:
            user = self.db.query(models.User).filter(models.User.username == username).first()

            if not user or not utils.verify_password(password, user.password_hash):
                log_security_event("authentication_failed", ip_address=client_ip, username=username)
                raise AuthenticationError("Invalid username or password")

            # Update last login timestamp if we add this field
            log_audit_event(action="user_login", user_id=user.id, details={"ip_address": client_ip})

            return user

        except SQLAlchemyError as e:
            raise DatabaseError(f"Authentication failed: {str(e)}") from e

    def get_user_by_id(self, user_id: int) -> models.User | None:
        """Get user by ID."""
        try:
            return self.db.query(models.User).filter(models.User.id == user_id).first()
        except SQLAlchemyError as e:
            raise DatabaseError(f"Failed to get user: {str(e)}") from e

    def get_user_by_username(self, username: str) -> models.User | None:
        """Get user by username."""
        try:
            return self.db.query(models.User).filter(models.User.username == username).first()
        except SQLAlchemyError as e:
            raise DatabaseError(f"Failed to get user: {str(e)}") from e

    def update_user(
        self, user_id: int, update_data: schemas.UserUpdate, updated_by: models.User
    ) -> models.User:  # noqa: E501
        """Update user information."""
        try:
            user = self.get_user_by_id(user_id)
            if not user:
                raise ValidationError(f"User with ID {user_id} not found")

            # Check permissions
            if updated_by.id != user_id and updated_by.role not in [
                models.RoleEnum.ADMIN,
                models.RoleEnum.SUPER_ADMIN,
            ]:  # noqa: E501
                raise AuthorizationError("Insufficient permissions to update user")

            update_details = {}

            # Update email if provided
            if update_data.email is not None:
                if update_data.email:
                    validated_email = validate_email(update_data.email)
                    # Check if email already exists for another user
                    existing_email = (
                        self.db.query(models.User)
                        .filter(models.User.email == validated_email, models.User.id != user_id)
                        .first()
                    )

                    if existing_email:
                        raise ValidationError(f"Email '{validated_email}' already exists")

                    user.email = validated_email
                else:
                    user.email = None

                update_details["email_updated"] = True

            # Update password if provided
            if update_data.password:
                validated_password = validate_password(update_data.password)
                user.password_hash = utils.get_password_hash(validated_password)
                update_details["password_updated"] = True

                log_security_event(
                    "password_changed", user_id=user.id, updated_by_user_id=updated_by.id
                )

            # Update role if provided (only admins can change roles)
            if update_data.role is not None:
                if updated_by.role not in [models.RoleEnum.ADMIN, models.RoleEnum.SUPER_ADMIN]:
                    raise AuthorizationError("Only admins can change user roles")

                old_role = user.role
                user.role = update_data.role
                update_details["role_changed"] = {"from": old_role.value, "to": user.role.value}

                log_security_event(
                    "role_changed",
                    user_id=user.id,
                    updated_by_user_id=updated_by.id,
                    old_role=old_role.value,
                    new_role=user.role.value,
                )

            user.updated_at = datetime.now(timezone.utc)
            self.db.commit()
            self.db.refresh(user)

            log_audit_event(
                action="user_updated",
                user_id=updated_by.id,
                target=f"user:{user.id}",
                details=update_details,
            )

            return user

        except SQLAlchemyError as e:
            self.db.rollback()
            raise DatabaseError(f"Failed to update user: {str(e)}") from e

    def delete_user(self, user_id: int, deleted_by: models.User) -> bool:
        """Delete a user (soft delete or hard delete based on business rules)."""
        try:
            user = self.get_user_by_id(user_id)
            if not user:
                raise ValidationError(f"User with ID {user_id} not found")

            # Check permissions
            if deleted_by.role not in [models.RoleEnum.ADMIN, models.RoleEnum.SUPER_ADMIN]:
                raise AuthorizationError("Only admins can delete users")

            # Prevent self-deletion
            if user_id == deleted_by.id:
                raise ValidationError("Users cannot delete themselves")

            # For now, we'll do hard delete, but in production you might want soft delete
            username = user.username
            self.db.delete(user)
            self.db.commit()

            log_audit_event(
                action="user_deleted",
                user_id=deleted_by.id,
                target=f"user:{user_id}",
                details={"deleted_username": username},
            )

            log_security_event(
                "user_deleted",
                user_id=deleted_by.id,
                target_user_id=user_id,
                deleted_username=username,
            )

            return True

        except SQLAlchemyError as e:
            self.db.rollback()
            raise DatabaseError(f"Failed to delete user: {str(e)}") from e

    def list_users(
        self, requesting_user: models.User, offset: int = 0, limit: int = 100
    ) -> list[models.User]:  # noqa: E501
        """List users (admin only)."""
        if requesting_user.role not in [models.RoleEnum.ADMIN, models.RoleEnum.SUPER_ADMIN]:
            raise AuthorizationError("Only admins can list users")

        try:
            return self.db.query(models.User).offset(offset).limit(limit).all()
        except SQLAlchemyError as e:
            raise DatabaseError(f"Failed to list users: {str(e)}") from e

    def check_user_permissions(
        self, user: models.User, required_roles: list[models.RoleEnum]
    ) -> bool:  # noqa: E501
        """Check if user has required roles."""
        return user.role in required_roles
