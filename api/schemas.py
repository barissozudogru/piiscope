"""Pydantic models used for request/response validation.

These schemas define the shape of payloads accepted by the API and
returned to clients.  They also serve as documentation in the
auto‑generated OpenAPI spec (Swagger UI).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from .models import ConnectionStatus, DataSourceType, RoleEnum, ScanStatus


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    username: str | None = None
    role: str | None = None


class UserBase(BaseModel):
    username: str
    email: EmailStr | None = None


class UserCreate(UserBase):
    password: str
    role: RoleEnum | None = RoleEnum.USER


class UserUpdate(BaseModel):
    email: EmailStr | None = None
    password: str | None = None
    role: RoleEnum | None = None


class UserOut(UserBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    role: RoleEnum
    created_at: datetime
    updated_at: datetime


class ProfileBase(BaseModel):
    name: str
    version: str | None = "1.0"
    description: str | None = None
    definition: dict[str, Any] = Field(
        ..., description="Profile definition containing patterns and weights"
    )  # noqa: E501


class ProfileCreate(ProfileBase):
    pass


class ProfileOut(ProfileBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime
    updated_at: datetime
    created_by_id: int | None


# Data Source schemas
class DataSourceBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: str | None = Field(None, max_length=255)
    source_type: DataSourceType


class DataSourceCreate(DataSourceBase):
    connection_config: dict[str, Any] = Field(..., description="Connection configuration")


class DataSourceUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=100)
    description: str | None = Field(None, max_length=255)
    connection_config: dict[str, Any] | None = None


class DataSourceOut(DataSourceBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: int
    status: ConnectionStatus
    last_tested_at: datetime | None
    test_error: str | None
    created_at: datetime
    updated_at: datetime


class ConnectionTestResult(BaseModel):
    success: bool
    message: str
    details: dict[str, Any] | None = None


class ScanJobCreate(BaseModel):
    profile_id: int
    data_source_id: int | None = None
    file_name: str | None = None
    table_name: str | None = Field(None, description="Database table name to scan")
    query: str | None = Field(None, description="Custom SQL query to scan")


class ScanJobOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    profile_id: int
    data_source_id: int | None
    file_name: str | None
    table_name: str | None
    query: str | None
    status: ScanStatus
    progress: float
    started_at: datetime | None
    finished_at: datetime | None
    error_message: str | None


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    record_index: int
    column_name: str
    rule_id: str
    severity: str
    confidence: float
    evidence: str | None
    is_false_positive: bool = False
    finding_metadata: dict[str, Any] | None = None


class ReidentificationRisk(BaseModel):
    prosecutor_risk: float | None = None
    journalist_risk: float | None = None
    marketer_risk: float | None = None
    risk_level: str | None = None
    unique_records: int | None = None
    equivalence_classes: int | None = None


class MetricOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    quasi_identifiers: list[str] | None
    k_anonymity: int | None
    l_diversity: int | None
    t_closeness: float | None
    reidentification_risk: dict[str, Any] | None = None
    privacy_impact_assessment: dict[str, Any] | None = None


class ReportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    html_path: str
    pdf_path: str | None
    created_at: datetime


class MessageResponse(BaseModel):
    message: str
