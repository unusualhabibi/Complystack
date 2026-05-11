from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256
from typing import Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ConsentStatus(str, Enum):
    granted = "granted"
    denied = "denied"
    withdrawn = "withdrawn"


class TIAStatus(str, Enum):
    pending = "pending"
    approved = "approved"
    rejected = "rejected"


SHA256_HEX_LENGTH = 64
RegulatorLiteral = Literal["NDPC", "CBN", "NCC", "ngCERT"]


class Organization(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: UUID = Field(default_factory=uuid4)
    name: str = Field(min_length=1)
    dcpmi_tier: str = Field(min_length=1)
    sector: str = Field(min_length=1)
    data_subject_count: int = Field(ge=0)


class ProcessingActivity(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: UUID = Field(default_factory=uuid4)
    organization_id: UUID
    lawful_basis: str = Field(min_length=1)
    cross_border: bool
    automated_decision_making: bool


class ConsentRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: UUID = Field(default_factory=uuid4)
    organization_id: UUID
    status: ConsentStatus
    audit_hash: str = Field(min_length=SHA256_HEX_LENGTH, max_length=SHA256_HEX_LENGTH)


class DPIA(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: UUID = Field(default_factory=uuid4)
    organization_id: UUID
    risk_score: float = Field(ge=0, le=100)
    shap_explanation: dict[str, float]
    mitigation_measures: list[str]


class BreachIncident(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: UUID = Field(default_factory=uuid4)
    organization_id: UUID
    regulators_triggered: list[RegulatorLiteral]
    xai_decision_trace: list[str]


class CrossBorderTransfer(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: UUID = Field(default_factory=uuid4)
    organization_id: UUID
    ncp2025_compliant: bool
    tia_status: TIAStatus


class PrivacyPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: UUID = Field(default_factory=uuid4)
    organization_id: UUID
    ndpa_compliant: bool
    gaps_detected: list[str] = Field(default_factory=list)


class DPCO(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: UUID = Field(default_factory=uuid4)
    name: str = Field(min_length=1)
    ndpc_license_number: str = Field(min_length=1)
    rating: float = Field(ge=0, le=5)


class User(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: UUID = Field(default_factory=uuid4)
    email: str
    role: str
    mfa_enabled: bool


class AuditAction(str, Enum):
    create = "create"
    update = "update"
    delete = "delete"


class AuditLog(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: UUID = Field(default_factory=uuid4)
    resource: str
    resource_id: str
    action: AuditAction
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    details: dict[str, str] = Field(default_factory=dict)


class ConsentCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    organization_id: UUID
    status: ConsentStatus
    consent_payload: str = Field(min_length=1)


class DPIACreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    organization_id: UUID
    risk_score: float = Field(ge=0, le=100)
    mitigation_measures: list[str] = Field(default_factory=list)
    factors: dict[str, float] = Field(default_factory=dict)
    cross_border: bool = False
    data_localization_country: str = "Nigeria"

    @field_validator("data_localization_country")
    @classmethod
    def validate_country(cls, value: str) -> str:
        return value.strip()


class BreachCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    organization_id: UUID
    sector: str = Field(min_length=1)
    cyber_attack: bool = False
    telecom_impact: bool = False
    banking_impact: bool = False


def build_audit_hash(payload: str) -> str:
    return sha256(payload.encode("utf-8")).hexdigest()
