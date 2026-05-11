from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException

from app.models import (
    AuditAction,
    AuditLog,
    BreachCreateRequest,
    BreachIncident,
    ConsentCreateRequest,
    ConsentRecord,
    DPIA,
    DPIACreateRequest,
    DPCO,
    build_audit_hash,
)


class InMemoryStore:
    def __init__(self) -> None:
        self.dpias: list[DPIA] = []
        self.breaches: list[BreachIncident] = []
        self.consents: list[ConsentRecord] = []
        self.audit_logs: tuple[AuditLog, ...] = ()
        self.dpcos: list[DPCO] = [
            DPCO(name="Lagos Data Trustees", ndpc_license_number="NDPC-DPCO-001", rating=4.7),
            DPCO(name="Abuja Privacy Partners", ndpc_license_number="NDPC-DPCO-002", rating=4.5),
        ]

    def append_audit(self, log: AuditLog) -> None:
        self.audit_logs = (*self.audit_logs, log)


store = InMemoryStore()
app = FastAPI(title="ComplyStack NDPA API")


def get_store() -> InMemoryStore:
    return store


def _log_create(resource: str, resource_id: str, state: InMemoryStore) -> None:
    state.append_audit(
        AuditLog(resource=resource, resource_id=resource_id, action=AuditAction.create, details={"worm": "immutable"})
    )


@app.post("/dpias", response_model=DPIA)
async def create_dpia(payload: DPIACreateRequest, state: Annotated[InMemoryStore, Depends(get_store)]) -> DPIA:
    if payload.cross_border and payload.data_localization_country.lower() != "nigeria":
        raise HTTPException(status_code=400, detail="Sovereign data must stay in Nigeria under NCP 2025.")

    total = sum(abs(v) for v in payload.factors.values())
    if total == 0:
        shap_explanation = {"risk_score_baseline": round(payload.risk_score / 100, 4)}
    else:
        shap_explanation = {k: round(v / total, 4) for k, v in payload.factors.items()}

    dpia = DPIA(
        organization_id=payload.organization_id,
        risk_score=payload.risk_score,
        shap_explanation=shap_explanation,
        mitigation_measures=payload.mitigation_measures,
    )
    state.dpias.append(dpia)
    _log_create("DPIA", str(dpia.id), state)
    return dpia


@app.post("/breaches", response_model=BreachIncident)
async def create_breach(
    payload: BreachCreateRequest,
    state: Annotated[InMemoryStore, Depends(get_store)],
) -> BreachIncident:
    regulators: list[str] = ["NDPC"]
    trace: list[str] = ["NDPC triggered: personal data incident falls under NDPA oversight."]

    if payload.banking_impact or payload.sector.lower() in {"banking", "fintech"}:
        regulators.append("CBN")
        trace.append("CBN triggered: financial sector impact detected.")
    if payload.telecom_impact or payload.sector.lower() == "telecom":
        regulators.append("NCC")
        trace.append("NCC triggered: telecom network or subscriber impact detected.")
    if payload.cyber_attack:
        regulators.append("ngCERT")
        trace.append("ngCERT triggered: cybersecurity incident indicators detected.")

    breach = BreachIncident(
        organization_id=payload.organization_id,
        regulators_triggered=sorted(set(regulators)),
        xai_decision_trace=trace,
    )
    state.breaches.append(breach)
    _log_create("BreachIncident", str(breach.id), state)
    return breach


@app.post("/consent", response_model=ConsentRecord)
async def create_consent(
    payload: ConsentCreateRequest,
    state: Annotated[InMemoryStore, Depends(get_store)],
) -> ConsentRecord:
    consent = ConsentRecord(
        organization_id=payload.organization_id,
        status=payload.status,
        audit_hash=build_audit_hash(payload.consent_payload),
    )
    state.consents.append(consent)
    _log_create("ConsentRecord", str(consent.id), state)
    return consent


@app.get("/car/status")
async def get_car_status() -> dict[str, object]:
    now = datetime.now(timezone.utc)
    return {
        "generated_at": now.strftime("%d-%m-%Y %H:%M"),
        "currency": "₦",
        "schedule": "GAID Schedule 2",
        "checklist": [
            {"item": "Data mapping completed", "complete": True},
            {"item": "Lawful basis documented", "complete": True},
            {"item": "Automated decision explainability attached", "complete": True},
            {"item": "Cross-border transfer controls reviewed", "complete": True},
        ],
    }


@app.get("/dpcos", response_model=list[DPCO])
async def list_dpcos(state: Annotated[InMemoryStore, Depends(get_store)]) -> list[DPCO]:
    return state.dpcos
