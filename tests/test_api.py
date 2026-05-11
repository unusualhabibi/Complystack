from uuid import uuid4

from fastapi.testclient import TestClient

from app.main import app, store
from app.models import SHA256_HEX_LENGTH

client = TestClient(app)


def test_create_dpia_returns_shap_explanation() -> None:
    response = client.post(
        "/dpias",
        json={
            "organization_id": str(uuid4()),
            "risk_score": 75,
            "mitigation_measures": ["Encrypt PII"],
            "factors": {"retention_risk": 2.0, "access_risk": 1.0},
            "cross_border": False,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert "shap_explanation" in body
    assert body["shap_explanation"]["retention_risk"] > body["shap_explanation"]["access_risk"]


def test_create_dpia_blocks_non_nigeria_cross_border_localization() -> None:
    response = client.post(
        "/dpias",
        json={
            "organization_id": str(uuid4()),
            "risk_score": 10,
            "mitigation_measures": [],
            "factors": {},
            "cross_border": True,
            "data_localization_country": "Ghana",
        },
    )

    assert response.status_code == 400
    assert "Nigeria" in response.json()["detail"]


def test_create_breach_classifies_regulators() -> None:
    response = client.post(
        "/breaches",
        json={
            "organization_id": str(uuid4()),
            "sector": "fintech",
            "cyber_attack": True,
            "telecom_impact": True,
            "banking_impact": False,
        },
    )

    assert response.status_code == 200
    regulators = response.json()["regulators_triggered"]
    assert "NDPC" in regulators
    assert "CBN" in regulators
    assert "NCC" in regulators
    assert "ngCERT" in regulators


def test_create_consent_generates_sha256_hash() -> None:
    response = client.post(
        "/consent",
        json={
            "organization_id": str(uuid4()),
            "status": "granted",
            "consent_payload": "user-accepted-v1",
        },
    )

    assert response.status_code == 200
    audit_hash = response.json()["audit_hash"]
    assert len(audit_hash) == SHA256_HEX_LENGTH


def test_car_status_and_dpcos_and_audit_log_behavior() -> None:
    initial_audit_count = len(store.audit_logs)

    car = client.get("/car/status")
    assert car.status_code == 200
    assert car.json()["currency"] == "₦"

    dpcos = client.get("/dpcos")
    assert dpcos.status_code == 200
    assert len(dpcos.json()) >= 1

    consent = client.post(
        "/consent",
        json={
            "organization_id": str(uuid4()),
            "status": "granted",
            "consent_payload": "audit-proof-check",
        },
    )
    assert consent.status_code == 200
    assert len(store.audit_logs) == initial_audit_count + 1
    latest = store.audit_logs[-1]
    assert latest.details["worm"] == "immutable"
