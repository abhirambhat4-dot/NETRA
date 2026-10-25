"""GET /api/incidents/{id}/risk-evaluations and the principal NETRA workflow through the HTTP API.

Runs on the core_api fixture's throwaway schema (rolled back); no persistent database is touched.
"""

from uuid import uuid4

from sqlalchemy import select

from app.models.incident import IncidentHistory
from app.models.user import User
from app.services.auth import hash_password
from app.services.risk_engine import RISK_METHODOLOGY_VERSION
from tests.conftest import CoreApi

PASSWORD = "workflow-test-password-1"


def _login(core_api: CoreApi) -> dict[str, str]:
    email = f"workflow-{uuid4().hex[:8]}@example.com"
    with core_api.session_factory() as session:
        session.add(User(email=email, full_name="Workflow Analyst", password_hash=hash_password(PASSWORD)))
        session.commit()
    response = core_api.client.post("/api/auth/login", json={"email": email, "password": PASSWORD})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def _ingest(core_api: CoreApi, headers: dict[str, str], uid: str, minute: int) -> dict:
    response = core_api.client.post(
        "/api/events/ingest",
        json={
            "event_uid": uid,
            "occurred_at": f"2026-10-25T10:{minute:02d}:00Z",
            "source": "SURICATA",
            "event_type": "ssh_bruteforce",
            "signature": f"SSH brute force attempt {minute}",
            "severity": "HIGH",
            "src_ip": "198.51.100.23",
            "dest_ip": "10.20.0.5",
            "anomaly_score": 0.6,
        },
        headers=headers,
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_risk_evaluations_require_authentication(core_api: CoreApi) -> None:
    response = core_api.client.get(f"/api/incidents/{uuid4()}/risk-evaluations")
    assert response.status_code == 401


def test_risk_evaluations_of_an_unknown_incident_are_not_found(core_api: CoreApi) -> None:
    response = core_api.client.get(f"/api/incidents/{uuid4()}/risk-evaluations", headers=core_api.headers)
    assert (response.status_code, response.json()) == (404, {"detail": "Incident not found"})


def test_the_principal_workflow_persists_and_returns_a_consistent_risk_evaluation(core_api: CoreApi) -> None:
    # 1. Authenticate with a real password login.
    headers = _login(core_api)
    assert core_api.client.get("/api/auth/me", headers=headers).status_code == 200

    # 2. Security events reach the API and are listed.
    first = _ingest(core_api, headers, f"evt-workflow-{uuid4().hex[:8]}", 0)
    second = _ingest(core_api, headers, f"evt-workflow-{uuid4().hex[:8]}", 5)
    events = core_api.client.get("/api/events", headers=headers)
    assert events.status_code == 200
    assert {first["id"], second["id"]} <= {item["id"] for item in events.json()["items"]}

    # 3. Open an incident from the first event; correlation links the related second event (DETECTED -> UNDERSTOOD).
    created = core_api.client.post(
        "/api/incidents",
        json={"title": "SSH brute force against 10.20.0.5", "severity": "HIGH", "detection_source": "SURICATA", "event_ids": [first["id"]]},
        headers=headers,
    )
    assert created.status_code == 201, created.text
    incident_id = created.json()["id"]
    assert core_api.client.get(f"/api/incidents/{incident_id}/risk-evaluations", headers=headers).json() == []
    correlated = core_api.client.post(f"/api/incidents/{incident_id}/correlate", headers=headers)
    assert correlated.status_code == 200, correlated.text
    assert correlated.json()["state"] == "UNDERSTOOD"

    # 4. Calculate risk: the score is returned and persisted as one evaluation.
    scored = core_api.client.post(f"/api/incidents/{incident_id}/risk-score", headers=headers)
    assert scored.status_code == 200, scored.text
    score = scored.json()

    # 5. Retrieve the incident and its evaluation again.
    detail = core_api.client.get(f"/api/incidents/{incident_id}", headers=headers)
    evaluations = core_api.client.get(f"/api/incidents/{incident_id}/risk-evaluations", headers=headers)
    assert detail.status_code == evaluations.status_code == 200
    incident = detail.json()["incident"]
    (evaluation,) = evaluations.json()

    # 6. Score, level, state and history agree with each other.
    assert incident["state"] == "PRIORITISED"
    assert incident["riskScore"] == score["riskScore"] == evaluation["riskScore"]
    assert evaluation["riskLevel"] == score["severity"]
    assert evaluation["factors"] == score["factors"]
    assert evaluation["missingEvidence"] == score["missingEvidence"]
    assert evaluation["methodologyVersion"] == RISK_METHODOLOGY_VERSION
    assert (evaluation["trigger"], evaluation["incidentId"], evaluation["previousRiskScore"]) == ("initial", incident_id, None)
    assert evaluation["actor"].startswith("workflow-") and evaluation["createdAt"]
    assert set(evaluation) == {
        "id", "incidentId", "methodologyVersion", "riskScore", "riskLevel", "previousRiskScore",
        "factors", "missingEvidence", "matchedIndicators", "trigger", "actor", "createdAt",
    }
    with core_api.session_factory() as session:
        (history,) = session.scalars(
            select(IncidentHistory).where(
                IncidentHistory.incident_id == incident_id, IncidentHistory.action == "risk_calculated"
            )
        ).all()
    assert history.details["risk_calculation"]["risk_score"] == evaluation["riskScore"]
    assert history.actor == evaluation["actor"]
    timeline = core_api.client.get(f"/api/incidents/{incident_id}/timeline", headers=headers)
    risk_entries = [entry for entry in timeline.json() if entry["title"] == "risk_calculated"]
    assert timeline.status_code == 200 and len(risk_entries) == 1
    assert (risk_entries[0]["stage"], risk_entries[0]["actor"]) == ("PRIORITISED", evaluation["actor"])

    # A repeated calculation is refused and adds no evaluation.
    assert core_api.client.post(f"/api/incidents/{incident_id}/risk-score", headers=headers).status_code == 409
    assert len(core_api.client.get(f"/api/incidents/{incident_id}/risk-evaluations", headers=headers).json()) == 1
