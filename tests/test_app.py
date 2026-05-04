from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


def build_client() -> TestClient:
    app = create_app(
        Settings(
            RUN_MODE="replay",
            ALLOW_SENSITIVE_TOOLS=False,
        )
    )
    return TestClient(app)


def test_home_page_renders() -> None:
    client = build_client()
    response = client.get("/")
    assert response.status_code == 200
    assert "Dual-LLM Security Demo" in response.text


def test_scenarios_are_listed() -> None:
    client = build_client()
    response = client.get("/api/scenarios")
    assert response.status_code == 200
    payload = response.json()
    assert len(payload) == 3
    assert {item["id"] for item in payload} == {
        "hidden-prompt-injection",
        "confused-deputy-web-research",
        "lethal-trifecta-memory-exfiltration",
    }


def test_gmail_status_reports_not_configured_by_default() -> None:
    client = build_client()
    response = client.get("/api/gmail/status")
    assert response.status_code == 200
    payload = response.json()
    assert payload["configured"] is False
    assert payload["connected"] is False


def test_gmail_messages_fail_cleanly_when_not_configured() -> None:
    client = build_client()
    response = client.get("/api/gmail/messages")
    assert response.status_code == 400
    assert "Gmail" in response.json()["detail"]


def test_baseline_hidden_prompt_injection_is_influenced() -> None:
    client = build_client()
    response = client.post(
        "/api/run",
        json={"scenario_id": "hidden-prompt-injection", "mode": "baseline"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["decision"]["tool_request"]["name"] == "mark_safe_to_ignore"
    assert payload["policy_verdict"]["status"] == "allow"
    assert "unsafe closure path" in payload["decision"]["justification"]


def test_dual_mode_redirects_hidden_prompt_to_ticket() -> None:
    client = build_client()
    response = client.post(
        "/api/run",
        json={"scenario_id": "hidden-prompt-injection", "mode": "dual"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["decision"]["tool_request"]["name"] == "create_ticket"
    assert payload["policy_verdict"]["status"] == "allow"
    assert payload["quarantined_output"]["suspicious_instructions"]


def test_lethal_trifecta_baseline_is_blocked() -> None:
    client = build_client()
    response = client.post(
        "/api/run",
        json={"scenario_id": "lethal-trifecta-memory-exfiltration", "mode": "baseline"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["decision"]["tool_request"]["name"] == "send_external_webhook"
    assert payload["policy_verdict"]["status"] == "block"
    assert "Sensitive tools are disabled" in payload["policy_verdict"]["reason"]


def test_dual_lethal_trifecta_requires_human_review() -> None:
    client = build_client()
    response = client.post(
        "/api/run",
        json={"scenario_id": "lethal-trifecta-memory-exfiltration", "mode": "dual"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["decision"]["tool_request"]["name"] == "create_ticket"
    assert payload["policy_verdict"]["status"] == "needs_human"
    assert payload["policy_verdict"]["requires_human"] is True


def test_run_can_be_fetched_by_id() -> None:
    client = build_client()
    create_response = client.post(
        "/api/run",
        json={"scenario_id": "confused-deputy-web-research", "mode": "dual"},
    )
    run_id = create_response.json()["id"]
    fetch_response = client.get(f"/api/runs/{run_id}")
    assert fetch_response.status_code == 200
    assert fetch_response.json()["id"] == run_id
