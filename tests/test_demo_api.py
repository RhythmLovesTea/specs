"""End-to-end API tests verifying every chapter and checklist item in demo/server.py."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from demo.server import app


@pytest.fixture
def client():
    with TestClient(app) as c:
        c.post("/api/reset")
        yield c
        c.post("/api/reset")


def test_index_and_story_and_metrics(client: TestClient):
    res = client.get("/")
    assert res.status_code == 200
    assert "The Gateway That Says No" in res.text
    assert "#090909" in res.text

    story = client.get("/api/story").json()
    assert len(story["chapters"]) == 9
    assert len(story["agents"]) == 4
    assert "DENY_TAINTED_EXTERNAL_EMAIL" in story["rules"]
    kpis = {k["label"]: k["value"] for k in story["metrics"]["kpis"]}
    assert kpis["Policy-covered attacks (no gateway)"] == "20 / 20"
    assert kpis["Policy-covered attacks (with gateway)"] == "0 / 20"
    assert kpis["Stopped by stateful taint rules"] == "9 / 20"
    assert kpis["Benign workflows completed"] == "19 / 20 (95%)"
    assert kpis["Decision latency (median / p95)"] == "6.1 µs / 8.0 µs"
    assert kpis["End-to-end with audit write (p95)"] == "51.8 µs"
    assert kpis["Actions mediated vs logged"] == "96 / 96"
    assert kpis["Automated test suite"] == "21 test cases, 26 pytest items, all passing"


def test_chapter2_and_chapter3(client: TestClient):
    # Ch2 benign email
    b2 = client.post("/api/step", json={"chapter_id": "ch2", "step_index": 0, "mode": "baseline"}).json()
    p2 = client.post("/api/step", json={"chapter_id": "ch2", "step_index": 0, "mode": "protected"}).json()
    assert b2["verdict"] == "EXECUTED"
    assert p2["verdict"] == "ALLOW"
    assert p2["matched_rule_id"] == "ALLOW_COM_EMAIL"

    # Ch3 static RBAC deny
    b3 = client.post("/api/step", json={"chapter_id": "ch3", "step_index": 0, "mode": "baseline"}).json()
    p3 = client.post("/api/step", json={"chapter_id": "ch3", "step_index": 0, "mode": "protected"}).json()
    assert b3["side_effect_occurred"] is True
    assert p3["verdict"] == "DENY"
    assert p3["matched_rule_id"] == "DENY_RES_EMAIL"
    assert p3["side_effect_occurred"] is False
    assert "DENY_RES_EMAIL" not in p3["agent_message"]
    assert "DENY_RES_EMAIL" in p3["operator_detail"]


def test_chapter4_hero_and_chapter5_two_hop(client: TestClient):
    # Ch4: fetch -> delegate -> send_email
    client.post("/api/step", json={"chapter_id": "ch4", "step_index": 0, "mode": "baseline"})
    p0 = client.post("/api/step", json={"chapter_id": "ch4", "step_index": 0, "mode": "protected"}).json()
    assert p0["verdict"] == "ALLOW"
    assert p0["taints"]["res_01"] == ["UNTRUSTED_EXTERNAL"]
    assert p0["taints"]["com_01"] == []

    client.post("/api/step", json={"chapter_id": "ch4", "step_index": 1, "mode": "baseline"})
    p1 = client.post("/api/step", json={"chapter_id": "ch4", "step_index": 1, "mode": "protected"}).json()
    assert p1["verdict"] == "ALLOW"
    assert p1["taints"]["com_01"] == ["UNTRUSTED_EXTERNAL"]

    b2 = client.post("/api/step", json={"chapter_id": "ch4", "step_index": 2, "mode": "baseline"}).json()
    p2 = client.post("/api/step", json={"chapter_id": "ch4", "step_index": 2, "mode": "protected"}).json()
    assert b2["verdict"] == "EXECUTED"
    assert b2["side_effect_occurred"] is True
    assert p2["verdict"] == "DENY"
    assert p2["matched_rule_id"] == "DENY_TAINTED_EXTERNAL_EMAIL"
    assert p2["side_effect_occurred"] is False
    assert "UNTRUSTED_EXTERNAL" not in p2["agent_message"]
    assert "DENY_TAINTED_EXTERNAL_EMAIL" in p2["operator_detail"]

    # Ch5: 2-hop res_01 -> orch_01 -> com_01
    for i in range(4):
        client.post("/api/step", json={"chapter_id": "ch5", "step_index": i, "mode": "baseline"})
        p = client.post("/api/step", json={"chapter_id": "ch5", "step_index": i, "mode": "protected"}).json()
    assert p["taints"]["res_01"] == ["UNTRUSTED_EXTERNAL"]
    assert p["taints"]["orch_01"] == ["UNTRUSTED_EXTERNAL"]
    assert p["taints"]["com_01"] == ["UNTRUSTED_EXTERNAL"]
    assert p["verdict"] == "DENY"
    assert p["matched_rule_id"] == "DENY_TAINTED_EXTERNAL_EMAIL"


def test_chapter6_precision_and_chapter7_hitl(client: TestClient):
    # Ch6: setup read_email_inbox, internal ALLOW, multi-recipient DENY, lookalike DENY
    p0 = client.post("/api/step", json={"chapter_id": "ch6", "step_index": 0, "mode": "protected"}).json()
    assert p0["taints"]["com_01"] == ["UNTRUSTED_EXTERNAL"]

    p1 = client.post("/api/step", json={"chapter_id": "ch6", "step_index": 1, "mode": "protected"}).json()
    assert p1["verdict"] == "ALLOW"

    p2 = client.post("/api/step", json={"chapter_id": "ch6", "step_index": 2, "mode": "protected"}).json()
    assert p2["verdict"] == "DENY"
    assert p2["matched_rule_id"] == "DENY_TAINTED_EXTERNAL_EMAIL"

    p3 = client.post("/api/step", json={"chapter_id": "ch6", "step_index": 3, "mode": "protected"}).json()
    assert p3["verdict"] == "DENY"
    assert p3["matched_rule_id"] == "DENY_TAINTED_EXTERNAL_EMAIL"

    # Ch7: CONFIDENTIAL_INTERNAL + HITL reject vs approve
    client.post("/api/step", json={"chapter_id": "ch7", "step_index": 0, "mode": "protected"})
    ok_api = client.post("/api/step", json={"chapter_id": "ch7", "step_index": 1, "mode": "protected"}).json()
    assert ok_api["verdict"] == "ALLOW"

    exfil = client.post("/api/step", json={"chapter_id": "ch7", "step_index": 2, "mode": "protected"}).json()
    assert exfil["verdict"] == "DENY"
    assert exfil["matched_rule_id"] == "DENY_CODER_CONF_EXFIL"

    rej = client.post("/api/step", json={"chapter_id": "ch7", "step_index": 3, "mode": "protected", "approval": False}).json()
    assert rej["verdict"] == "DENY"
    assert rej["agent_message"] == "Action requires human approval (not granted)."
    assert "ESCALATE_CODER_DB_DELETE" in rej["operator_detail"]

    app_res = client.post("/api/step", json={"chapter_id": "ch7", "step_index": 3, "mode": "protected", "approval": True}).json()
    assert app_res["verdict"] == "ALLOW"
    assert app_res["result"] == "deleted"


def test_chapter8_audit_tamper_verify_restore_and_reset(client: TestClient):
    restored = client.post("/api/restore").json()
    assert restored["ok"] is True
    assert restored["count"] >= 10

    v1 = client.get("/api/verify").json()
    assert v1["ok"] is True
    assert v1["bad_line"] is None

    tamper = client.post("/api/tamper")
    assert tamper.status_code == 200

    v2 = client.get("/api/verify").json()
    assert v2["ok"] is False
    assert v2["bad_line"] == 2

    restored2 = client.post("/api/restore").json()
    assert restored2["ok"] is True

    reset = client.post("/api/reset").json()
    assert reset["audit_count"] == 0
    assert client.get("/api/audit").json()["count"] == 0
    assert client.get("/api/taints?session_id=sess_ch4").json()["taints"]["res_01"] == []


def test_freeplay_and_benchmark(client: TestClient):
    fp = client.post(
        "/api/freeplay",
        json={"agent_id": "cod_01", "tool_name": "shell_exec", "arguments": {"command": "id"}},
    ).json()
    assert fp["baseline"]["verdict"] == "EXECUTED"
    assert fp["protected"]["verdict"] == "DENY"
    assert fp["protected"]["matched_rule_id"] == "DENY_SHELL_ALL"

    bench = client.post("/api/benchmark").json()
    assert bench["iterations"] == 10000
    assert bench["p95_us"] < 50000
