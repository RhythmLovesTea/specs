"""FastAPI backend wrapping the real AgentSecurityGateway for the interactive demo."""
from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from evaluation.mock_tools import AGENTS, Ledger, build_tools
from src.audit_logger import AuditLogger
from src.gateway import AgentSecurityGateway, SecurityException
from src.models import ToolCallRequest

ROOT_DIR = Path(__file__).resolve().parent.parent
POLICY_PATH = ROOT_DIR / "config" / "policies.yaml"
SCENARIOS_PATH = ROOT_DIR / "demo" / "scenarios.json"
STATIC_INDEX = ROOT_DIR / "demo" / "static" / "index.html"
AUDIT_LOG_PATH = (
    Path(tempfile.gettempdir()) / "demo_audit.jsonl"
    if os.environ.get("VERCEL")
    else ROOT_DIR / "logs" / "demo_audit.jsonl"
)


class _LedgerRouter:
    """Routes mock tool side-effect recording to the currently active chapter ledger."""

    def __init__(self) -> None:
        self.target: Ledger = Ledger()

    def record(self, tool_name: str, **kwargs: Any) -> None:
        self.target.record(tool_name, **kwargs)


class DemoState:
    def __init__(self) -> None:
        self.story = self._load_story()
        self.rules_map = self._load_rules_map()
        self.approval_flag: List[bool] = [False]
        self.protected_router = _LedgerRouter()
        self.baseline_router = _LedgerRouter()
        self.protected_ledgers: Dict[str, Ledger] = {}
        self.baseline_ledgers: Dict[str, Ledger] = {}
        self.baseline_tools = build_tools(self.baseline_router)  # type: ignore[arg-type]
        self.gw = self._build_gateway(truncate=False)

    @staticmethod
    def _load_story() -> Dict[str, Any]:
        with SCENARIOS_PATH.open("r", encoding="utf-8") as fh:
            return json.load(fh)

    @staticmethod
    def _load_rules_map() -> Dict[str, Dict[str, Any]]:
        with POLICY_PATH.open("r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
        rules_map: Dict[str, Dict[str, Any]] = {}
        for rule in raw.get("rules", []):
            rid = rule["rule_id"]
            rules_map[rid] = {
                **rule,
                "yaml": yaml.safe_dump(rule, sort_keys=False).strip(),
            }
        # Built-in fallback rules from the gateway itself
        rules_map.setdefault(
            "DEFAULT_DENY",
            {
                "rule_id": "DEFAULT_DENY",
                "role": "*",
                "tool_pattern": "*",
                "effect": "DENY",
                "priority": 0,
                "yaml": "# Built-in fail-closed fallback\neffect: DENY\nreason: No explicit allow rule matched",
            },
        )
        rules_map.setdefault(
            "UNREGISTERED_AGENT",
            {
                "rule_id": "UNREGISTERED_AGENT",
                "role": "UNKNOWN",
                "tool_pattern": "*",
                "effect": "DENY",
                "priority": 9999,
                "yaml": "# Built-in identity guard\neffect: DENY\nreason: Agent ID not in registry",
            },
        )
        rules_map.setdefault(
            "UNREGISTERED_TOOL",
            {
                "rule_id": "UNREGISTERED_TOOL",
                "role": "*",
                "tool_pattern": "UNKNOWN",
                "effect": "DENY",
                "priority": 9999,
                "yaml": "# Built-in tool guard\neffect: DENY\nreason: Tool not registered",
            },
        )
        return rules_map

    def _build_gateway(self, truncate: bool) -> AgentSecurityGateway:
        AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        if truncate or not AUDIT_LOG_PATH.exists():
            AUDIT_LOG_PATH.write_text("", encoding="utf-8")
        gw = AgentSecurityGateway(
            str(POLICY_PATH),
            str(AUDIT_LOG_PATH),
            human_approval_callback=lambda req, rid: self.approval_flag[0],
        )
        for agent in AGENTS:
            gw.register_agent(agent)
        for name, fn in build_tools(self.protected_router).items():  # type: ignore[arg-type]
            gw.register_tool(name, fn)
        return gw

    def reset_all(self) -> None:
        self.approval_flag[0] = False
        self.protected_ledgers.clear()
        self.baseline_ledgers.clear()
        self.gw = self._build_gateway(truncate=True)

    def reset_chapter(self, chapter_id: str) -> None:
        ch = self.get_chapter(chapter_id)
        self.gw.clear_session(ch["session_id"])
        self.protected_ledgers[chapter_id] = Ledger()
        self.baseline_ledgers[chapter_id] = Ledger()

    def get_chapter(self, chapter_id: str) -> Dict[str, Any]:
        for ch in self.story["chapters"]:
            if ch["id"] == chapter_id:
                return ch
        raise HTTPException(status_code=404, detail=f"Unknown chapter_id: {chapter_id}")

    def read_audit_records(self) -> List[Dict[str, Any]]:
        if not AUDIT_LOG_PATH.exists():
            return []
        records: List[Dict[str, Any]] = []
        with AUDIT_LOG_PATH.open("r", encoding="utf-8") as fh:
            for idx, line in enumerate(fh, start=1):
                raw = line.strip()
                if not raw:
                    continue
                try:
                    item = json.loads(raw)
                except json.JSONDecodeError:
                    item = {"raw": raw, "corrupt": True}
                item["line_number"] = idx
                records.append(item)
        return records

    def get_taints_map(self, session_id: str) -> Dict[str, List[str]]:
        return {
            agent["id"]: self.gw.taint_tracker.get_taints(session_id, agent["id"])
            for agent in self.story["agents"]
        }


state = DemoState()
app = FastAPI(title="The Gateway That Says No — Demo API", version="1.0.0")


class StepRequest(BaseModel):
    chapter_id: str
    step_index: int = Field(ge=0)
    mode: str = Field(pattern="^(baseline|protected)$")
    approval: bool = False


class ChapterResetRequest(BaseModel):
    chapter_id: str


class FreePlayRequest(BaseModel):
    agent_id: str
    tool_name: str
    arguments: Dict[str, Any] = Field(default_factory=dict)
    session_id: str = "sess_freeplay"
    approval: bool = False


def _evaluate_goal(goal: Optional[Dict[str, Any]], ledger: Ledger) -> bool:
    if not goal:
        return False
    kind = goal.get("kind")
    if kind == "email_sent_to":
        return ledger.email_sent_to(goal["contains"])
    if kind == "posted_to":
        return ledger.posted_to(goal["contains"])
    if kind == "tool_executed":
        return ledger.executed(goal["tool"])
    return False


def _run_protected_step(
    chapter: Dict[str, Any], step: Dict[str, Any], approval: bool
) -> Dict[str, Any]:
    chapter_id = chapter["id"]
    session_id = chapter["session_id"]
    ledger = state.protected_ledgers.setdefault(chapter_id, Ledger())
    state.protected_router.target = ledger
    state.approval_flag[0] = approval

    step_type = step["type"]
    result: Optional[str] = None
    agent_message: Optional[str] = None
    operator_detail: Optional[str] = None

    try:
        if step_type in ("tool", "human_approval"):
            req = ToolCallRequest(
                session_id=session_id,
                agent_id=step["agent"],
                tool_name=step["tool"],
                arguments=step.get("args", {}),
            )
            result = state.gw.execute_tool(req)
        elif step_type == "delegate":
            result = state.gw.delegate_task(
                session_id,
                step["from"],
                step["to"],
                step.get("payload", "task"),
            )
            if result is not None:
                result = f"Delegated to {step['to']} (taints propagated)"
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported step type: {step_type}")
    except SecurityException as exc:
        agent_message = exc.public_message
        operator_detail = exc.internal_detail

    records = state.read_audit_records()
    latest_record = records[-1] if records else None
    verdict = latest_record["verdict"] if latest_record else "DENY"
    matched_rule_id = (
        latest_record["matched_rule_id"] if latest_record else "ENGINE_ERROR"
    )
    initial_effect = (
        latest_record.get("initial_effect", verdict) if latest_record else verdict
    )

    return {
        "mode": "protected",
        "verdict": verdict,
        "initial_effect": initial_effect,
        "matched_rule_id": matched_rule_id,
        "agent_message": agent_message,
        "operator_detail": operator_detail,
        "result": result,
        "taints": state.get_taints_map(session_id),
        "side_effect_occurred": _evaluate_goal(chapter.get("goal"), ledger),
        "audit_record": latest_record,
    }


def _run_baseline_step(chapter: Dict[str, Any], step: Dict[str, Any]) -> Dict[str, Any]:
    chapter_id = chapter["id"]
    ledger = state.baseline_ledgers.setdefault(chapter_id, Ledger())
    state.baseline_router.target = ledger

    step_type = step["type"]
    result: Optional[str] = None

    if step_type in ("tool", "human_approval"):
        tool_fn = state.baseline_tools.get(step["tool"])
        if tool_fn is None:
            result = f"Tool '{step['tool']}' executed directly (unregistered in baseline)"
        else:
            result = tool_fn(**step.get("args", {}))
    elif step_type == "delegate":
        result = f"Relayed directly from {step['from']} to {step['to']} (no check)"
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported step type: {step_type}")

    return {
        "mode": "baseline",
        "verdict": "EXECUTED",
        "initial_effect": "EXECUTED",
        "matched_rule_id": None,
        "agent_message": None,
        "operator_detail": None,
        "result": result,
        "taints": {a["id"]: [] for a in state.story["agents"]},
        "side_effect_occurred": _evaluate_goal(chapter.get("goal"), ledger),
        "audit_record": None,
    }


@app.get("/")
def serve_index() -> FileResponse:
    return FileResponse(STATIC_INDEX)


@app.get("/api/story")
def get_story() -> Dict[str, Any]:
    return {
        **state.story,
        "rules": state.rules_map,
    }


@app.post("/api/reset")
def reset_demo() -> Dict[str, Any]:
    state.reset_all()
    return {
        "ok": True,
        "audit_count": 0,
        "taints": {a["id"]: [] for a in state.story["agents"]},
    }


@app.post("/api/chapter/reset")
def reset_chapter(req: ChapterResetRequest) -> Dict[str, Any]:
    state.reset_chapter(req.chapter_id)
    ch = state.get_chapter(req.chapter_id)
    return {
        "ok": True,
        "chapter_id": req.chapter_id,
        "taints": state.get_taints_map(ch["session_id"]),
    }


@app.post("/api/step")
def run_step(req: StepRequest) -> Dict[str, Any]:
    chapter = state.get_chapter(req.chapter_id)
    steps = chapter.get("steps", [])
    if req.step_index >= len(steps):
        raise HTTPException(
            status_code=400,
            detail=f"step_index {req.step_index} out of bounds for {req.chapter_id}",
        )
    step = steps[req.step_index]

    # Starting a chapter from step 0 isolates that chapter's session and ledger
    if req.step_index == 0:
        if req.mode == "protected":
            state.gw.clear_session(chapter["session_id"])
            state.protected_ledgers[req.chapter_id] = Ledger()
        else:
            state.baseline_ledgers[req.chapter_id] = Ledger()

    if req.mode == "protected":
        return _run_protected_step(chapter, step, req.approval)
    return _run_baseline_step(chapter, step)


@app.get("/api/audit")
def get_audit() -> Dict[str, Any]:
    records = state.read_audit_records()
    return {"records": records, "count": len(records)}


@app.get("/api/audit/download")
def download_audit() -> FileResponse:
    if not AUDIT_LOG_PATH.exists():
        AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        AUDIT_LOG_PATH.write_text("", encoding="utf-8")
    return FileResponse(
        AUDIT_LOG_PATH,
        media_type="application/x-ndjson",
        filename="demo_audit.jsonl",
    )


@app.get("/api/verify")
def verify_audit() -> Dict[str, Any]:
    records = state.read_audit_records()
    if not AUDIT_LOG_PATH.exists() or len(records) == 0:
        return {"ok": True, "bad_line": None, "count": 0}
    ok, bad_line = AuditLogger.verify_chain(str(AUDIT_LOG_PATH))
    return {"ok": ok, "bad_line": bad_line, "count": len(records)}


@app.post("/api/tamper")
def tamper_audit() -> JSONResponse:
    if not AUDIT_LOG_PATH.exists():
        return JSONResponse(
            status_code=400,
            content={"ok": False, "detail": "Audit log is empty. Run or restore scenarios first."},
        )
    lines = AUDIT_LOG_PATH.read_text(encoding="utf-8").splitlines()
    if len(lines) < 2:
        return JSONResponse(
            status_code=400,
            content={"ok": False, "detail": "Need at least 2 audit records before tampering line 2."},
        )
    if '"DENY"' not in lines[1]:
        return JSONResponse(
            status_code=400,
            content={"ok": False, "detail": "Line 2 is already tampered or not a DENY record. Click Restore log first."},
        )
    lines[1] = lines[1].replace('"DENY"', '"ALLOW"', 1)
    AUDIT_LOG_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return JSONResponse(
        status_code=200,
        content={"ok": True, "tampered_line": 2, "detail": "Flipped verdict DENY -> ALLOW at line 2."},
    )


@app.post("/api/restore")
def restore_audit_chain() -> Dict[str, Any]:
    """Reset state and replay protected Chapters 2..7 so line 2 is DENY_RES_EMAIL."""
    state.reset_all()
    for ch in state.story["chapters"]:
        if ch["id"] in ("ch2", "ch3", "ch4", "ch5", "ch6", "ch7"):
            for idx, step in enumerate(ch.get("steps", [])):
                if idx == 0:
                    state.gw.clear_session(ch["session_id"])
                    state.protected_ledgers[ch["id"]] = Ledger()
                _run_protected_step(ch, step, approval=False)
    ok, bad_line = AuditLogger.verify_chain(str(AUDIT_LOG_PATH))
    records = state.read_audit_records()
    return {
        "ok": ok,
        "bad_line": bad_line,
        "count": len(records),
        "records": records,
    }


@app.get("/api/taints")
def get_taints(session_id: str = Query(...)) -> Dict[str, Any]:
    return {
        "session_id": session_id,
        "taints": state.get_taints_map(session_id),
    }


@app.post("/api/freeplay")
def run_freeplay(req: FreePlayRequest) -> Dict[str, Any]:
    """Run an ad-hoc tool call in both Baseline and Protected modes for Q&A."""
    # Baseline
    base_ledger = Ledger()
    state.baseline_router.target = base_ledger
    fn = state.baseline_tools.get(req.tool_name)
    if fn is None:
        base_out = f"Executed '{req.tool_name}' directly (no gateway protection)"
    else:
        try:
            base_out = fn(**req.arguments)
        except TypeError as exc:
            base_out = f"Baseline call error: {exc}"

    # Protected
    prot_ledger = Ledger()
    state.protected_router.target = prot_ledger
    state.approval_flag[0] = req.approval
    prot_result: Optional[str] = None
    agent_msg: Optional[str] = None
    op_detail: Optional[str] = None
    try:
        if req.tool_name == "a2a.delegate":
            target_id = str(req.arguments.get("target_agent_id", ""))
            prot_result = state.gw.delegate_task(
                req.session_id,
                req.agent_id,
                target_id,
                str(req.arguments.get("payload", "task")),
            )
            prot_result = f"Delegated to {target_id} (taints propagated)"
        else:
            treq = ToolCallRequest(
                session_id=req.session_id,
                agent_id=req.agent_id,
                tool_name=req.tool_name,
                arguments=req.arguments,
            )
            prot_result = state.gw.execute_tool(treq)
    except SecurityException as exc:
        agent_msg = exc.public_message
        op_detail = exc.internal_detail

    records = state.read_audit_records()
    latest = records[-1] if records else None
    return {
        "baseline": {"verdict": "EXECUTED", "result": base_out},
        "protected": {
            "verdict": latest["verdict"] if latest else "DENY",
            "matched_rule_id": latest["matched_rule_id"] if latest else "ENGINE_ERROR",
            "agent_message": agent_msg,
            "operator_detail": op_detail,
            "result": prot_result,
            "taints": state.get_taints_map(req.session_id),
            "audit_record": latest,
        },
    }


@app.post("/api/benchmark")
def run_latency_benchmark() -> Dict[str, Any]:
    """Run 10,000 live gateway.evaluate() calls and return percentiles + histogram."""
    sample_requests = [
        ToolCallRequest(session_id="bench", agent_id="com_01", tool_name="send_email", arguments={"to": "manager@company.com"}),
        ToolCallRequest(session_id="bench", agent_id="res_01", tool_name="send_email", arguments={"to": "attacker@evil.com"}),
        ToolCallRequest(session_id="bench", agent_id="cod_01", tool_name="write_file", arguments={"path": "/workspace/sandbox/out.txt"}),
        ToolCallRequest(session_id="bench", agent_id="res_01", tool_name="a2a.delegate", arguments={"target_role": "Communicator", "target_agent_id": "com_01"}),
        ToolCallRequest(session_id="bench", agent_id="rogue_99", tool_name="query_internal_db", arguments={}),
        ToolCallRequest(session_id="bench", agent_id="cod_01", tool_name="shell_exec", arguments={"command": "whoami"}),
    ]
    # Warm-up
    for i in range(500):
        state.gw.evaluate(sample_requests[i % len(sample_requests)])

    samples_us: List[float] = []
    n = 10000
    for i in range(n):
        r = sample_requests[i % len(sample_requests)]
        t0 = time.perf_counter_ns()
        state.gw.evaluate(r)
        t1 = time.perf_counter_ns()
        samples_us.append((t1 - t0) / 1000.0)

    samples_us.sort()
    p50 = round(samples_us[int(0.50 * n)], 2)
    p95 = round(samples_us[int(0.95 * n)], 2)
    p99 = round(samples_us[int(0.99 * n)], 2)
    mean = round(sum(samples_us) / n, 2)

    # 8 histogram bins up to 20 µs + overflow
    edges = [0, 2, 4, 6, 8, 10, 12, 16, 20]
    bins = [{"label": f"{edges[i]}–{edges[i+1]} µs", "count": 0} for i in range(len(edges) - 1)]
    bins.append({"label": ">20 µs", "count": 0})
    for val in samples_us:
        placed = False
        for i in range(len(edges) - 1):
            if val < edges[i + 1]:
                bins[i]["count"] += 1
                placed = True
                break
        if not placed:
            bins[-1]["count"] += 1

    return {
        "iterations": n,
        "mean_us": mean,
        "p50_us": p50,
        "p95_us": p95,
        "p99_us": p99,
        "bins": bins,
    }
