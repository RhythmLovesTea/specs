"""Policy Enforcement Point (PEP) and Policy Decision Point (PDP)."""
from __future__ import annotations

import fnmatch
import re
import time
from typing import Any, Callable, Dict, List, Optional

import yaml
from pydantic import ValidationError

from src.audit_logger import AuditLogger
from src.models import (
    AgentIdentity,
    AuditRecord,
    Effect,
    EnforcementVerdict,
    PolicyConfig,
    PolicyRule,
    ToolCallRequest,
)
from src.taint_tracker import TaintTracker

DELEGATE_TOOL = "a2a.delegate"  # pseudo-tool used to govern delegation
EFFECT_RANK = {Effect.DENY: 3, Effect.ESCALATE: 2, Effect.ALLOW: 1}
MAX_LOGGED_CHARS = 120
ApprovalCallback = Callable[[ToolCallRequest, str], bool]


class SecurityException(PermissionError):
    """Raised when the PEP blocks an action.

    public_message is safe to show to the (untrusted) agent; internal_detail
    carries rule identifiers and is intended for operators and logs only.
    """

    def __init__(self, public_message: str, internal_detail: str = "") -> None:
        super().__init__(public_message)
        self.public_message = public_message
        self.internal_detail = internal_detail


def _sanitize(arguments: Dict[str, Any]) -> Dict[str, Any]:
    clean: Dict[str, Any] = {}
    for key, value in arguments.items():
        if not isinstance(value, (str, int, float, bool, type(None))):
            value = repr(value)
        if isinstance(value, str) and len(value) > MAX_LOGGED_CHARS:
            value = value[:MAX_LOGGED_CHARS] + "..."
        clean[str(key)] = value
    return clean


class AgentSecurityGateway:
    def __init__(
        self,
        policy_file: str,
        audit_log_path: str = "logs/audit_log.jsonl",
        human_approval_callback: Optional[ApprovalCallback] = None,
    ) -> None:
        # Any parse/validation error here aborts start-up (fail-closed).
        with open(policy_file, "r", encoding="utf-8") as fh:
            self.policy = PolicyConfig(**yaml.safe_load(fh))
        self._taint_by_tool = {
            s.tool: s.adds_taint for s in self.policy.taint_sources
        }
        self.agents: Dict[str, AgentIdentity] = {}
        self.tools: Dict[str, Callable[..., Any]] = {}
        self.taint_tracker = TaintTracker()
        self.audit_logger = AuditLogger(audit_log_path)
        self.human_approval_callback = human_approval_callback

    # ------------------------------------------------------------ registry
    def register_agent(self, identity: AgentIdentity) -> None:
        self.agents[identity.agent_id] = identity

    def register_tool(self, tool_name: str, func: Callable[..., Any]) -> None:
        self.tools[tool_name] = func

    def clear_session(self, session_id: str) -> None:
        self.taint_tracker.clear_session(session_id)

    # ------------------------------------------------- policy decision (PDP)
    def _matches_conditions(
        self, rule: PolicyRule, request: ToolCallRequest, taints: List[str]
    ) -> bool:
        cond = rule.conditions
        if cond is None:
            return True
        if cond.taint_present_any and not any(
            t in taints for t in cond.taint_present_any
        ):
            return False
        for name, pattern in cond.argument_matches.items():
            value = str(request.arguments.get(name, ""))
            if re.fullmatch(pattern, value) is None:
                return False
        for name, pattern in cond.argument_not_matches.items():
            value = str(request.arguments.get(name, ""))
            if re.fullmatch(pattern, value) is not None:
                return False
        return True

    def _decide(self, request: ToolCallRequest) -> EnforcementVerdict:
        agent = self.agents.get(request.agent_id)
        if agent is None:
            return EnforcementVerdict(
                effect=Effect.DENY,
                matched_rule_id="UNREGISTERED_AGENT",
                reason=f"Unknown agent_id: {request.agent_id}",
            )
        if request.tool_name != DELEGATE_TOOL and (
            request.tool_name not in self.tools
        ):
            return EnforcementVerdict(
                effect=Effect.DENY,
                matched_rule_id="UNREGISTERED_TOOL",
                reason=f"Tool '{request.tool_name}' is not registered.",
            )
        taints = self.taint_tracker.get_taints(
            request.session_id, request.agent_id
        )
        matched: List[PolicyRule] = []
        for rule in self.policy.rules:
            if rule.role not in ("*", agent.role):
                continue
            if not fnmatch.fnmatchcase(request.tool_name, rule.tool_pattern):
                continue
            if self._matches_conditions(rule, request, taints):
                matched.append(rule)
        if not matched:
            return EnforcementVerdict(
                effect=self.policy.default_effect,
                matched_rule_id="DEFAULT_DENY",
                reason="No explicit allow rule matched (default-deny).",
                active_taints=taints,
            )
        # Strict precedence: DENY > ESCALATE > ALLOW, then higher priority.
        matched.sort(
            key=lambda r: (EFFECT_RANK[r.effect], r.priority),
            reverse=True,
        )
        winner = matched[0]
        return EnforcementVerdict(
            effect=winner.effect,
            matched_rule_id=winner.rule_id,
            reason=f"Matched rule '{winner.rule_id}' ({winner.effect.value}).",
            active_taints=taints,
        )

    def evaluate(self, request: ToolCallRequest) -> EnforcementVerdict:
        start = time.perf_counter()
        try:
            verdict = self._decide(request)
        except Exception as exc:  # NFR-01: any engine fault => DENY
            verdict = EnforcementVerdict(
                effect=Effect.DENY,
                matched_rule_id="ENGINE_ERROR",
                reason=f"Evaluation error: {type(exc).__name__}",
            )
        verdict.latency_ms = round((time.perf_counter() - start) * 1000, 4)
        return verdict

    # ------------------------------------------------ enforcement (PEP) core
    def _mediate(self, request: ToolCallRequest) -> EnforcementVerdict:
        """Evaluate, resolve ESCALATE, write the audit row, raise if blocked."""
        verdict = self.evaluate(request)
        final = verdict.effect
        if final is Effect.ESCALATE:
            approved = False
            if self.human_approval_callback is not None:
                try:
                    approved = bool(
                        self.human_approval_callback(
                            request, verdict.matched_rule_id
                        )
                    )
                except Exception:
                    approved = False
            final = Effect.ALLOW if approved else Effect.DENY
        agent = self.agents.get(request.agent_id)
        self.audit_logger.write(
            AuditRecord(
                session_id=request.session_id,
                agent_id=request.agent_id,
                role=agent.role if agent else "UNKNOWN",
                tool_name=request.tool_name,
                arguments=_sanitize(request.arguments),
                active_taints=verdict.active_taints,
                matched_rule_id=verdict.matched_rule_id,
                initial_effect=verdict.effect,
                verdict=final,
                latency_ms=verdict.latency_ms,
            )
        )
        if final is not Effect.ALLOW:
            if verdict.effect is Effect.ESCALATE:
                public = "Action requires human approval (not granted)."
            else:
                public = (
                    f"Policy violation: '{request.tool_name}' is not permitted "
                    "for this agent in the current context."
                )
            raise SecurityException(
                public,
                f"[{verdict.matched_rule_id}] {verdict.reason} "
                f"taints={verdict.active_taints}",
            )
        return verdict

    def execute_tool(self, request: ToolCallRequest) -> Any:
        """Intercept, evaluate, log and (only if authorised) execute a tool."""
        self._mediate(request)
        result = self.tools[request.tool_name](**request.arguments)
        label = self._taint_by_tool.get(request.tool_name)
        if label:  # output of a taint source labels the caller's context
            self.taint_tracker.add_taint(
                request.session_id, request.agent_id, label
            )
        return result

    def execute_raw(self, payload: Dict[str, Any]) -> Any:
        """Entry point for untrusted payloads; malformed input fails closed."""
        try:
            request = ToolCallRequest(**payload)
        except (ValidationError, TypeError) as exc:
            self.audit_logger.write(
                AuditRecord(
                    session_id="UNKNOWN",
                    agent_id="UNKNOWN",
                    role="UNKNOWN",
                    tool_name="MALFORMED",
                    arguments={},
                    active_taints=[],
                    matched_rule_id="SCHEMA_INVALID",
                    initial_effect=Effect.DENY,
                    verdict=Effect.DENY,
                    latency_ms=0.0,
                )
            )
            raise SecurityException(
                "Malformed request rejected.", str(exc)[:200]
            ) from exc
        return self.execute_tool(request)

    def delegate_task(
        self,
        session_id: str,
        from_agent_id: str,
        to_agent_id: str,
        payload: str,
    ) -> str:
        """Mediate agent-to-agent delegation and propagate taint labels."""
        target = self.agents.get(to_agent_id)
        request = ToolCallRequest(
            session_id=session_id,
            agent_id=from_agent_id,
            tool_name=DELEGATE_TOOL,
            arguments={
                "target_role": target.role if target else "UNKNOWN",
                "target_agent_id": to_agent_id,
            },
        )
        self._mediate(request)  # raises SecurityException when not permitted
        self.taint_tracker.propagate_taint(
            session_id, from_agent_id, to_agent_id
        )
        return payload
