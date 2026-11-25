"""Pydantic v2 schemas for requests, policy rules, verdicts and audit rows."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Effect(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    ESCALATE = "ESCALATE"


class AgentIdentity(BaseModel):
    model_config = ConfigDict(frozen=True)

    agent_id: str = Field(min_length=1)
    agent_name: str
    role: str
    privilege_level: int = Field(ge=1, le=10)


class ToolCallRequest(BaseModel):
    """A structured tool invocation. Unknown fields are rejected."""

    model_config = ConfigDict(extra="forbid")

    session_id: str = Field(min_length=1)
    agent_id: str = Field(min_length=1)
    tool_name: str = Field(min_length=1)
    arguments: Dict[str, Any] = Field(default_factory=dict)


class RuleCondition(BaseModel):
    """Extra conditions that must ALL hold for a rule to apply.

    argument_matches      -> every listed argument must fully match its regex
    argument_not_matches  -> every listed argument must NOT fully match
    taint_present_any     -> at least one listed taint label is active
    """

    model_config = ConfigDict(extra="forbid")

    taint_present_any: List[str] = Field(default_factory=list)
    argument_matches: Dict[str, str] = Field(default_factory=dict)
    argument_not_matches: Dict[str, str] = Field(default_factory=dict)

    @field_validator("argument_matches", "argument_not_matches")
    @classmethod
    def _patterns_must_compile(cls, value: Dict[str, str]) -> Dict[str, str]:
        for pattern in value.values():
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError(f"invalid regex {pattern!r}: {exc}") from exc
        return value


class PolicyRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str
    role: str
    tool_pattern: str
    effect: Effect
    priority: int = 10
    conditions: Optional[RuleCondition] = None


class TaintSource(BaseModel):
    tool: str
    adds_taint: str


class PolicyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str
    default_effect: Effect = Effect.DENY
    taint_sources: List[TaintSource] = Field(default_factory=list)
    rules: List[PolicyRule] = Field(default_factory=list)

    @field_validator("default_effect")
    @classmethod
    def _default_must_deny(cls, value: Effect) -> Effect:
        if value is not Effect.DENY:
            raise ValueError("default_effect must be DENY (fail-closed)")
        return value


class EnforcementVerdict(BaseModel):
    effect: Effect
    matched_rule_id: str
    reason: str
    active_taints: List[str] = Field(default_factory=list)
    latency_ms: float = 0.0


class AuditRecord(BaseModel):
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(
            timespec="milliseconds"
        )
    )
    session_id: str
    agent_id: str
    role: str
    tool_name: str
    arguments: Dict[str, Any]
    active_taints: List[str]
    matched_rule_id: str
    initial_effect: Effect
    verdict: Effect
    latency_ms: float
    prev_hash: str = ""
    hash: str = ""
