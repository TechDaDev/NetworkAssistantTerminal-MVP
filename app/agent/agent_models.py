from __future__ import annotations

from dataclasses import dataclass, field

from pydantic import BaseModel, Field


@dataclass(frozen=True)
class ParsedIntent:
    tool_name: str
    args: dict = field(default_factory=dict)
    raw_text: str = ""


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    risk_level: str
    requires_confirmation: bool = False
    allowed_in_agent: bool = True
    direct_cli_required: bool = False
    direct_cli_template: str | None = None
    reason: str = ""


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    risk_level: str
    requires_confirmation: bool = False
    direct_cli_required: bool = False
    message: str = ""
    direct_cli_command: str | None = None


@dataclass
class AgentResult:
    action: str
    risk_level: str
    ok: bool
    message: str
    next_command: str | None = None
    data: dict | list | None = None
    policy_decision: str = ""


class AgentToolResult(BaseModel):
    success: bool
    title: str
    summary: str
    details: dict = Field(default_factory=dict)
    suggested_commands: list[str] = Field(default_factory=list)
    next_actions: list[str] = Field(default_factory=list)
