from __future__ import annotations

import json
import re
from dataclasses import asdict
from datetime import datetime

from sqlalchemy import select

from app.agent.agent_models import AgentResult, ParsedIntent, PolicyDecision
from app.database import get_session, init_db
from app.models import AgentActionLog


SECRET_PATTERNS = (
    re.compile(r"(?i)(password\s*=\s*)\S+"),
    re.compile(r"(?i)(api[_-]?key\s*=\s*)\S+"),
    re.compile(r"(?i)(token\s*=\s*)\S+"),
    re.compile(r"(?i)(secret\s*=\s*)\S+"),
    re.compile(r"sk-[A-Za-z0-9_-]{12,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL),
)


def redact_secrets(value: object) -> str:
    text = value if isinstance(value, str) else json.dumps(value, default=str)
    for pattern in SECRET_PATTERNS:
        text = pattern.sub(lambda match: f"{match.group(1)}[REDACTED]" if match.groups() else "[REDACTED]", text)
    redacted_lines = []
    for line in text.splitlines():
        lowered = line.lower()
        if any(word in lowered for word in ("private key", "password", "api_key", "api-key", "token", "secret")):
            key = line.split("=", 1)[0] if "=" in line else line[:24]
            redacted_lines.append(f"{key}=[REDACTED]")
        else:
            redacted_lines.append(line)
    return "\n".join(redacted_lines)


def log_agent_action(
    *,
    session_id: str,
    user_input: str,
    intent: ParsedIntent,
    decision: PolicyDecision,
    confirmation_result: str,
    executed: bool,
    result: AgentResult | None = None,
    error_message: str | None = None,
) -> AgentActionLog:
    init_db()
    with get_session() as session:
        log = AgentActionLog(
            session_id=redact_secrets(session_id),
            user_input=redact_secrets(user_input),
            parsed_intent=redact_secrets(asdict(intent)),
            tool_name=intent.tool_name,
            risk_level=decision.risk_level,
            policy_decision=redact_secrets(_policy_text(decision)),
            confirmation_required=decision.requires_confirmation,
            confirmation_result=confirmation_result,
            executed=executed,
            success=bool(result.ok) if result else False,
            result_summary=redact_secrets(result.message if result else ""),
            error_message=redact_secrets(error_message) if error_message else None,
        )
        session.add(log)
        session.commit()
        session.refresh(log)
        return log


def list_agent_logs(limit: int = 25) -> list[AgentActionLog]:
    init_db()
    with get_session() as session:
        return list(
            session.scalars(
                select(AgentActionLog)
                .order_by(AgentActionLog.created_at.desc())
                .limit(limit)
            ).all()
        )


def get_agent_log(log_id: int) -> AgentActionLog | None:
    init_db()
    with get_session() as session:
        return session.get(AgentActionLog, log_id)


def new_agent_session_id(now: datetime | None = None) -> str:
    now = now or datetime.now()
    suffix = f"{id(now) & 0xFFFF:04x}"
    return f"agent-{now.strftime('%Y%m%d-%H%M%S')}-{suffix}"


def _policy_text(decision: PolicyDecision) -> str:
    if decision.direct_cli_required:
        return "direct_cli_required"
    if not decision.allowed:
        return "blocked"
    if decision.requires_confirmation:
        return "requires_confirmation"
    return "allowed"
