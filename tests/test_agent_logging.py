from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.agent.action_log import redact_secrets
from app.models import AgentActionLog, Base


def test_agent_action_log_model_can_save_blocked_action():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        log = AgentActionLog(
            session_id="agent-test",
            user_input="ssh into router",
            parsed_intent='{"tool_name": "blocked_request"}',
            tool_name="blocked_request",
            risk_level="high",
            policy_decision="blocked",
            confirmation_required=False,
            confirmation_result="not_required",
            executed=False,
            success=False,
            result_summary="Blocked.",
        )
        session.add(log)
        session.commit()
        assert log.id is not None


def test_redact_secrets_removes_sensitive_values():
    redacted = redact_secrets("password=hunter2 token=abc123 sk-1234567890abcdef")

    assert "hunter2" not in redacted
    assert "abc123" not in redacted
    assert "sk-1234567890abcdef" not in redacted
    assert "[REDACTED]" in redacted
