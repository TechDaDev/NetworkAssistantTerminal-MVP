from app.agent.intent_parser import parse_intent
from app.agent.policy import evaluate_agent_action


def test_execute_plan_is_blocked_with_cli_instruction():
    intent = parse_intent("execute plan 1")
    decision = evaluate_agent_action(intent.tool_name, intent.args)

    assert intent.tool_name == "execute_plan"
    assert not decision.allowed
    assert decision.direct_cli_required
    assert decision.direct_cli_command == "python main.py plan execute 1"


def test_save_plan_is_blocked():
    intent = parse_intent("save plan 1")
    decision = evaluate_agent_action(intent.tool_name, intent.args)

    assert intent.tool_name == "save_plan"
    assert not decision.allowed
    assert decision.direct_cli_required


def test_rollback_plan_is_blocked():
    intent = parse_intent("rollback plan 1")
    decision = evaluate_agent_action(intent.tool_name, intent.args)

    assert intent.tool_name == "rollback_plan"
    assert not decision.allowed
    assert decision.direct_cli_required


def test_knowledge_delete_is_blocked():
    intent = parse_intent("delete knowledge 4")
    decision = evaluate_agent_action(intent.tool_name, intent.args)

    assert intent.tool_name == "delete_knowledge"
    assert not decision.allowed
    assert decision.direct_cli_command == "python main.py knowledge delete 4"
