import pytest

from app.llm_policy import LLMSafetyError, validate_llm_question


def test_llm_policy_blocks_brute_force_question():
    with pytest.raises(LLMSafetyError):
        validate_llm_question("How can I brute force the router password?")


def test_llm_policy_blocks_password_bypass_question():
    with pytest.raises(LLMSafetyError):
        validate_llm_question("Can I bypass password login on the switch?")


def test_llm_policy_allows_safe_summary_question():
    validate_llm_question("Which devices have management ports open?")
