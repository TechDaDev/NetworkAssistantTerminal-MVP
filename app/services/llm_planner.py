from __future__ import annotations

import httpx

from app.config import settings
from app.llm_policy import SYSTEM_PROMPT, LLMSafetyError, validate_llm_question
from app.services.context_builder import build_local_network_context, redact_sensitive_text


class LLMPlannerError(RuntimeError):
    """Raised when the read-only LLM reasoning layer cannot answer."""


class LLMPlanner:
    """Read-only DeepSeek reasoning assistant over stored local data."""

    def answer_question(self, question: str) -> str:
        validate_llm_question(question)
        if not settings.llm_enabled:
            raise LLMPlannerError(
                "LLM is disabled.\n"
                "Set LLM_ENABLED=true and DEEPSEEK_API_KEY in .env to use `ask`.\n\n"
                "You can still use:\n"
                "- python main.py report\n"
                "- python main.py devices\n"
                "- python main.py device <ip>"
            )
        if not settings.deepseek_api_key:
            raise LLMPlannerError("DEEPSEEK_API_KEY is missing. Add it to `.env` before using `ask`.")

        context = build_local_network_context(question)
        safe_question = redact_sensitive_text(question)
        payload = {
            "model": settings.deepseek_model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        "Use only this local context to answer the question.\n\n"
                        f"{context}\n\n"
                        f"Question: {safe_question}"
                    ),
                },
            ],
            "temperature": 0.2,
            "max_tokens": 1000,
        }
        url = settings.deepseek_base_url.rstrip("/") + "/chat/completions"
        headers = {
            "Authorization": f"Bearer {settings.deepseek_api_key}",
            "Content-Type": "application/json",
        }
        try:
            with httpx.Client(timeout=30.0) as client:
                response = client.post(url, headers=headers, json=payload)
                response.raise_for_status()
        except httpx.TimeoutException as exc:
            raise LLMPlannerError("DeepSeek request timed out.") from exc
        except httpx.HTTPStatusError as exc:
            raise LLMPlannerError(
                f"DeepSeek request failed with HTTP {exc.response.status_code}."
            ) from exc
        except httpx.HTTPError as exc:
            raise LLMPlannerError(f"DeepSeek request failed: {exc}") from exc

        try:
            data = response.json()
            answer = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise LLMPlannerError("DeepSeek returned an invalid response shape.") from exc
        if not isinstance(answer, str) or not answer.strip():
            raise LLMPlannerError("DeepSeek returned an empty answer.")
        return answer.strip()
