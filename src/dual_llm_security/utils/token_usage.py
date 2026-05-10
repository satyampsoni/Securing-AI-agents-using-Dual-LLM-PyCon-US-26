from __future__ import annotations

from dual_llm_security.models import TokenUsage


def estimate_tokens(*parts: str) -> int:
    joined = " ".join(part for part in parts if part)
    return max(1, len(joined) // 4) if joined else 0


def build_token_usage(prompt: str, response: str) -> TokenUsage:
    return TokenUsage(
        input_tokens=estimate_tokens(prompt),
        output_tokens=estimate_tokens(response),
    )


def combine_token_usage(usages: list[TokenUsage]) -> TokenUsage:
    return TokenUsage(
        input_tokens=sum(item.input_tokens for item in usages),
        output_tokens=sum(item.output_tokens for item in usages),
    )
