from __future__ import annotations

from dual_llm_security.models import ToolExecutionResult


def draft_reply() -> ToolExecutionResult:
    return ToolExecutionResult(
        tool_name="draft_reply",
        success=True,
        output="Drafted a cautious reply for human review before any external response is sent.",
    )


def create_ticket(queue: str, priority: str) -> ToolExecutionResult:
    return ToolExecutionResult(
        tool_name="create_ticket",
        success=True,
        output=f"Created internal ticket in queue '{queue}' with priority '{priority}'.",
    )


def mark_safe_to_ignore(reason: str) -> ToolExecutionResult:
    return ToolExecutionResult(
        tool_name="mark_safe_to_ignore",
        success=True,
        output=f"Marked the request safe to ignore: {reason}.",
    )
