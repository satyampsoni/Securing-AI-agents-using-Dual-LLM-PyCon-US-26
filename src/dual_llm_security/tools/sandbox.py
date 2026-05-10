from __future__ import annotations

from dual_llm_security.models import ToolDefinition, ToolExecutionResult, ToolRequest, ToolSensitivity
from dual_llm_security.tools import email_tool


TOOL_CATALOG: dict[str, ToolDefinition] = {
    "draft_reply": ToolDefinition(
        name="draft_reply",
        description="Create a draft response for a human to review before sending.",
        sensitivity=ToolSensitivity.LOW,
    ),
    "create_ticket": ToolDefinition(
        name="create_ticket",
        description="Open an internal investigation ticket for another team.",
        sensitivity=ToolSensitivity.MEDIUM,
    ),
    "mark_safe_to_ignore": ToolDefinition(
        name="mark_safe_to_ignore",
        description="Close the request with no additional follow-up.",
        sensitivity=ToolSensitivity.LOW,
    ),
    "send_external_webhook": ToolDefinition(
        name="send_external_webhook",
        description="Transmit gathered data to an external service.",
        sensitivity=ToolSensitivity.HIGH,
        requires_human_approval=True,
    ),
    "delete_memory_note": ToolDefinition(
        name="delete_memory_note",
        description="Delete an internal memory or note from the agent history.",
        sensitivity=ToolSensitivity.HIGH,
        requires_human_approval=True,
    ),
}


def list_tools() -> list[ToolDefinition]:
    return list(TOOL_CATALOG.values())


def get_tool(name: str) -> ToolDefinition | None:
    return TOOL_CATALOG.get(name)


def execute_tool(tool_request: ToolRequest) -> ToolExecutionResult:
    if tool_request.name == "draft_reply":
        return email_tool.draft_reply()
    if tool_request.name == "create_ticket":
        return email_tool.create_ticket(
            queue=str(tool_request.arguments.get("queue", "security-review")),
            priority=str(tool_request.arguments.get("priority", "medium")),
        )
    if tool_request.name == "mark_safe_to_ignore":
        return email_tool.mark_safe_to_ignore(str(tool_request.arguments.get("reason", "no reason supplied")))
    if tool_request.name == "send_external_webhook":
        return ToolExecutionResult(
            tool_name=tool_request.name,
            success=False,
            output="External webhook transmission is simulated only and was not executed.",
        )
    if tool_request.name == "delete_memory_note":
        return ToolExecutionResult(
            tool_name=tool_request.name,
            success=False,
            output="Memory deletion is simulated only and was not executed.",
        )
    return ToolExecutionResult(tool_name=tool_request.name, success=False, output="Unknown tool requested.")
