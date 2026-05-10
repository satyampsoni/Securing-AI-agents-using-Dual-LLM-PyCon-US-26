from __future__ import annotations

from dual_llm_security.agents.base import ModelGateway
from dual_llm_security.models import AttackScenario, RuntimeConfig


class PrivilegedAgent:
    def __init__(self, gateway: ModelGateway) -> None:
        self.gateway = gateway

    async def reason_over_raw(self, *, scenario: AttackScenario, raw_input: str, runtime_config: RuntimeConfig):
        prompt = (
            f"{runtime_config.single_prompt}\n"
            f"Available tools:\n{self._tool_instructions()}\n\n"
            f"{raw_input}"
        )
        decision, trace = await self.gateway.generate_privileged_decision(
            scenario,
            prompt,
            dual_mode=False,
            model_name_override=runtime_config.privileged_llm.model_name,
        )
        return decision, trace, prompt

    async def reason_over_sanitized(
        self,
        *,
        scenario: AttackScenario,
        privileged_input: str,
        runtime_config: RuntimeConfig,
    ):
        prompt = f"{runtime_config.privileged_llm.prompt}\n\n{privileged_input}"
        return await self.gateway.generate_privileged_decision(
            scenario,
            prompt,
            dual_mode=True,
            model_name_override=runtime_config.privileged_llm.model_name,
        )

    def _tool_instructions(self) -> str:
        return (
            "- draft_reply\n"
            "- create_ticket\n"
            "- mark_safe_to_ignore\n"
            "- send_external_webhook\n"
            "- delete_memory_note"
        )
