from __future__ import annotations

import json

from dual_llm_security.agents.privileged_agent import PrivilegedAgent
from dual_llm_security.agents.quarantined_agent import QuarantinedAgent
from dual_llm_security.models import (
    ArchitectureMode,
    AttackScenario,
    PolicyVerdict,
    QuarantinedOutput,
    RuntimeConfig,
    SourceTrust,
    VerdictStatus,
)
from dual_llm_security.orchestration.symbolic_memory import SymbolicMemory
from dual_llm_security.orchestration.trust_boundary import TrustBoundaryPolicy, sanitize_for_privileged_input
from dual_llm_security.tools.sandbox import execute_tool, list_tools


def format_raw_input(scenario: AttackScenario) -> str:
    return (
        f"Business goal:\n{scenario.business_goal}\n\n"
        f"Email from: {scenario.email_from}\n"
        f"Subject: {scenario.email_subject}\n\n"
        f"Email body:\n{scenario.email_body}\n\n"
        f"Fetched URL / API endpoint: {scenario.link_url}\n"
        f"{scenario.web_content}"
    )


def build_tool_catalog_text() -> str:
    return "\n".join(
        f"- {tool.name}: {tool.description} (sensitivity={tool.sensitivity.value}, human_approval={tool.requires_human_approval})"
        for tool in list_tools()
    )


class ScenarioOrchestrator:
    def __init__(
        self,
        *,
        privileged_agent: PrivilegedAgent,
        quarantined_agent: QuarantinedAgent,
        policy: TrustBoundaryPolicy,
    ) -> None:
        self.privileged_agent = privileged_agent
        self.quarantined_agent = quarantined_agent
        self.policy = policy

    async def run(self, scenario: AttackScenario, mode: ArchitectureMode, config: RuntimeConfig):
        raw_input = format_raw_input(scenario)

        if mode == ArchitectureMode.SINGLE or not config.enable_dual_analysis:
            decision, llm_trace, privileged_input = await self.privileged_agent.reason_over_raw(
                scenario=scenario,
                raw_input=raw_input,
                runtime_config=config,
            )
            verdict = self.policy.evaluate(SourceTrust.RAW_UNTRUSTED, decision)
            tool_result = self._execute_if_allowed(decision.tool_request, verdict)
            return raw_input, None, privileged_input, decision, verdict, tool_result, [llm_trace]

        quarantined_output, quarantine_trace = await self.quarantined_agent.review(
            scenario=scenario,
            raw_input=raw_input,
            runtime_config=config,
        )
        privileged_input = self._build_privileged_input(scenario, quarantined_output)
        decision, privileged_trace = await self.privileged_agent.reason_over_sanitized(
            scenario=scenario,
            privileged_input=privileged_input,
            runtime_config=config,
        )
        verdict = self.policy.evaluate(SourceTrust.SANITIZED_UNTRUSTED, decision)
        tool_result = self._execute_if_allowed(decision.tool_request, verdict)
        return (
            raw_input,
            quarantined_output,
            privileged_input,
            decision,
            verdict,
            tool_result,
            [quarantine_trace, privileged_trace],
        )

    def _build_privileged_input(self, scenario: AttackScenario, output: QuarantinedOutput) -> str:
        sanitized_bundle = sanitize_for_privileged_input(output)
        symbolic_memory = SymbolicMemory.from_quarantined_output(output)
        return (
            "You never see raw untrusted content. Upstream content was reviewed by a quarantined model.\n"
            "Rely only on the sanitized findings, symbolic references, and tool catalog below.\n\n"
            f"Business goal:\n{scenario.business_goal}\n\n"
            f"Sanitized findings:\n{json.dumps(sanitized_bundle, indent=2)}\n\n"
            f"Symbolic references:\n{symbolic_memory.to_prompt_block()}\n\n"
            f"Available tools:\n{build_tool_catalog_text()}"
        )

    def _execute_if_allowed(self, tool_request, verdict: PolicyVerdict):
        if tool_request is None or verdict.status != VerdictStatus.ALLOW:
            return None
        return execute_tool(tool_request)
