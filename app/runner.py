from __future__ import annotations

import json

from app.llm import LLMClient
from app.models import (
    InputBundle,
    PrivilegedDecision,
    QuarantinedOutput,
    RunMode,
    RunTrace,
    RuntimeConfig,
    Scenario,
    SourceTrust,
    TracePanel,
    VerdictStatus,
)
from app.policy import PolicyEngine
from app.tools import execute_tool, list_tools


def build_input_bundle(scenario: Scenario, input_override: InputBundle | None = None) -> InputBundle:
    if input_override is not None:
        return input_override
    return InputBundle(
        email_from=scenario.email_from,
        email_subject=scenario.email_subject,
        email_body=scenario.email_body,
        external_source_label="Fetched URL / API endpoint",
        external_source_ref=scenario.link_url,
        external_data=scenario.web_content,
        business_goal=scenario.business_goal,
    )


def format_raw_input(bundle: InputBundle) -> str:
    return (
        f"Business goal:\n{bundle.business_goal}\n\n"
        f"Email from: {bundle.email_from}\n"
        f"Subject: {bundle.email_subject}\n\n"
        f"Email body:\n{bundle.email_body}\n\n"
        f"{bundle.external_source_label}: {bundle.external_source_ref}\n"
        f"{bundle.external_data}"
    )


def build_tool_catalog_text() -> str:
    return "\n".join(
        f"- {tool.name}: {tool.description} (sensitivity={tool.sensitivity.value}, "
        f"human_approval={tool.requires_human_approval})"
        for tool in list_tools()
    )


def build_baseline_prompt(bundle: InputBundle, config: RuntimeConfig) -> str:
    return (
        f"{config.baseline_prompt}\n"
        "You are operating without quarantine, so the raw email and external content are visible below.\n"
        f"Available tools:\n{build_tool_catalog_text()}\n\n"
        f"{format_raw_input(bundle)}"
    )


def build_quarantine_prompt(bundle: InputBundle, config: RuntimeConfig) -> str:
    return (
        f"{config.quarantined_llm.prompt}\n"
        f"Maximum quarantine rounds available: {config.max_quarantine_rounds}.\n"
        "This MVP performs a single quarantined analysis pass before handing structured findings to the privileged agent.\n\n"
        f"{format_raw_input(bundle)}"
    )


def build_privileged_prompt(bundle: InputBundle, quarantine_output: QuarantinedOutput, config: RuntimeConfig) -> str:
    sanitized = json.dumps(quarantine_output.model_dump(), indent=2)
    return (
        f"{config.privileged_llm.prompt}\n"
        "You never see raw untrusted content. Upstream data is sanitized and may be incomplete.\n"
        "Rely only on the structured summary and policy-aware tool descriptions below.\n\n"
        f"Business goal:\n{bundle.business_goal}\n\n"
        f"Sanitized input:\n{sanitized}\n\n"
        f"Available tools:\n{build_tool_catalog_text()}"
    )


class ScenarioRunner:
    def __init__(self, llm_client: LLMClient, policy_engine: PolicyEngine, backend_name: str) -> None:
        self.llm_client = llm_client
        self.policy_engine = policy_engine
        self.backend_name = backend_name

    async def run(
        self,
        scenario: Scenario,
        mode: RunMode,
        *,
        runtime_config: RuntimeConfig | None = None,
        input_override: InputBundle | None = None,
    ) -> RunTrace:
        runtime_config = runtime_config or RuntimeConfig()
        input_bundle = build_input_bundle(scenario, input_override=input_override)
        raw_input = format_raw_input(input_bundle)
        notes = list(scenario.presenter_notes)
        if runtime_config.max_quarantine_rounds > 1:
            notes.append(
                f"MVP note: configured for up to {runtime_config.max_quarantine_rounds} quarantine rounds; the current demo executes one pass before LLM2."
            )

        effective_mode = mode
        if not runtime_config.enable_dual_analysis and mode == RunMode.DUAL:
            effective_mode = RunMode.BASELINE
            notes.append("Dual analysis was disabled in the configuration, so the request ran through the baseline path.")

        if effective_mode == RunMode.BASELINE:
            prompt = build_baseline_prompt(input_bundle, runtime_config)
            decision, decision_trace = await self.llm_client.generate_privileged_decision(
                scenario,
                prompt,
                baseline=True,
                model_name_override=runtime_config.privileged_llm.model_name,
            )
            policy = self.policy_engine.evaluate(SourceTrust.RAW_UNTRUSTED, decision)
            tool_result = self._execute_if_allowed(decision, policy)
            outcome = self._final_outcome(decision, policy, tool_result)
            panels = self._build_panels(
                mode=effective_mode,
                raw_input=raw_input,
                privileged_input=prompt,
                decision=decision,
                policy_reason=policy.reason,
                tool_result=tool_result.output if tool_result else "No tool executed.",
                quarantined_output=None,
                runtime_config=runtime_config,
            )
            return RunTrace(
                mode=effective_mode,
                scenario_id=scenario.id,
                scenario_title=scenario.title,
                run_backend=self.backend_name,
                runtime_config=runtime_config,
                raw_input=raw_input,
                privileged_input=prompt,
                decision=decision,
                policy_verdict=policy,
                tool_result=tool_result,
                llm_traces=[decision_trace],
                final_user_outcome=outcome,
                trace_panels=panels,
                notes=notes,
            )

        quarantine_prompt = build_quarantine_prompt(input_bundle, runtime_config)
        quarantined_output, quarantine_trace = await self.llm_client.generate_quarantined_output(
            scenario,
            quarantine_prompt,
            model_name_override=runtime_config.quarantined_llm.model_name,
        )
        privileged_prompt = build_privileged_prompt(input_bundle, quarantined_output, runtime_config)
        decision, decision_trace = await self.llm_client.generate_privileged_decision(
            scenario,
            privileged_prompt,
            baseline=False,
            model_name_override=runtime_config.privileged_llm.model_name,
        )
        policy = self.policy_engine.evaluate(SourceTrust.SANITIZED_UNTRUSTED, decision)
        tool_result = self._execute_if_allowed(decision, policy)
        outcome = self._final_outcome(decision, policy, tool_result)
        panels = self._build_panels(
            mode=effective_mode,
            raw_input=raw_input,
            privileged_input=privileged_prompt,
            decision=decision,
            policy_reason=policy.reason,
            tool_result=tool_result.output if tool_result else "No tool executed.",
            quarantined_output=quarantined_output,
            runtime_config=runtime_config,
        )
        return RunTrace(
            mode=effective_mode,
            scenario_id=scenario.id,
            scenario_title=scenario.title,
            run_backend=self.backend_name,
            runtime_config=runtime_config,
            raw_input=raw_input,
            quarantined_output=quarantined_output,
            privileged_input=privileged_prompt,
            decision=decision,
            policy_verdict=policy,
            tool_result=tool_result,
            llm_traces=[quarantine_trace, decision_trace],
            final_user_outcome=outcome,
            trace_panels=panels,
            notes=notes,
        )

    def _execute_if_allowed(self, decision: PrivilegedDecision, policy_status) -> object | None:
        if decision.tool_request is None:
            return None
        if policy_status.status != VerdictStatus.ALLOW:
            return None
        return execute_tool(decision.tool_request)

    def _final_outcome(self, decision: PrivilegedDecision, policy_status, tool_result) -> str:
        if policy_status.status == VerdictStatus.BLOCK:
            return f"Blocked tool request: {policy_status.reason}"
        if policy_status.status == VerdictStatus.NEEDS_HUMAN:
            return f"Escalated for human approval: {policy_status.reason}"
        if tool_result is None:
            return decision.recommended_action
        return f"{decision.recommended_action} Result: {tool_result.output}"

    def _build_panels(
        self,
        *,
        mode: RunMode,
        raw_input: str,
        privileged_input: str,
        decision: PrivilegedDecision,
        policy_reason: str,
        tool_result: str,
        quarantined_output: QuarantinedOutput | None,
        runtime_config: RuntimeConfig,
    ) -> list[TracePanel]:
        return [
            TracePanel(title="Runtime Configuration", content=runtime_config.model_dump()),
            TracePanel(title="Raw Input", content=raw_input),
            TracePanel(
                title="LLM1 Structured Findings",
                content=quarantined_output.model_dump() if quarantined_output else {
                    "status": "not_used",
                    "note": "Baseline mode exposes the privileged model directly to raw input.",
                },
            ),
            TracePanel(title="LLM2 Reasoning Input", content=privileged_input),
            TracePanel(
                title="Requested Action",
                content={
                    "mode": mode.value,
                    "recommended_action": decision.recommended_action,
                    "tool_request": decision.tool_request.model_dump() if decision.tool_request else None,
                    "risk_level": decision.risk_level.value,
                    "human_approval_required": decision.human_approval_required,
                },
            ),
            TracePanel(
                title="Final Policy Decision",
                content={
                    "policy_reason": policy_reason,
                    "tool_result": tool_result,
                },
            ),
        ]
