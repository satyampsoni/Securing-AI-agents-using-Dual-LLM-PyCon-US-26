from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from dual_llm_security.agents.base import build_model_gateway
from dual_llm_security.agents.privileged_agent import PrivilegedAgent
from dual_llm_security.agents.quarantined_agent import QuarantinedAgent
from dual_llm_security.config import Settings, get_settings
from dual_llm_security.models import ArchitectureMode, AttackScenario, RunTrace, RunBackend, RuntimeConfig
from dual_llm_security.orchestration.orchestrator import ScenarioOrchestrator
from dual_llm_security.orchestration.trust_boundary import TrustBoundaryPolicy
from dual_llm_security.utils.latency import total_latency_ms
from dual_llm_security.utils.token_usage import combine_token_usage


def load_scenario(path: str | Path) -> AttackScenario:
    scenario_path = Path(path)
    return AttackScenario.model_validate_json(scenario_path.read_text(encoding="utf-8"))


def load_dataset(path: str | Path) -> list[AttackScenario]:
    dataset_path = Path(path)
    if dataset_path.is_file():
        return [load_scenario(dataset_path)]
    return [load_scenario(item) for item in sorted(dataset_path.rglob("*.json"))]


async def run_scenario(
    scenario: AttackScenario,
    mode: ArchitectureMode,
    *,
    runtime_config: RuntimeConfig | None = None,
    settings: Settings | None = None,
) -> RunTrace:
    settings = settings or get_settings()
    runtime_config = runtime_config or RuntimeConfig(allow_sensitive_tools=settings.allow_sensitive_tools)

    gateway = build_model_gateway(settings)
    orchestrator = ScenarioOrchestrator(
        privileged_agent=PrivilegedAgent(gateway),
        quarantined_agent=QuarantinedAgent(gateway),
        policy=TrustBoundaryPolicy(allow_sensitive_tools=runtime_config.allow_sensitive_tools),
    )
    raw_input, quarantined_output, privileged_input, decision, verdict, tool_result, llm_traces = await orchestrator.run(
        scenario,
        mode,
        runtime_config,
    )

    final_outcome = _final_outcome(decision.recommended_action, verdict.status.value, verdict.reason, tool_result.output if tool_result else None)
    total_usage = combine_token_usage([trace.token_usage for trace in llm_traces])
    return RunTrace(
        mode=mode,
        scenario_id=scenario.id,
        scenario_title=scenario.title,
        run_backend=RunBackend.LIVE if settings.use_live_models else RunBackend.REPLAY,
        runtime_config=runtime_config,
        raw_input=raw_input,
        quarantined_output=quarantined_output,
        privileged_input=privileged_input,
        decision=decision,
        tool_request=decision.tool_request,
        policy_verdict=verdict,
        tool_result=tool_result,
        llm_traces=llm_traces,
        final_user_outcome=final_outcome,
        total_latency_ms=total_latency_ms(llm_traces),
        total_token_usage=total_usage,
        attack_markers=list(scenario.attack_markers),
        metadata={
            "attack_type": scenario.attack_type,
            "expected_safe_outcome": scenario.expected_safe_outcome,
            "expected_facts": scenario.expected_facts,
        },
    )


async def run_dataset(
    dataset: str | Path,
    mode: ArchitectureMode,
    *,
    runtime_config: RuntimeConfig | None = None,
    settings: Settings | None = None,
) -> list[RunTrace]:
    settings = settings or get_settings()
    traces: list[RunTrace] = []
    for scenario in load_dataset(dataset):
        traces.append(await run_scenario(scenario, mode, runtime_config=runtime_config, settings=settings))
    return traces


def export_agent_trace(trace: RunTrace) -> dict[str, Any]:
    return {
        "sample_id": trace.scenario_id,
        "raw_input": trace.raw_input,
        "privileged_input": trace.privileged_input,
        "quarantined_output": trace.quarantined_output.model_dump() if trace.quarantined_output is not None else None,
        "tool_request": trace.tool_request.model_dump() if trace.tool_request is not None else None,
        "policy_verdict": trace.policy_verdict.status.value,
        "final_outcome": trace.final_user_outcome,
        "latency_ms": trace.total_latency_ms,
        "metadata": {
            "mode": trace.mode.value,
            "scenario_title": trace.scenario_title,
            "run_backend": trace.run_backend.value,
            "decision": trace.decision.model_dump(),
            "policy_details": trace.policy_verdict.model_dump(),
            "llm_traces": [llm_trace.model_dump() for llm_trace in trace.llm_traces],
            "total_token_usage": trace.total_token_usage.model_dump(),
        },
    }


def write_json(path: str | Path, payload: dict[str, Any]) -> None:
    Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")


def write_jsonl(path: str | Path, rows: list[dict[str, Any]]) -> None:
    destination = Path(path)
    with destination.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row) + "\n")


def _final_outcome(recommended_action: str, verdict: str, reason: str, tool_output: str | None) -> str:
    if verdict == "block":
        return f"Blocked action. {reason}"
    if verdict == "needs_human":
        return f"Escalated for human approval. {recommended_action}"
    if tool_output:
        return f"{recommended_action} Result: {tool_output}"
    return recommended_action
