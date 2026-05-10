"""CLI-first dual-LLM proof-of-concept that emits benchmarkable traces."""

from dual_llm_security.models import (
    ArchitectureMode,
    AttackScenario,
    LLMTrace,
    PolicyVerdict,
    PrivilegedDecision,
    QuarantinedOutput,
    RunTrace,
    RuntimeConfig,
    ToolRequest,
)
from dual_llm_security.runner import (
    export_agent_trace,
    load_dataset,
    load_scenario,
    run_dataset,
    run_scenario,
)

__all__ = [
    "ArchitectureMode",
    "AttackScenario",
    "LLMTrace",
    "PolicyVerdict",
    "PrivilegedDecision",
    "QuarantinedOutput",
    "RunTrace",
    "RuntimeConfig",
    "ToolRequest",
    "export_agent_trace",
    "load_dataset",
    "load_scenario",
    "run_dataset",
    "run_scenario",
]
