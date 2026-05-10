from __future__ import annotations

import asyncio
from pathlib import Path

from dual_llm_security.config import Settings
from dual_llm_security.models import ArchitectureMode
from dual_llm_security.runner import load_scenario, run_scenario


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_single_hidden_prompt_is_vulnerable_in_replay() -> None:
    scenario = load_scenario(REPO_ROOT / "datasets" / "malicious_emails" / "hidden-prompt-injection.json")
    trace = asyncio.run(run_scenario(scenario, ArchitectureMode.SINGLE, settings=Settings(RUN_MODE="replay")))
    assert trace.tool_request is not None
    assert trace.tool_request.name == "mark_safe_to_ignore"
    assert trace.policy_verdict.status.value == "allow"


def test_dual_hidden_prompt_routes_to_ticket() -> None:
    scenario = load_scenario(REPO_ROOT / "datasets" / "malicious_emails" / "hidden-prompt-injection.json")
    trace = asyncio.run(run_scenario(scenario, ArchitectureMode.DUAL, settings=Settings(RUN_MODE="replay")))
    assert trace.tool_request is not None
    assert trace.tool_request.name == "create_ticket"
    assert trace.policy_verdict.status.value == "allow"
    assert trace.quarantined_output is not None
    assert "ignore prior user requests" in trace.quarantined_output.suspicious_instructions
