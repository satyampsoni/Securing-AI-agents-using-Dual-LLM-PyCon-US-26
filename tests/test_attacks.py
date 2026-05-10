from __future__ import annotations

import asyncio
from pathlib import Path

from dual_llm_security.attacks.html_injection import matches_html_injection
from dual_llm_security.attacks.memory_poisoning import matches_memory_poisoning
from dual_llm_security.config import Settings
from dual_llm_security.models import ArchitectureMode
from dual_llm_security.runner import load_dataset, load_scenario, run_scenario


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_dataset_layout_loads_expected_scenarios() -> None:
    scenarios = load_dataset(REPO_ROOT / "datasets")
    ids = {scenario.id for scenario in scenarios}
    assert "hidden-prompt-injection" in ids
    assert "confused-deputy-web-research" in ids
    assert "lethal-trifecta-memory-exfiltration" in ids
    assert "benign-vendor-followup" in ids


def test_attack_helpers_match_expected_families() -> None:
    hidden = load_scenario(REPO_ROOT / "datasets" / "malicious_emails" / "hidden-prompt-injection.json")
    memory = load_scenario(REPO_ROOT / "datasets" / "memory_attacks" / "lethal-trifecta-memory-exfiltration.json")
    assert matches_html_injection(hidden) is True
    assert matches_memory_poisoning(memory) is True


def test_sensitive_tool_requests_are_not_executed() -> None:
    scenario = load_scenario(REPO_ROOT / "datasets" / "memory_attacks" / "lethal-trifecta-memory-exfiltration.json")
    trace = asyncio.run(run_scenario(scenario, ArchitectureMode.SINGLE, settings=Settings(RUN_MODE="replay")))
    assert trace.tool_request is not None
    assert trace.tool_request.name == "send_external_webhook"
    assert trace.policy_verdict.status.value == "block"
    assert trace.tool_result is None
