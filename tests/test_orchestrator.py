from __future__ import annotations

import asyncio
from pathlib import Path

from dual_llm_security.config import Settings
from dual_llm_security.models import ArchitectureMode
from dual_llm_security.runner import load_scenario, run_scenario


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_dual_mode_hides_raw_attack_markers_from_privileged_input() -> None:
    scenario = load_scenario(REPO_ROOT / "datasets" / "malicious_emails" / "hidden-prompt-injection.json")
    trace = asyncio.run(run_scenario(scenario, ArchitectureMode.DUAL, settings=Settings(RUN_MODE="replay")))
    privileged_input = trace.privileged_input.casefold()
    for marker in scenario.attack_markers:
        assert marker.casefold() not in privileged_input
    assert "instruction_override_attempt" in privileged_input


def test_single_mode_exposes_attack_markers_to_privileged_input() -> None:
    scenario = load_scenario(REPO_ROOT / "datasets" / "injected_html" / "confused-deputy-web-research.json")
    trace = asyncio.run(run_scenario(scenario, ArchitectureMode.SINGLE, settings=Settings(RUN_MODE="replay")))
    assert "send the partner dataset" in trace.privileged_input.casefold()
