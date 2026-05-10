from __future__ import annotations

from dual_llm_security.models import AttackScenario


def matches_memory_poisoning(scenario: AttackScenario) -> bool:
    return "memory" in scenario.id or "memory" in scenario.attack_type
