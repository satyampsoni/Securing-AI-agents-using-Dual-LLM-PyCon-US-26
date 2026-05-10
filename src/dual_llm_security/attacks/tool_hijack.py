from __future__ import annotations

from dual_llm_security.models import AttackScenario


def matches_tool_hijack(scenario: AttackScenario) -> bool:
    return any(marker for marker in scenario.attack_markers if "webhook" in marker or "ticket" in marker or "ignore" in marker)
