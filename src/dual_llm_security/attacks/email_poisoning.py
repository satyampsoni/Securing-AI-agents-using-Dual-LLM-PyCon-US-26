from __future__ import annotations

from dual_llm_security.models import AttackScenario


def matches_email_poisoning(scenario: AttackScenario) -> bool:
    return "email" in scenario.attack_type or "prompt" in scenario.attack_type
