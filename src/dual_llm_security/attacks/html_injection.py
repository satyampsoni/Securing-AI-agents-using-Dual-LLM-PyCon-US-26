from __future__ import annotations

from dual_llm_security.models import AttackScenario


def matches_html_injection(scenario: AttackScenario) -> bool:
    return scenario.attack_type == "hidden_prompt_injection"
