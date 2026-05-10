from __future__ import annotations

from dual_llm_security.models import AttackScenario


def render_external_source(scenario: AttackScenario) -> str:
    return f"Fetched URL / API endpoint: {scenario.link_url}\n{scenario.web_content}"
