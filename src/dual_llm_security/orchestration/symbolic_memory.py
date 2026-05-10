from __future__ import annotations

from pydantic import BaseModel, Field

from dual_llm_security.models import Entity, QuarantinedOutput


class SymbolicReference(BaseModel):
    key: str
    summary: str


class SymbolicMemory(BaseModel):
    references: list[SymbolicReference] = Field(default_factory=list)

    @classmethod
    def from_quarantined_output(cls, output: QuarantinedOutput) -> "SymbolicMemory":
        refs = [
            SymbolicReference(key=entity.label, summary=_sanitize_entity_summary(entity.label, entity.value))
            for entity in output.entities
        ]
        refs.append(SymbolicReference(key="intent", summary=output.user_intent))
        return cls(references=refs)

    def to_prompt_block(self) -> str:
        return "\n".join(f"- {reference.key}: {reference.summary}" for reference in self.references)


def _sanitize_entity_summary(label: str, value: str) -> str:
    lowered_label = label.casefold()
    lowered_value = value.casefold()
    if "external" in lowered_label or "url" in lowered_label or "webhook" in lowered_value:
        return "redacted_external_destination"
    if "authority" in lowered_label:
        return "unverified_third_party_authority"
    if "sensitive_action" in lowered_label:
        return "high_risk_action_reference"
    return value
