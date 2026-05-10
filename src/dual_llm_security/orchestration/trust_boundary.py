from __future__ import annotations

from dual_llm_security.models import PolicyVerdict, PrivilegedDecision, QuarantinedOutput, SourceTrust, VerdictStatus
from dual_llm_security.tools.sandbox import get_tool


class TrustBoundaryPolicy:
    def __init__(self, *, allow_sensitive_tools: bool) -> None:
        self.allow_sensitive_tools = allow_sensitive_tools

    def evaluate(self, source_trust: SourceTrust, decision: PrivilegedDecision) -> PolicyVerdict:
        if decision.tool_request is None:
            return PolicyVerdict(
                status=VerdictStatus.ALLOW,
                reason="No tool request was made.",
                matched_rules=["no_tool_request"],
            )

        tool = get_tool(decision.tool_request.name)
        if tool is None:
            return PolicyVerdict(
                status=VerdictStatus.BLOCK,
                reason="Requested tool is not in the approved catalog.",
                matched_rules=["unknown_tool"],
            )

        if tool.sensitivity.value == "high" and not self.allow_sensitive_tools:
            return PolicyVerdict(
                status=VerdictStatus.BLOCK,
                reason="Sensitive tools are disabled for this proof-of-concept.",
                matched_rules=["sensitive_tools_disabled"],
            )

        if source_trust == SourceTrust.RAW_UNTRUSTED and tool.requires_human_approval:
            return PolicyVerdict(
                status=VerdictStatus.BLOCK,
                reason="Privileged action came directly from raw untrusted content.",
                matched_rules=["raw_untrusted_sensitive_tool"],
                requires_human=True,
            )

        if decision.human_approval_required or tool.requires_human_approval:
            return PolicyVerdict(
                status=VerdictStatus.NEEDS_HUMAN,
                reason="A human must approve this action before execution.",
                matched_rules=["human_approval_gate"],
                requires_human=True,
            )

        if source_trust == SourceTrust.RAW_UNTRUSTED and decision.risk_level.value == "high":
            return PolicyVerdict(
                status=VerdictStatus.NEEDS_HUMAN,
                reason="High-risk reasoning based on raw untrusted input is routed to a human reviewer.",
                matched_rules=["raw_high_risk_review"],
                requires_human=True,
            )

        return PolicyVerdict(
            status=VerdictStatus.ALLOW,
            reason="The requested tool is within policy and can execute.",
            matched_rules=["approved_tool"],
        )


def sanitize_for_privileged_input(output: QuarantinedOutput) -> dict[str, object]:
    return {
        "summary": output.summary,
        "entities": [
            {
                "label": entity.label,
                "value": _sanitize_entity_value(entity.label, entity.value),
            }
            for entity in output.entities
        ],
        "user_intent": output.user_intent,
        "risk_labels": [
            _risk_label(item)
            for item in output.suspicious_instructions
        ],
        "requested_actions_detected": output.requested_actions_detected,
        "confidence": output.confidence,
        "sanitization_notes": output.sanitization_notes,
    }


def _risk_label(item: str) -> str:
    lowered = item.lower()
    if "ignore prior user requests" in lowered or "override" in lowered:
        return "instruction_override_attempt"
    if "mark" in lowered and "ignore" in lowered:
        return "silent_close_attempt"
    if "webhook" in lowered or "external" in lowered:
        return "external_exfiltration_attempt"
    if "delete" in lowered and "memory" in lowered:
        return "memory_mutation_attempt"
    if "false" in lowered or "no anomalies" in lowered:
        return "false_attestation_attempt"
    if "authority" in lowered or "authorized" in lowered:
        return "delegated_authority_claim"
    return "suspicious_instruction_detected"


def _sanitize_entity_value(label: str, value: str) -> str:
    lowered_label = label.casefold()
    lowered_value = value.casefold()
    if "external" in lowered_label or "url" in lowered_label or "webhook" in lowered_value:
        return "redacted_external_destination"
    if "authority" in lowered_label:
        return "unverified_third_party_authority"
    if "sensitive_action" in lowered_label:
        return "high_risk_action_reference"
    return value
