from app.config import Settings
from app.models import PolicyVerdict, PrivilegedDecision, SourceTrust, VerdictStatus
from app.tools import get_tool


class PolicyEngine:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def evaluate(self, source_trust: SourceTrust, decision: PrivilegedDecision) -> PolicyVerdict:
        if decision.tool_request is None:
            return PolicyVerdict(
                status=VerdictStatus.ALLOW,
                reason="No tool was requested, so the system can safely present the recommendation.",
                matched_rules=["no_tool_request"],
            )

        tool = get_tool(decision.tool_request.name)
        if tool is None:
            return PolicyVerdict(
                status=VerdictStatus.BLOCK,
                reason="The requested tool is not in the approved catalog.",
                matched_rules=["unknown_tool"],
            )

        if tool.sensitivity.value == "high" and not self.settings.allow_sensitive_tools:
            return PolicyVerdict(
                status=VerdictStatus.BLOCK,
                reason="Sensitive tools are disabled in the MVP, so exfiltration and memory mutation are blocked.",
                matched_rules=["sensitive_tools_disabled"],
            )

        if source_trust == SourceTrust.RAW_UNTRUSTED and tool.requires_human_approval:
            return PolicyVerdict(
                status=VerdictStatus.BLOCK,
                reason="Privileged action came directly from raw untrusted content and requires human approval.",
                matched_rules=["raw_untrusted_sensitive_tool"],
                requires_human=True,
            )

        if decision.human_approval_required or tool.requires_human_approval:
            return PolicyVerdict(
                status=VerdictStatus.NEEDS_HUMAN,
                reason="The action may be legitimate, but a human must approve it before execution.",
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
            reason="The requested tool is within the approved catalog and does not cross the policy thresholds.",
            matched_rules=["approved_tool"],
        )
