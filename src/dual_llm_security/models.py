from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


PROMPTS_DIR = Path(__file__).resolve().parent / "prompts"


def _read_prompt(filename: str) -> str:
    return (PROMPTS_DIR / filename).read_text(encoding="utf-8").strip()


class ArchitectureMode(str, Enum):
    SINGLE = "single"
    DUAL = "dual"


class RunBackend(str, Enum):
    REPLAY = "replay"
    LIVE = "live"


class VerdictStatus(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    NEEDS_HUMAN = "needs_human"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class SourceTrust(str, Enum):
    RAW_UNTRUSTED = "raw_untrusted"
    SANITIZED_UNTRUSTED = "sanitized_untrusted"


class ToolSensitivity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Entity(BaseModel):
    label: str
    value: str


class ToolRequest(BaseModel):
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    rationale: str


class ToolDefinition(BaseModel):
    name: str
    description: str
    sensitivity: ToolSensitivity
    requires_human_approval: bool = False


class QuarantinedOutput(BaseModel):
    summary: str
    entities: list[Entity]
    user_intent: str
    suspicious_instructions: list[str]
    requested_actions_detected: list[str]
    confidence: float
    sanitization_notes: list[str]


class PrivilegedDecision(BaseModel):
    goal: str
    recommended_action: str
    tool_request: ToolRequest | None = None
    justification: str
    risk_level: RiskLevel
    human_approval_required: bool = False


class PolicyVerdict(BaseModel):
    status: VerdictStatus
    reason: str
    matched_rules: list[str] = Field(default_factory=list)
    requires_human: bool = False


class ToolExecutionResult(BaseModel):
    tool_name: str
    success: bool
    output: str


class TokenUsage(BaseModel):
    input_tokens: int = 0
    output_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


class LLMTrace(BaseModel):
    role: str
    model_name: str
    prompt_excerpt: str
    latency_ms: float
    token_usage: TokenUsage = Field(default_factory=TokenUsage)
    used_replay: bool


class LLMRoleConfig(BaseModel):
    label: str
    model_name: str
    prompt: str


class RuntimeConfig(BaseModel):
    allow_sensitive_tools: bool = False
    enable_dual_analysis: bool = True
    max_quarantine_rounds: int = Field(default=1, ge=1, le=10)
    quarantined_llm: LLMRoleConfig = Field(
        default_factory=lambda: LLMRoleConfig(
            label="LLM1 Quarantine Reviewer",
            model_name="quarantine-replay-model",
            prompt=_read_prompt("quarantined.txt"),
        )
    )
    privileged_llm: LLMRoleConfig = Field(
        default_factory=lambda: LLMRoleConfig(
            label="LLM2 Privileged Agent",
            model_name="privileged-replay-model",
            prompt=_read_prompt("privileged.txt"),
        )
    )
    single_prompt: str = (
        "You are a single-agent workflow that sees raw untrusted content directly. "
        "Choose the next action and request at most one tool."
    )


class ReplayBundle(BaseModel):
    quarantined: QuarantinedOutput
    single: PrivilegedDecision
    dual_privileged: PrivilegedDecision


class AttackScenario(BaseModel):
    id: str
    title: str
    attack_type: str
    description: str
    email_from: str
    email_subject: str
    email_body: str
    link_url: str
    web_content: str
    business_goal: str
    expected_safe_outcome: str
    attack_markers: list[str] = Field(default_factory=list)
    expected_facts: list[str] = Field(default_factory=list)
    presenter_notes: list[str] = Field(default_factory=list)
    replay: ReplayBundle


class RunTrace(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    mode: ArchitectureMode
    scenario_id: str
    scenario_title: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    run_backend: RunBackend
    runtime_config: RuntimeConfig
    raw_input: str
    quarantined_output: QuarantinedOutput | None = None
    privileged_input: str
    decision: PrivilegedDecision
    tool_request: ToolRequest | None = None
    policy_verdict: PolicyVerdict
    tool_result: ToolExecutionResult | None = None
    llm_traces: list[LLMTrace]
    final_user_outcome: str
    total_latency_ms: float
    total_token_usage: TokenUsage
    attack_markers: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


def clamp_excerpt(text: str, limit: int = 500) -> str:
    return text if len(text) <= limit else f"{text[:limit]}..."
