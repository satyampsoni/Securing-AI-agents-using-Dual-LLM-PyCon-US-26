from __future__ import annotations

from dual_llm_security.models import LLMTrace


def total_latency_ms(traces: list[LLMTrace]) -> float:
    return round(sum(trace.latency_ms for trace in traces), 2)
