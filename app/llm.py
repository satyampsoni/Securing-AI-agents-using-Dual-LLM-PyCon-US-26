from __future__ import annotations

import json
from pathlib import Path
from time import perf_counter
from typing import Any

import httpx
from pydantic import BaseModel

from app.config import Settings
from app.models import LLMTrace, PrivilegedDecision, QuarantinedOutput, Scenario, estimate_tokens


def clamp_excerpt(text: str, limit: int = 500) -> str:
    return text if len(text) <= limit else f"{text[:limit]}..."


class LLMClient:
    async def generate_quarantined_output(
        self,
        scenario: Scenario,
        prompt: str,
        *,
        model_name_override: str | None = None,
    ) -> tuple[QuarantinedOutput, LLMTrace]:
        raise NotImplementedError

    async def generate_privileged_decision(
        self,
        scenario: Scenario,
        prompt: str,
        *,
        baseline: bool,
        model_name_override: str | None = None,
    ) -> tuple[PrivilegedDecision, LLMTrace]:
        raise NotImplementedError


class ReplayLLMClient(LLMClient):
    def __init__(self, replay_dir: Path, settings: Settings) -> None:
        self.replay_dir = replay_dir
        self.settings = settings

    def _load_fixture(self, scenario_id: str) -> dict[str, Any]:
        path = self.replay_dir / f"{scenario_id}.json"
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    async def generate_quarantined_output(
        self,
        scenario: Scenario,
        prompt: str,
        *,
        model_name_override: str | None = None,
    ) -> tuple[QuarantinedOutput, LLMTrace]:
        started = perf_counter()
        payload = self._load_fixture(scenario.id)["quarantined"]
        model = QuarantinedOutput.model_validate(payload)
        latency_ms = round((perf_counter() - started) * 1000, 2)
        trace = LLMTrace(
            role="quarantined",
            model_name=model_name_override or self.settings.quarantined_model_name,
            prompt_excerpt=clamp_excerpt(prompt),
            latency_ms=latency_ms,
            used_replay=True,
            token_estimate=estimate_tokens(prompt, model.model_dump_json()),
        )
        return model, trace

    async def generate_privileged_decision(
        self,
        scenario: Scenario,
        prompt: str,
        *,
        baseline: bool,
        model_name_override: str | None = None,
    ) -> tuple[PrivilegedDecision, LLMTrace]:
        started = perf_counter()
        fixture = self._load_fixture(scenario.id)
        key = "baseline" if baseline else "dual_privileged"
        model = PrivilegedDecision.model_validate(fixture[key])
        latency_ms = round((perf_counter() - started) * 1000, 2)
        trace = LLMTrace(
            role="baseline" if baseline else "privileged",
            model_name=model_name_override or self.settings.privileged_model_name,
            prompt_excerpt=clamp_excerpt(prompt),
            latency_ms=latency_ms,
            used_replay=True,
            token_estimate=estimate_tokens(prompt, model.model_dump_json()),
        )
        return model, trace


class LiveOpenAICompatibleClient(LLMClient):
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def generate_quarantined_output(
        self,
        scenario: Scenario,
        prompt: str,
        *,
        model_name_override: str | None = None,
    ) -> tuple[QuarantinedOutput, LLMTrace]:
        return await self._call_role(
            prompt=prompt,
            schema=QuarantinedOutput,
            model_name=model_name_override or self.settings.quarantined_model_name,
            base_url=self.settings.quarantined_base_url,
            api_key=self.settings.quarantined_api_key,
            trace_role="quarantined",
        )

    async def generate_privileged_decision(
        self,
        scenario: Scenario,
        prompt: str,
        *,
        baseline: bool,
        model_name_override: str | None = None,
    ) -> tuple[PrivilegedDecision, LLMTrace]:
        return await self._call_role(
            prompt=prompt,
            schema=PrivilegedDecision,
            model_name=model_name_override or self.settings.privileged_model_name,
            base_url=self.settings.privileged_base_url,
            api_key=self.settings.privileged_api_key,
            trace_role="baseline" if baseline else "privileged",
        )

    async def _call_role(
        self,
        *,
        prompt: str,
        schema: type[BaseModel],
        model_name: str,
        base_url: str | None,
        api_key: str | None,
        trace_role: str,
    ) -> tuple[Any, LLMTrace]:
        if not base_url or not api_key:
            raise RuntimeError(f"Live mode requires configured credentials for role {trace_role}.")

        system_prompt = (
            "You are a security demo model. Return strictly valid JSON matching the requested schema and do not "
            "include markdown fences or explanatory prose."
        )
        user_prompt = (
            f"{prompt}\n\n"
            f"JSON schema:\n{json.dumps(schema.model_json_schema(), indent=2)}"
        )

        payload = {
            "model": model_name,
            "temperature": 0.1,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }

        headers = {"Authorization": f"Bearer {api_key}"}
        endpoint = base_url.rstrip("/") + "/chat/completions"

        last_error: Exception | None = None
        for _attempt in range(2):
            started = perf_counter()
            async with httpx.AsyncClient(timeout=self.settings.default_timeout_seconds) as client:
                response = await client.post(endpoint, json=payload, headers=headers)
                response.raise_for_status()
            latency_ms = round((perf_counter() - started) * 1000, 2)
            content = response.json()["choices"][0]["message"]["content"]
            try:
                parsed = schema.model_validate_json(content)
                trace = LLMTrace(
                    role=trace_role,
                    model_name=model_name,
                    prompt_excerpt=clamp_excerpt(prompt),
                    latency_ms=latency_ms,
                    used_replay=False,
                    token_estimate=estimate_tokens(prompt, content),
                )
                return parsed, trace
            except Exception as exc:  # pragma: no cover - exercised through retry logic design
                last_error = exc

        raise RuntimeError(f"Failed to parse live model output for role {trace_role}: {last_error}") from last_error


def build_llm_client(settings: Settings) -> LLMClient:
    if settings.use_live_models:
        return LiveOpenAICompatibleClient(settings)
    return ReplayLLMClient(settings.replay_dir, settings)
