from __future__ import annotations

import json
from time import perf_counter
from typing import Any

import httpx
from pydantic import BaseModel

from dual_llm_security.config import Settings
from dual_llm_security.models import AttackScenario, LLMTrace, PrivilegedDecision, QuarantinedOutput, clamp_excerpt
from dual_llm_security.utils.token_usage import build_token_usage


class ModelGateway:
    async def generate_quarantined_output(
        self,
        scenario: AttackScenario,
        prompt: str,
        *,
        model_name_override: str | None = None,
    ) -> tuple[QuarantinedOutput, LLMTrace]:
        raise NotImplementedError

    async def generate_privileged_decision(
        self,
        scenario: AttackScenario,
        prompt: str,
        *,
        dual_mode: bool,
        model_name_override: str | None = None,
    ) -> tuple[PrivilegedDecision, LLMTrace]:
        raise NotImplementedError


class ReplayModelGateway(ModelGateway):
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def generate_quarantined_output(
        self,
        scenario: AttackScenario,
        prompt: str,
        *,
        model_name_override: str | None = None,
    ) -> tuple[QuarantinedOutput, LLMTrace]:
        started = perf_counter()
        payload = scenario.replay.quarantined
        latency_ms = round((perf_counter() - started) * 1000, 2)
        trace = LLMTrace(
            role="quarantined",
            model_name=model_name_override or self.settings.quarantined_model_name,
            prompt_excerpt=clamp_excerpt(prompt),
            latency_ms=latency_ms,
            token_usage=build_token_usage(prompt, payload.model_dump_json()),
            used_replay=True,
        )
        return payload, trace

    async def generate_privileged_decision(
        self,
        scenario: AttackScenario,
        prompt: str,
        *,
        dual_mode: bool,
        model_name_override: str | None = None,
    ) -> tuple[PrivilegedDecision, LLMTrace]:
        started = perf_counter()
        payload = scenario.replay.dual_privileged if dual_mode else scenario.replay.single
        latency_ms = round((perf_counter() - started) * 1000, 2)
        trace = LLMTrace(
            role="privileged" if dual_mode else "single",
            model_name=model_name_override or self.settings.privileged_model_name,
            prompt_excerpt=clamp_excerpt(prompt),
            latency_ms=latency_ms,
            token_usage=build_token_usage(prompt, payload.model_dump_json()),
            used_replay=True,
        )
        return payload, trace


class OpenAICompatibleGateway(ModelGateway):
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def generate_quarantined_output(
        self,
        scenario: AttackScenario,
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
        scenario: AttackScenario,
        prompt: str,
        *,
        dual_mode: bool,
        model_name_override: str | None = None,
    ) -> tuple[PrivilegedDecision, LLMTrace]:
        return await self._call_role(
            prompt=prompt,
            schema=PrivilegedDecision,
            model_name=model_name_override or self.settings.privileged_model_name,
            base_url=self.settings.privileged_base_url,
            api_key=self.settings.privileged_api_key,
            trace_role="privileged" if dual_mode else "single",
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
            "Return only valid JSON matching the requested schema. "
            "Do not include markdown fences or explanatory prose."
        )
        user_prompt = f"{prompt}\n\nJSON schema:\n{json.dumps(schema.model_json_schema(), indent=2)}"
        payload = {
            "model": model_name,
            "temperature": 0.1,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        endpoint = base_url.rstrip("/") + "/chat/completions"
        headers = {"Authorization": f"Bearer {api_key}"}

        started = perf_counter()
        async with httpx.AsyncClient(timeout=self.settings.default_timeout_seconds) as client:
            response = await client.post(endpoint, json=payload, headers=headers)
            response.raise_for_status()
        latency_ms = round((perf_counter() - started) * 1000, 2)
        content = response.json()["choices"][0]["message"]["content"]
        parsed = schema.model_validate_json(content)
        trace = LLMTrace(
            role=trace_role,
            model_name=model_name,
            prompt_excerpt=clamp_excerpt(prompt),
            latency_ms=latency_ms,
            token_usage=build_token_usage(prompt, content),
            used_replay=False,
        )
        return parsed, trace


def build_model_gateway(settings: Settings) -> ModelGateway:
    if settings.use_live_models:
        return OpenAICompatibleGateway(settings)
    return ReplayModelGateway(settings)
