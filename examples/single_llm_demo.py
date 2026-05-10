from __future__ import annotations

import asyncio
import json
from pathlib import Path

from dual_llm_security.models import ArchitectureMode
from dual_llm_security.runner import load_scenario, run_scenario


async def main() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    scenario = load_scenario(repo_root / "datasets" / "malicious_emails" / "hidden-prompt-injection.json")
    trace = await run_scenario(scenario, ArchitectureMode.SINGLE)
    print(json.dumps(trace.model_dump(mode="json"), indent=2))


if __name__ == "__main__":
    asyncio.run(main())
