from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from dual_llm_security.models import ArchitectureMode
from dual_llm_security.runner import export_agent_trace, load_scenario, run_scenario


def add_local_benchmark_package(repo_root: Path) -> None:
    bench_src = repo_root / "dual-llm-bench" / "src"
    if bench_src.exists() and str(bench_src) not in sys.path:
        sys.path.insert(0, str(bench_src))


async def main() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    add_local_benchmark_package(repo_root)

    from dual_llm_bench import BenchmarkSuite, built_in_metrics

    scenario_paths = [
        repo_root / "datasets" / "malicious_emails" / "hidden-prompt-injection.json",
        repo_root / "datasets" / "injected_html" / "confused-deputy-web-research.json",
        repo_root / "datasets" / "memory_attacks" / "lethal-trifecta-memory-exfiltration.json",
    ]

    single_traces = []
    dual_traces = []
    for path in scenario_paths:
        scenario = load_scenario(path)
        single_traces.append(export_agent_trace(await run_scenario(scenario, ArchitectureMode.SINGLE)))
        dual_traces.append(export_agent_trace(await run_scenario(scenario, ArchitectureMode.DUAL)))

    suite = BenchmarkSuite.from_builtin("pycon-core")
    metrics = built_in_metrics()
    single_report = suite.score_traces(single_traces, metrics=metrics)
    dual_report = suite.score_traces(dual_traces, metrics=metrics)

    print(json.dumps({"single": single_report.metric_scores(), "dual": dual_report.metric_scores()}, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
