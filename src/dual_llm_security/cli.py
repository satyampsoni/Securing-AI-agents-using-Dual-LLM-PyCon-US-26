from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from dual_llm_security.config import get_settings
from dual_llm_security.models import ArchitectureMode, RuntimeConfig
from dual_llm_security.runner import export_agent_trace, load_scenario, run_dataset, run_scenario, write_json, write_jsonl


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dual-llm-security", description="Run single or dual LLM security scenarios.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_case = subparsers.add_parser("run-case", help="Run one scenario file.")
    run_case.add_argument("--case", required=True, type=Path)
    run_case.add_argument("--mode", required=True, choices=[mode.value for mode in ArchitectureMode])
    run_case.add_argument("--output", type=Path)
    run_case.add_argument("--format", choices=["run-trace", "agent-trace"], default="run-trace")

    run_dataset_parser = subparsers.add_parser("run-dataset", help="Run all scenario files in a dataset directory.")
    run_dataset_parser.add_argument("--dataset", required=True, type=Path)
    run_dataset_parser.add_argument("--mode", required=True, choices=[mode.value for mode in ArchitectureMode])
    run_dataset_parser.add_argument("--output", required=True, type=Path)
    run_dataset_parser.add_argument("--format", choices=["run-trace", "agent-trace"], default="run-trace")

    return parser


async def _run_case(case: Path, mode: str, output: Path | None, fmt: str) -> int:
    trace = await run_scenario(
        load_scenario(case),
        ArchitectureMode(mode),
        runtime_config=RuntimeConfig(allow_sensitive_tools=get_settings().allow_sensitive_tools),
        settings=get_settings(),
    )
    payload = export_agent_trace(trace) if fmt == "agent-trace" else trace.model_dump(mode="json")
    if output:
        write_json(output, payload)
    else:
        print(json.dumps(payload, indent=2))
    return 0


async def _run_dataset(dataset: Path, mode: str, output: Path, fmt: str) -> int:
    traces = await run_dataset(
        dataset,
        ArchitectureMode(mode),
        runtime_config=RuntimeConfig(allow_sensitive_tools=get_settings().allow_sensitive_tools),
        settings=get_settings(),
    )
    rows = [export_agent_trace(trace) if fmt == "agent-trace" else trace.model_dump(mode="json") for trace in traces]
    write_jsonl(output, rows)
    return 0


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "run-case":
        return asyncio.run(_run_case(args.case, args.mode, args.output, args.format))
    if args.command == "run-dataset":
        return asyncio.run(_run_dataset(args.dataset, args.mode, args.output, args.format))
    parser.error("Unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
