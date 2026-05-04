from app.models import RunTrace


class RunStore:
    def __init__(self) -> None:
        self._runs: dict[str, RunTrace] = {}

    def save(self, run: RunTrace) -> RunTrace:
        self._runs[run.id] = run
        return run

    def get(self, run_id: str) -> RunTrace:
        return self._runs[run_id]
