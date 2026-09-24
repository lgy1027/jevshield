"""Aggregate ten opt-in real Jev multi-agent handoff evaluations.

Set JEV_API_KEY (or TYPESAFE_API_KEY / OPENROUTER_API_KEY) before running:
    python examples/08_live_multi_agent_handoff_stability_eval.py
"""

from collections import Counter
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path


DEFAULT_RUNS = 10


def run_stability_evaluation(run_once, runs=DEFAULT_RUNS):
    """Aggregate safe metrics from repeated single-run live evaluations."""

    if not isinstance(runs, int) or isinstance(runs, bool) or runs < 1:
        raise ValueError("runs must be a positive integer.")

    route_statuses = Counter()
    handoff_actions = Counter()
    route_total = 0
    full_chain_count = 0
    expected_route_matches = 0
    for _ in range(runs):
        report = run_once()
        route_total += report["route_total"]
        route_statuses.update(report["route_status_counts"])
        handoff_actions.update(report["handoff_action_counts"])
        full_chain_count += int(report["full_chain_completed"])
        expected_route_matches += report["expected_route_matches"]

    return {
        "runs": runs,
        "route_total": route_total,
        "route_status_counts": dict(sorted(route_statuses.items())),
        "handoff_action_counts": dict(sorted(handoff_actions.items())),
        "full_chain_count": full_chain_count,
        "expected_route_matches": expected_route_matches,
    }


def _load_single_run_example():
    path = Path(__file__).with_name("07_live_multi_agent_handoff_eval.py")
    spec = spec_from_file_location("live_multi_agent_handoff_eval", path)
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run_once_with_fresh_live_client(example):
    client = example.require_live_client()
    try:
        return example.run_live_evaluation(client)
    finally:
        client.close()


if __name__ == "__main__":
    example = _load_single_run_example()
    print(
        json.dumps(
            run_stability_evaluation(
                lambda: _run_once_with_fresh_live_client(example)
            ),
            sort_keys=True,
        )
    )
