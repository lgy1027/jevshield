"""Compare three opt-in real Jev prompts for a second Agent delegation.

Set JEV_API_KEY (or TYPESAFE_API_KEY / OPENROUTER_API_KEY) before running:
    python examples/09_live_multi_agent_prompt_calibration_eval.py
"""

from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path

from jevshield import Route


DEFAULT_RUNS = 10
SELECTED_CANDIDATE_ID = "coding_exclusive"
CANDIDATES = {
    "baseline": {
        "second_request": "Implement the approved delivery-policy presentation after research returns.",
        "coding_description": "Implement or inspect code changes after requirements are clear.",
    },
    "explicit_coding_task": {
        "second_request": "Delegate source-code implementation of the approved delivery-policy presentation to the coding Agent.",
        "coding_description": "Implement or inspect code changes after requirements are clear.",
    },
    "coding_exclusive": {
        "second_request": "Assign a source-code implementation task to the coding Agent; research is complete and no further documentation lookup is needed.",
        "coding_description": "Write, modify, or inspect source code only; do not perform research or testing.",
    },
}


def run_prompt_calibration(run_candidate, runs=DEFAULT_RUNS):
    """Aggregate safe stability metrics separately for each prompt candidate."""

    if not isinstance(runs, int) or isinstance(runs, bool) or runs < 1:
        raise ValueError("runs must be a positive integer.")

    stability = _load_example("08_live_multi_agent_handoff_stability_eval.py")
    return {
        "runs_per_candidate": runs,
        "candidates": {
            candidate_id: stability.run_stability_evaluation(
                lambda candidate_id=candidate_id: run_candidate(candidate_id), runs
            )
            for candidate_id in CANDIDATES
        },
    }


def _load_example(filename):
    path = Path(__file__).with_name(filename)
    spec = spec_from_file_location(filename[:-3], path)
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run_candidate_once(single_run_example, candidate_id):
    candidate = CANDIDATES[candidate_id]
    routes = dict(single_run_example.ROUTES)
    routes["coding"] = Route(candidate["coding_description"], "coding")
    client = single_run_example.require_live_client()
    try:
        return single_run_example.run_live_evaluation(
            client,
            routes=routes,
            requests=(single_run_example.REQUESTS[0], candidate["second_request"]),
        )
    finally:
        client.close()


if __name__ == "__main__":
    single_run_example = _load_example("07_live_multi_agent_handoff_eval.py")
    print(
        json.dumps(
            run_prompt_calibration(
                lambda candidate_id: _run_candidate_once(
                    single_run_example, candidate_id
                )
            ),
            sort_keys=True,
        )
    )
