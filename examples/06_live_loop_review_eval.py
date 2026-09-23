"""Run a small, opt-in real Jev evaluation of semantic loop checkpoints.

Set JEV_API_KEY (or TYPESAFE_API_KEY / OPENROUTER_API_KEY) before running:
    python examples/06_live_loop_review_eval.py
"""

from collections import Counter
import json

from jevshield import (
    JevClient,
    LoopPolicy,
    LoopReviewInput,
    LoopReviewer,
    LoopStep,
    LoopTerminator,
)


SCENARIOS = (
    (
        "agent_planning",
        "Answer a support request from approved catalog data.",
        "plan_after_catalog_lookup",
        ("A safe catalog lookup completed.",),
        None,
    ),
    (
        "rag_evidence_insufficient",
        "Answer only when retrieved evidence supports the answer.",
        "evidence_insufficient",
        ("Retrieval found no source supporting the requested claim.",),
        "Available evidence does not support an answer.",
    ),
    (
        "rag_evidence_conflict",
        "Answer only when retrieved evidence is consistent.",
        "evidence_conflict",
        ("Two approved sources disagree on the requested policy.",),
        "Retrieved evidence conflicts and needs resolution.",
    ),
)


def require_live_client(client=None):
    """Return a configured client and refuse to present mock mode as live."""

    client = client or JevClient()
    if client.is_mock_mode:
        raise RuntimeError(
            "Set JEV_API_KEY, TYPESAFE_API_KEY, or OPENROUTER_API_KEY before "
            "running this live evaluation."
        )
    return client


def run_live_evaluation(client):
    """Return safe aggregate counts for three real semantic checkpoints."""

    reviewer = LoopReviewer(client, min_confidence=0.7)
    status_counts = Counter()
    action_counts = Counter()
    for _, objective, checkpoint, summaries, evidence in SCENARIOS:
        decision = reviewer.review(
            LoopReviewInput(
                trusted_objective=objective,
                checkpoint=checkpoint,
                iteration=1,
                spent_budget=1.0,
                step_summaries=summaries,
                evidence_summary=evidence,
            )
        )
        status_counts[decision.status.value] += 1
        action_counts[decision.action.value if decision.action is not None else "none"] += 1

    local = LoopTerminator(LoopPolicy(max_iterations=1)).observe(
        LoopStep(tool_call_key="eval_control", observation_key="complete")
    )
    return {
        "semantic_total": len(SCENARIOS),
        "status_counts": dict(sorted(status_counts.items())),
        "action_counts": dict(sorted(action_counts.items())),
        "local_action": local.action.value,
    }


if __name__ == "__main__":
    live_client = require_live_client()
    try:
        print(json.dumps(run_live_evaluation(live_client), sort_keys=True))
    finally:
        live_client.close()
