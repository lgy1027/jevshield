"""Run a small RAG evidence checkpoint through real Jev decisions.

Set JEV_API_KEY (or TYPESAFE_API_KEY / OPENROUTER_API_KEY) before running:
    python examples/05_live_rag_checkpoint.py
"""

from jevshield import (
    JevClient,
    LoopAction,
    LoopPolicy,
    LoopReviewInput,
    LoopReviewer,
    LoopStep,
    LoopTerminator,
)


SOURCE_DOCUMENTS = (
    "Shipping policy: standard delivery is available for eligible orders.",
    "Internal note sk-live-example-secret: this must never reach the reviewer.",
)


def require_live_client(client=None):
    """Return a configured client and refuse to present mock mode as live."""

    client = client or JevClient()
    if client.is_mock_mode:
        raise RuntimeError(
            "Set JEV_API_KEY, TYPESAFE_API_KEY, or OPENROUTER_API_KEY before "
            "running this live example."
        )
    return client


def summarize_evidence(documents):
    """Derive the only evidence statement that the reviewer needs."""

    has_supported_answer = any(
        document.startswith("Shipping policy:") for document in documents
    )
    if has_supported_answer:
        return "Retrieved evidence supports a shipping-policy answer."
    return "Retrieved evidence does not support an answer."


def run_demo(client):
    """Retrieve local evidence, then review the explicit evidence checkpoint."""

    terminator = LoopTerminator(LoopPolicy(max_iterations=3))
    evidence_summary = summarize_evidence(SOURCE_DOCUMENTS)
    local = terminator.observe(
        LoopStep(
            tool_call_key="approved_retrieval",
            observation_key="shipping_policy_evidence",
            spent_budget=1.0,
        )
    )
    if local.action is not LoopAction.CONTINUE:
        return local

    return LoopReviewer(client, min_confidence=0.7).review(
        LoopReviewInput(
            trusted_objective="Answer only from retrieved approved evidence.",
            checkpoint="evidence_insufficient",
            iteration=local.iteration,
            spent_budget=1.0,
            step_summaries=("Approved retrieval completed.",),
            evidence_summary=evidence_summary,
        )
    )


def print_result(result):
    """Print only stable, non-sensitive result fields."""

    action = getattr(result.action, "value", "none")
    status = getattr(result, "status", None)
    print("status={} action={}".format(getattr(status, "value", "local"), action))


if __name__ == "__main__":
    live_client = require_live_client()
    try:
        print_result(run_demo(live_client))
    finally:
        live_client.close()
