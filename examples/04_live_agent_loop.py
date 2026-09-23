"""Run a small guarded Agent loop through real Jev decisions.

Set JEV_API_KEY (or TYPESAFE_API_KEY / OPENROUTER_API_KEY) before running:
    python examples/04_live_agent_loop.py
"""

from jevshield import (
    JevClient,
    LoopAction,
    LoopPolicy,
    LoopReviewInput,
    LoopReviewer,
    LoopStep,
    LoopTerminator,
    ProductionPolicy,
    guard,
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


def run_demo(client):
    """Run one safe tool step, then review the explicit planning checkpoint."""

    @guard(policy=ProductionPolicy(), client=client)
    def search_approved_catalog(topic):
        """Read the approved product catalog for a customer-support topic."""

        return "The catalog contains a shipping-policy article."

    terminator = LoopTerminator(LoopPolicy(max_iterations=3))
    observation = search_approved_catalog("shipping policy")
    local = terminator.observe(
        LoopStep(
            tool_call_key="catalog_lookup",
            observation_key="catalog_shipping_policy",
            spent_budget=1.0,
        )
    )
    if local.action is not LoopAction.CONTINUE:
        return local

    return LoopReviewer(client, min_confidence=0.7).review(
        LoopReviewInput(
            trusted_objective="Answer a shipping-policy question from approved data.",
            checkpoint="plan_after_catalog_lookup",
            iteration=local.iteration,
            spent_budget=1.0,
            step_summaries=("Catalog lookup completed.", observation),
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
