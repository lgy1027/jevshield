"""Run an opt-in real Jev evaluation of a multi-agent handoff flow.

Set JEV_API_KEY (or TYPESAFE_API_KEY / OPENROUTER_API_KEY) before running:
    python examples/07_live_multi_agent_handoff_eval.py
"""

from collections import Counter
import json

from jevshield import (
    HandoffAction,
    HandoffPolicy,
    HandoffTracker,
    JevClient,
    Route,
    Router,
)


ROUTES = {
    "research": Route(
        description="Research approved documentation and summarize relevant facts.",
        target="research",
    ),
    "coding": Route(
        description="Implement or inspect code changes after requirements are clear.",
        target="coding",
    ),
    "testing": Route(
        description="Validate behavior and report reproducible test results.",
        target="testing",
    ),
}

REQUESTS = (
    "Research the documented delivery policy before proposing an answer.",
    "Implement the approved delivery-policy presentation after research returns.",
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
    """Route twice through Jev while locally tracking an explicit return flow."""

    router = Router(ROUTES, client, min_confidence=0.7)
    tracker = HandoffTracker(
        HandoffPolicy(max_handoffs=3, max_repeated_handoffs=3)
    )
    route_statuses = Counter()
    handoff_actions = Counter()
    handoff_count = 0

    first = router.select({"request": REQUESTS[0]})
    route_statuses[first.status.value] += 1
    if first.route_key is None:
        return _report(route_statuses, handoff_actions, handoff_count)

    delegated = tracker.delegate("main", first.route_key)
    handoff_count = delegated.handoff_count
    handoff_actions[delegated.action.value] += 1
    if delegated.action is not HandoffAction.CONTINUE:
        return _report(route_statuses, handoff_actions, handoff_count)

    returned = tracker.return_to_parent(first.route_key, "main")
    handoff_count = returned.handoff_count
    handoff_actions[returned.action.value] += 1

    second = router.select({"request": REQUESTS[1]})
    route_statuses[second.status.value] += 1
    if second.route_key is None:
        return _report(route_statuses, handoff_actions, handoff_count)

    delegated = tracker.delegate("main", second.route_key)
    handoff_count = delegated.handoff_count
    handoff_actions[delegated.action.value] += 1
    return _report(route_statuses, handoff_actions, handoff_count)


def _report(route_statuses, handoff_actions, handoff_count):
    """Return aggregate-only data suitable for a live example's stdout."""

    return {
        "route_total": sum(route_statuses.values()),
        "route_status_counts": dict(sorted(route_statuses.items())),
        "handoff_action_counts": dict(sorted(handoff_actions.items())),
        "handoff_count": handoff_count,
    }


if __name__ == "__main__":
    live_client = require_live_client()
    try:
        print(json.dumps(run_live_evaluation(live_client), sort_keys=True))
    finally:
        live_client.close()
