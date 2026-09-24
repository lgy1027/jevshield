"""Run a minimal framework-independent Agent flow without a Jev credential.

This demonstrates the default integration boundary: Router selects a role,
application code invokes that role, and Guard protects a simulated tool call.
Replace DemoRouterClient with JevClient(api_key="...") in an application.
"""

from jevshield import (
    ChoiceAnswer,
    DecisionStatus,
    DevelopmentPolicy,
    JevClient,
    Route,
    Router,
    guard,
)


class DemoRouterClient:
    """A deterministic local stand-in that keeps this first example runnable."""

    def __init__(self, route_key):
        self.route_key = route_key

    def choose(self, _state, _question):
        return ChoiceAnswer(
            self.route_key, 1.0, DecisionStatus.RESOLVED, 0.0, "local_demo"
        )

    async def achoose(self, state, question):
        return self.choose(state, question)


demo_guard_client = JevClient(api_key="")


def research_agent(_request):
    """A child role remains ordinary application code."""

    return "research: approved shipping-policy facts"


@guard(policy=DevelopmentPolicy(), client=demo_guard_client)
def simulate_save_answer(path, _content):
    """Simulate an application write; replace this body with real storage code."""

    return "simulated save: {}".format(path)


def coding_agent(_request):
    """A second child role invokes a protected tool at its execution boundary."""

    return simulate_save_answer("answer.md", "Approved shipping-policy answer.")


def dispatch_request(request, client):
    """Route once, then let application code explicitly invoke the target."""

    router = Router(
        {
            "research": Route("Find approved facts before drafting an answer.", research_agent),
            "coding": Route("Write an approved answer using known facts.", coding_agent),
        },
        client=client,
        min_confidence=0.7,
    )
    selection = router.select({"request": request})
    if selection.status is not DecisionStatus.RESOLVED or selection.target is None:
        return "route unavailable: {}".format(selection.status.value)
    return selection.target(request)


if __name__ == "__main__":
    print(dispatch_request("Find the shipping policy.", DemoRouterClient("research")))
    print(dispatch_request("Write the approved answer.", DemoRouterClient("coding")))
