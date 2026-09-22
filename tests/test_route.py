import asyncio
import unittest

from jevshield.route import Route, Router
from jevshield.runtime import ChoiceAnswer, DecisionStatus


class StubClient:
    def __init__(self, answer):
        self.answer = answer

    def choose(self, state, question):
        return self.answer

    async def achoose(self, state, question):
        return self.choose(state, question)


class TestRouter(unittest.TestCase):
    def _routes(self, calls):
        def orders(message):
            calls.append(("orders", message))

        def human(message):
            calls.append(("human", message))

        return {
            "orders": Route("Order questions and order changes.", orders),
            "human": Route("Requests requiring a human operator.", human),
        }

    def test_selection_returns_registered_target_without_invoking_it(self):
        calls = []
        router = Router(self._routes(calls), StubClient(ChoiceAnswer("orders", 0.94, DecisionStatus.RESOLVED, 2.0, "jev")))
        selection = router.select("Where is order 1024?")
        self.assertEqual(selection.route_key, "orders")
        self.assertEqual(calls, [])
        self.assertIsNotNone(selection.target)

    def test_low_confidence_returns_uncertain_without_target(self):
        calls = []
        router = Router(self._routes(calls), StubClient(ChoiceAnswer("orders", 0.40, DecisionStatus.RESOLVED, 2.0, "jev")), min_confidence=0.70)
        selection = router.select("Where is order 1024?")
        self.assertEqual(selection.status, DecisionStatus.UNCERTAIN)
        self.assertIsNone(selection.target)

    def test_configured_fallback_is_explicit(self):
        calls = []
        router = Router(self._routes(calls), StubClient(ChoiceAnswer(None, 0.0, DecisionStatus.UNAVAILABLE, 2.0, "timeout")), fallback_key="human")
        selection = router.select("Where is order 1024?")
        self.assertEqual(selection.route_key, "human")
        self.assertEqual(selection.source, "configured_fallback")
        self.assertEqual(calls, [])

    def test_async_selection_returns_registered_target(self):
        calls = []
        router = Router(self._routes(calls), StubClient(ChoiceAnswer("human", 0.94, DecisionStatus.RESOLVED, 2.0, "jev")))
        selection = asyncio.run(router.aselect("I need help"))
        self.assertEqual(selection.route_key, "human")
