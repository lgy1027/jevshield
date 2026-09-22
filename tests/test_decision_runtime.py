import math
import unittest

from jevshield.redaction import build_decision_state
from jevshield.runtime import ChoiceAnswer, ChoiceQuestion, DecisionStatus


class TestDecisionState(unittest.TestCase):
    def test_state_is_passive_json_and_redacts_credentials(self):
        state = build_decision_state({"token": "sk-abcdefghijklmnopqrstuvwxyz123456"})
        self.assertIn("passive data", state)
        self.assertIn("[REDACTED_SECRET]", state)
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz", state)

    def test_state_is_bounded_without_using_user_repr(self):
        class Unsafe:
            def __repr__(self):
                raise AssertionError("repr must not run")

        state = build_decision_state({"unsafe": Unsafe()}, max_chars=80)
        self.assertLessEqual(len(state), 80)
        self.assertIn("passive data", state)


class TestRuntimeContracts(unittest.TestCase):
    def test_resolved_choice_requires_known_value_and_bounded_numbers(self):
        answer = ChoiceAnswer(
            value="orders",
            confidence=0.91,
            status=DecisionStatus.RESOLVED,
            latency_ms=12.0,
            source="jev",
        )
        self.assertEqual(answer.value, "orders")

        with self.assertRaises(ValueError):
            ChoiceAnswer(None, 0.9, DecisionStatus.RESOLVED, 1.0, "jev")
        with self.assertRaises(ValueError):
            ChoiceAnswer("orders", math.nan, DecisionStatus.RESOLVED, 1.0, "jev")

    def test_question_rejects_empty_or_invalid_criteria(self):
        with self.assertRaises(ValueError):
            ChoiceQuestion("", "Route this request", {"orders": "Orders"})
        with self.assertRaises(ValueError):
            ChoiceQuestion("route", "", {"orders": "Orders"})
        with self.assertRaises(ValueError):
            ChoiceQuestion("route", "Route this request", {"": "Orders"})
