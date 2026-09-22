import asyncio
from enum import Enum
import unittest

from jevshield.classify import IntentClassifier
from jevshield.runtime import ChoiceAnswer, DecisionStatus


class Intent(str, Enum):
    LOOK_UP_ORDER = "look_up_order"
    MODIFY_ORDER = "modify_order"


class ForeignIntent(str, Enum):
    LOOK_UP_ORDER = "look_up_order"
    MODIFY_ORDER = "modify_order"


class StubClient:
    def __init__(self, answer):
        self.answer = answer
        self.states = []
        self.questions = []

    def choose(self, state, question):
        self.states.append(state)
        self.questions.append(question)
        return self.answer

    async def achoose(self, state, question):
        return self.choose(state, question)


class TestIntentClassifier(unittest.TestCase):
    def _descriptions(self):
        return {
            Intent.LOOK_UP_ORDER: "Read order data without changing it.",
            Intent.MODIFY_ORDER: "Change an existing order.",
        }

    def test_returns_the_exact_enum_member(self):
        client = StubClient(ChoiceAnswer("modify_order", 0.91, DecisionStatus.RESOLVED, 4.0, "jev"))
        result = IntentClassifier(Intent, self._descriptions(), client).classify("Change order 1024")
        self.assertEqual(result.value, Intent.MODIFY_ORDER)
        self.assertEqual(result.status, DecisionStatus.RESOLVED)

    def test_low_confidence_becomes_uncertain_without_a_value(self):
        client = StubClient(ChoiceAnswer("modify_order", 0.40, DecisionStatus.RESOLVED, 4.0, "jev"))
        result = IntentClassifier(Intent, self._descriptions(), client, min_confidence=0.70).classify("Change order 1024")
        self.assertEqual(result.status, DecisionStatus.UNCERTAIN)
        self.assertIsNone(result.value)

    def test_input_is_redacted_before_it_reaches_client(self):
        client = StubClient(ChoiceAnswer("look_up_order", 0.91, DecisionStatus.RESOLVED, 4.0, "jev"))
        IntentClassifier(Intent, self._descriptions(), client).classify({"token": "sk-abcdefghijklmnopqrstuvwxyz123456"})
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz", client.states[0])
        self.assertIn("[REDACTED_SECRET]", client.states[0])

    def test_async_classification_returns_the_exact_enum_member(self):
        client = StubClient(ChoiceAnswer("look_up_order", 0.91, DecisionStatus.RESOLVED, 4.0, "jev"))
        result = asyncio.run(IntentClassifier(Intent, self._descriptions(), client).aclassify("Find order 1024"))
        self.assertEqual(result.value, Intent.LOOK_UP_ORDER)

    def test_rejects_raw_string_description_keys(self):
        descriptions = {
            "look_up_order": "Read order data without changing it.",
            "modify_order": "Change an existing order.",
        }

        with self.assertRaises(ValueError):
            IntentClassifier(Intent, descriptions, StubClient(None))

    def test_rejects_same_value_foreign_enum_description_keys(self):
        descriptions = {
            ForeignIntent.LOOK_UP_ORDER: "Read order data without changing it.",
            ForeignIntent.MODIFY_ORDER: "Change an existing order.",
        }

        with self.assertRaises(ValueError):
            IntentClassifier(Intent, descriptions, StubClient(None))
