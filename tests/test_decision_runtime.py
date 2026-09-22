import asyncio
import math
import unittest
from unittest import mock

import httpx

from jevshield.client import JevClient
from jevshield.redaction import build_decision_state
from jevshield.runtime import ChoiceAnswer, ChoiceQuestion, DecisionStatus


class FakeResponse:
    def __init__(self, status_code, json_data=None):
        self.status_code = status_code
        self._json_data = json_data or {}

    def json(self):
        return self._json_data


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


class TestJevChoiceExecution(unittest.TestCase):
    def _client(self):
        client = JevClient(api_key="test-key", backend="typesafe")
        client.is_mock_mode = False
        client._http_client = mock.Mock()
        return client

    def _question(self):
        return ChoiceQuestion("route", "Choose the correct route.", {
            "orders": "Order questions.", "knowledge": "Knowledge questions.",
        })

    def test_choose_builds_generic_choice_payload_and_parses_answer(self):
        client = self._client()
        client._http_client.post.return_value = FakeResponse(200, {"answers": {
            "route": {"type": "choice", "choice": "orders", "confidence": 0.92}
        }})

        answer = client.choose("passive request", self._question())

        self.assertEqual(answer.status, DecisionStatus.RESOLVED)
        self.assertEqual(answer.value, "orders")
        payload = client._http_client.post.call_args.kwargs["json"]
        self.assertEqual(payload["questions"]["route"]["criteria"]["orders"], "Order questions.")

    def test_choose_returns_uncertain_for_unknown_choice(self):
        client = self._client()
        client._http_client.post.return_value = FakeResponse(200, {"answers": {
            "route": {"type": "choice", "choice": "unknown", "confidence": 0.92}
        }})

        answer = client.choose("passive request", self._question())

        self.assertEqual(answer.status, DecisionStatus.UNCERTAIN)
        self.assertIsNone(answer.value)

    def test_choose_returns_unavailable_on_timeout_without_heuristic_fallback(self):
        client = self._client()
        client._http_client.post.side_effect = httpx.ReadTimeout("slow")

        answer = client.choose("passive request", self._question())

        self.assertEqual(answer.status, DecisionStatus.UNAVAILABLE)
        self.assertEqual(answer.source, "timeout")

    def test_achoose_has_the_same_resolved_result(self):
        client = JevClient(api_key="test-key", backend="typesafe")
        client.is_mock_mode = False
        client._async_http_client = mock.Mock(is_closed=False)
        client._async_http_client.post = mock.AsyncMock(return_value=FakeResponse(200, {"answers": {
            "route": {"type": "choice", "selected": "knowledge", "confidence": 0.88}
        }}))

        answer = asyncio.run(client.achoose("passive request", self._question()))

        self.assertEqual(answer.status, DecisionStatus.RESOLVED)
        self.assertEqual(answer.value, "knowledge")
