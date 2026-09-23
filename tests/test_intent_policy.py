"""Contracts for trusted guard metadata and intent consistency."""

import asyncio
from dataclasses import FrozenInstanceError
from enum import Enum
import unittest

from jevshield.classify import IntentClassifier
from jevshield.intent import IntentPolicy, IntentStatus
from jevshield.models import (
    Action,
    GuardContext,
    GuardContextMetadata,
    merge_context_metadata,
)
from jevshield.redaction import (
    MAX_DECISION_STATE_CHARS,
    build_observed_intent_state,
)
from jevshield.runtime import ChoiceAnswer, DecisionStatus


class Intent(str, Enum):
    READ = "read"
    DELETE = "delete"


class RecordingDecisionClient:
    def __init__(self, answers):
        self.answers = list(answers)
        self.states = []

    def choose(self, state, question):
        self.states.append(state)
        return self.answers.pop(0)

    async def achoose(self, state, question):
        return self.choose(state, question)


def answer(value, confidence=0.95, status=DecisionStatus.RESOLVED, reason=""):
    return ChoiceAnswer(value, confidence, status, 1.0, "stub", reason)


def policy(answers, **kwargs):
    client = RecordingDecisionClient(answers)
    classifier = IntentClassifier(
        Intent,
        {Intent.READ: "Read data.", Intent.DELETE: "Delete data."},
        client,
        min_confidence=0.7,
    )
    return IntentPolicy(classifier=classifier, **kwargs), client


def context(intent="Read order 42"):
    return GuardContext(
        tool_name="read_order",
        tool_description="Read an order.",
        args={"order_id": "42"},
        intent=intent,
    )


class TestGuardContextMetadata(unittest.TestCase):
    def test_metadata_is_immutable_and_rejects_non_string_or_non_tuple_values(self):
        metadata = GuardContextMetadata(
            intent="look up an order",
            environment="production",
            actor_id="user-42",
            resource_scope=("order:42",),
        )

        with self.assertRaises(FrozenInstanceError):
            metadata.intent = "delete an order"

        for kwargs in (
            {"intent": 42},
            {"environment": ["production"]},
            {"actor_id": b"user-42"},
            {"resource_scope": ["order:42"]},
            {"resource_scope": ("order:42", 42)},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(TypeError):
                GuardContextMetadata(**kwargs)

    def test_merge_adds_only_trusted_metadata_without_spoofing_invocation(self):
        context = GuardContext(
            tool_name="lookup_order",
            tool_description="Read one order.",
            args={"order_id": "42"},
            intent="untrusted request text",
        )
        metadata = GuardContextMetadata(
            intent="look up an order",
            environment="production",
            actor_id="user-42",
            resource_scope=("order:42",),
        )

        merged = merge_context_metadata(context, metadata)

        self.assertEqual(merged.tool_name, "lookup_order")
        self.assertEqual(merged.tool_description, "Read one order.")
        self.assertEqual(merged.args, {"order_id": "42"})
        self.assertEqual(merged.intent, "look up an order")
        self.assertEqual(merged.environment, "production")
        self.assertEqual(merged.actor_id, "user-42")
        self.assertEqual(merged.resource_scope, ("order:42",))


class TestObservedIntentState(unittest.TestCase):
    def test_observed_state_redacts_and_bounds_tool_data_without_trusted_intent(self):
        secret = "sk-abcdefghijklmnopqrstuvwxyz123456"
        context = GuardContext(
            tool_name="lookup_order",
            tool_description="Read one order.",
            args={"order_id": "42", "api_key": secret},
            intent="look up an order",
        )

        state = build_observed_intent_state(context)

        self.assertIn('"tool_name":"lookup_order"', state)
        self.assertIn('"tool_description":"Read one order."', state)
        self.assertIn('"order_id":"42"', state)
        self.assertIn("[REDACTED_SECRET]", state)
        self.assertNotIn(secret, state)
        self.assertNotIn('"intent"', state)
        self.assertNotIn("look up an order", state)
        self.assertLessEqual(len(state), MAX_DECISION_STATE_CHARS)


class TestIntentPolicy(unittest.TestCase):
    def test_missing_trusted_intent_skips_without_client_call(self):
        guard_policy, client = policy([])

        assessment = guard_policy.assess(context(intent=None))

        self.assertEqual(assessment.status, IntentStatus.SKIPPED)
        self.assertIsNone(assessment.action)
        self.assertIsNone(assessment.expected)
        self.assertIsNone(assessment.observed)
        self.assertEqual(client.states, [])

    def test_matching_intents_pass_without_granting_allow(self):
        guard_policy, client = policy([answer("read"), answer("read")])

        assessment = guard_policy.assess(context())

        self.assertEqual(assessment.status, IntentStatus.PASS)
        self.assertEqual(assessment.expected, Intent.READ)
        self.assertEqual(assessment.observed, Intent.READ)
        self.assertIsNone(assessment.action)
        self.assertEqual(len(client.states), 2)

    def test_mismatch_returns_configured_deny(self):
        guard_policy, _ = policy(
            [answer("read"), answer("delete")], on_mismatch=Action.DENY
        )

        assessment = guard_policy.assess(context())

        self.assertEqual(assessment.status, IntentStatus.MISMATCH)
        self.assertEqual(assessment.expected, Intent.READ)
        self.assertEqual(assessment.observed, Intent.DELETE)
        self.assertEqual(assessment.action, Action.DENY)

    def test_low_confidence_returns_configured_ask(self):
        guard_policy, _ = policy(
            [answer("read", confidence=0.4), answer("delete")],
            on_uncertain=Action.ASK,
        )

        assessment = guard_policy.assess(context())

        self.assertEqual(assessment.status, IntentStatus.UNCERTAIN)
        self.assertIsNone(assessment.expected)
        self.assertEqual(assessment.observed, Intent.DELETE)
        self.assertEqual(assessment.action, Action.ASK)

    def test_unavailable_returns_configured_deny_and_safe_reason(self):
        secret = "sk-abcdefghijklmnopqrstuvwxyz123456"
        guard_policy, _ = policy(
            [answer("read"), answer(None, status=DecisionStatus.UNAVAILABLE, reason=secret)],
            on_unavailable=Action.DENY,
        )

        assessment = guard_policy.assess(context())

        self.assertEqual(assessment.status, IntentStatus.UNAVAILABLE)
        self.assertEqual(assessment.expected, Intent.READ)
        self.assertIsNone(assessment.observed)
        self.assertEqual(assessment.action, Action.DENY)
        self.assertNotIn(secret, assessment.reason)

    def test_observed_classification_omits_trusted_objective(self):
        trusted_objective = "trusted objective: read order 42"
        guard_policy, client = policy([answer("read"), answer("read")])

        guard_policy.assess(context(intent=trusted_objective))

        self.assertIn(trusted_objective, client.states[0])
        self.assertNotIn(trusted_objective, client.states[1])
        self.assertIn("read_order", client.states[1])
        self.assertNotIn('"intent"', client.states[1])
        self.assertLessEqual(len(client.states[1]), MAX_DECISION_STATE_CHARS)

    def test_relation_callback_can_approve_compatible_intents(self):
        guard_policy, _ = policy(
            [answer("read"), answer("delete")],
            relation=lambda expected, observed: (
                expected is Intent.READ and observed is Intent.DELETE
            ),
        )

        assessment = guard_policy.assess(context())

        self.assertEqual(assessment.status, IntentStatus.PASS)
        self.assertIsNone(assessment.action)

    def test_invalid_actions_are_rejected(self):
        for option in ("on_mismatch", "on_uncertain", "on_unavailable"):
            with self.subTest(option=option), self.assertRaises(ValueError):
                policy([], **{option: Action.ALLOW})

    def test_async_assessment_uses_the_same_policy(self):
        guard_policy, client = policy([answer("read"), answer("delete")])

        assessment = asyncio.run(guard_policy.aassess(context()))

        self.assertEqual(assessment.status, IntentStatus.MISMATCH)
        self.assertEqual(assessment.action, Action.DENY)
        self.assertEqual(len(client.states), 2)
