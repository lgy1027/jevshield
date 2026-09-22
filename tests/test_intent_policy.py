"""Contracts for trusted guard metadata and observed intent framing."""

from dataclasses import FrozenInstanceError
import unittest

from jevshield.models import (
    GuardContext,
    GuardContextMetadata,
    merge_context_metadata,
)
from jevshield.redaction import (
    MAX_DECISION_STATE_CHARS,
    build_observed_intent_state,
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
