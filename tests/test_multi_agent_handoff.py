import unittest

import jevshield


class TestMultiAgentHandoff(unittest.TestCase):
    def test_public_api_exports_handoff_types(self):
        """Removing package exports must fail this test."""
        from jevshield.handoff import (
            HandoffAction,
            HandoffDecision,
            HandoffPolicy,
            HandoffTracker,
        )

        self.assertIs(jevshield.HandoffAction, HandoffAction)
        self.assertIs(jevshield.HandoffDecision, HandoffDecision)
        self.assertIs(jevshield.HandoffPolicy, HandoffPolicy)
        self.assertIs(jevshield.HandoffTracker, HandoffTracker)
        self.assertTrue(
            {"HandoffAction", "HandoffDecision", "HandoffPolicy", "HandoffTracker"}
            <= set(jevshield.__all__)
        )

    def test_handoff_budget_escalates_to_human(self):
        from jevshield.handoff import HandoffPolicy, HandoffTracker

        tracker = HandoffTracker(HandoffPolicy(max_handoffs=2))
        self.assertEqual(tracker.observe("research", "coding").action.value, "continue")
        self.assertEqual(tracker.observe("coding", "testing").action.value, "human_escalation")

    def test_repeated_transfer_escalates_to_human(self):
        """Removing repeated-transfer detection must fail this test."""
        from jevshield.handoff import HandoffAction, HandoffPolicy, HandoffTracker

        tracker = HandoffTracker(
            HandoffPolicy(max_handoffs=5, max_repeated_handoffs=2)
        )
        tracker.observe("research", "coding")
        decision = tracker.observe("research", "coding")

        self.assertEqual(decision.action, HandoffAction.HUMAN_ESCALATION)
        self.assertEqual(decision.reason, "repeated_handoff")

    def test_returning_to_a_prior_role_escalates_to_human(self):
        """Removing cycle detection must fail this test."""
        from jevshield.handoff import HandoffAction, HandoffPolicy, HandoffTracker

        tracker = HandoffTracker(HandoffPolicy(max_handoffs=5))
        tracker.observe("research", "coding")
        tracker.observe("coding", "testing")
        decision = tracker.observe("testing", "research")

        self.assertEqual(decision.action, HandoffAction.HUMAN_ESCALATION)
        self.assertEqual(decision.reason, "handoff_cycle")

    def test_reset_starts_a_new_handoff_run(self):
        """Removing reset state cleanup must fail this test."""
        from jevshield.handoff import HandoffAction, HandoffPolicy, HandoffTracker

        tracker = HandoffTracker(HandoffPolicy(max_handoffs=2))
        self.assertEqual(
            tracker.observe("research", "coding").action, HandoffAction.CONTINUE
        )
        tracker.reset()

        decision = tracker.observe("research", "coding")

        self.assertEqual(decision.action, HandoffAction.CONTINUE)
        self.assertEqual(decision.handoff_count, 1)
