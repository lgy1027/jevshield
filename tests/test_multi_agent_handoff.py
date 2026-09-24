import unittest
import warnings

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

    def test_completed_child_returns_do_not_count_as_new_delegations(self):
        from jevshield.handoff import HandoffPolicy, HandoffTracker

        tracker = HandoffTracker(HandoffPolicy(max_handoffs=2))
        self.assertEqual(tracker.delegate("main", "research").action.value, "continue")
        self.assertEqual(
            tracker.return_to_parent("research", "main").action.value, "continue"
        )
        decision = tracker.delegate("main", "coding")

        self.assertEqual(decision.action.value, "human_escalation")
        self.assertEqual(decision.reason, "max_handoffs")

    def test_completed_child_can_return_before_main_delegates_to_another_child(self):
        """Treating completed returns as active cycles must fail this test."""
        from jevshield.handoff import HandoffAction, HandoffPolicy, HandoffTracker

        tracker = HandoffTracker(HandoffPolicy(max_handoffs=3))
        tracker.delegate("main", "research")
        returned = tracker.return_to_parent("research", "main")
        decision = tracker.delegate("main", "coding")

        self.assertEqual(returned.action, HandoffAction.CONTINUE)
        self.assertEqual(returned.handoff_count, 1)
        self.assertEqual(decision.action, HandoffAction.CONTINUE)
        self.assertEqual(decision.handoff_count, 2)

    def test_observe_remains_a_deprecated_delegate_alias(self):
        """Removing the compatibility alias must fail this test."""
        from jevshield.handoff import HandoffAction, HandoffTracker

        tracker = HandoffTracker()
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            decision = tracker.observe("main", "research")

        self.assertEqual(decision.action, HandoffAction.CONTINUE)
        self.assertEqual(len(caught), 1)
        self.assertIs(caught[0].category, DeprecationWarning)

    def test_invalid_stack_transitions_are_rejected(self):
        """Removing stack-order validation must fail this test."""
        from jevshield.handoff import HandoffTracker

        tracker = HandoffTracker()
        with self.assertRaises(ValueError):
            tracker.return_to_parent("research", "main")

        tracker.delegate("main", "research")
        with self.assertRaises(ValueError):
            tracker.delegate("main", "coding")
        with self.assertRaises(ValueError):
            tracker.return_to_parent("research", "coding")

    def test_repeated_transfer_escalates_to_human(self):
        """Removing repeated-transfer detection must fail this test."""
        from jevshield.handoff import HandoffAction, HandoffPolicy, HandoffTracker

        tracker = HandoffTracker(
            HandoffPolicy(max_handoffs=5, max_repeated_handoffs=2)
        )
        tracker.delegate("main", "research")
        tracker.return_to_parent("research", "main")
        decision = tracker.delegate("main", "research")

        self.assertEqual(decision.action, HandoffAction.HUMAN_ESCALATION)
        self.assertEqual(decision.reason, "repeated_delegation")

    def test_only_active_delegation_stack_cycles_escalate_to_human(self):
        """Removing active-stack cycle detection must fail this test."""
        from jevshield.handoff import HandoffAction, HandoffPolicy, HandoffTracker

        tracker = HandoffTracker(HandoffPolicy(max_handoffs=5))
        tracker.delegate("main", "research")
        tracker.delegate("research", "coding")
        decision = tracker.delegate("coding", "research")

        self.assertEqual(decision.action, HandoffAction.HUMAN_ESCALATION)
        self.assertEqual(decision.reason, "active_delegation_cycle")

    def test_reset_starts_a_new_handoff_run(self):
        """Removing reset state cleanup must fail this test."""
        from jevshield.handoff import HandoffAction, HandoffPolicy, HandoffTracker

        tracker = HandoffTracker(HandoffPolicy(max_handoffs=2))
        self.assertEqual(
            tracker.delegate("main", "research").action, HandoffAction.CONTINUE
        )
        tracker.reset()

        decision = tracker.delegate("main", "research")

        self.assertEqual(decision.action, HandoffAction.CONTINUE)
        self.assertEqual(decision.handoff_count, 1)
