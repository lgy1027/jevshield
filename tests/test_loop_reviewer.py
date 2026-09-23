import math
import unittest
from dataclasses import FrozenInstanceError

from jevshield.review import LoopReviewAction, LoopReviewDecision, LoopReviewInput
from jevshield.runtime import DecisionStatus


class TestLoopReviewContracts(unittest.TestCase):
    def test_public_package_exports_loop_review_contracts(self):
        from jevshield import LoopReviewAction as PublicLoopReviewAction
        from jevshield import LoopReviewDecision as PublicLoopReviewDecision
        from jevshield import LoopReviewInput as PublicLoopReviewInput

        self.assertIs(PublicLoopReviewAction, LoopReviewAction)
        self.assertIs(PublicLoopReviewDecision, LoopReviewDecision)
        self.assertIs(PublicLoopReviewInput, LoopReviewInput)

    def test_review_input_is_immutable_and_validated(self):
        value = LoopReviewInput(
            "Answer from evidence.",
            "evidence_insufficient",
            3,
            spent_budget=1.5,
            step_summaries=("no new evidence",),
        )

        with self.assertRaises(FrozenInstanceError):
            value.iteration = 4
        with self.assertRaises(ValueError):
            LoopReviewInput("", "checkpoint", 1)
        with self.assertRaises(ValueError):
            LoopReviewInput("goal", "", 1)
        with self.assertRaises(ValueError):
            LoopReviewInput("goal", "checkpoint", 0)

    def test_review_input_rejects_invalid_optional_fields(self):
        invalid_budgets = (True, -1.0, math.inf, math.nan, "1.0")
        for spent_budget in invalid_budgets:
            with self.subTest(spent_budget=spent_budget):
                with self.assertRaises(ValueError):
                    LoopReviewInput("goal", "checkpoint", 1, spent_budget)

        invalid_summaries = (["summary"], ("",), (1,))
        for step_summaries in invalid_summaries:
            with self.subTest(step_summaries=step_summaries):
                with self.assertRaises(ValueError):
                    LoopReviewInput(
                        "goal",
                        "checkpoint",
                        1,
                        step_summaries=step_summaries,
                    )

        for evidence_summary in ("", 1):
            with self.subTest(evidence_summary=evidence_summary):
                with self.assertRaises(ValueError):
                    LoopReviewInput(
                        "goal",
                        "checkpoint",
                        1,
                        evidence_summary=evidence_summary,
                    )

    def test_review_input_requires_exact_string_and_integer_types(self):
        class StringSubclass(str):
            pass

        with self.assertRaises(ValueError):
            LoopReviewInput(StringSubclass("goal"), "checkpoint", 1)
        with self.assertRaises(ValueError):
            LoopReviewInput("goal", StringSubclass("checkpoint"), 1)
        with self.assertRaises(ValueError):
            LoopReviewInput("goal", "checkpoint", True)

    def test_unavailable_decision_cannot_have_action(self):
        with self.assertRaises(ValueError):
            LoopReviewDecision(
                LoopReviewAction.CONTINUE,
                DecisionStatus.UNAVAILABLE,
                0.0,
                1.0,
                "timeout",
            )

    def test_decision_requires_consistent_status_action_and_valid_fields(self):
        decision = LoopReviewDecision(
            LoopReviewAction.ASK_FOR_HELP,
            DecisionStatus.RESOLVED,
            0.9,
            1.0,
            "jev",
        )
        self.assertEqual(decision.action, LoopReviewAction.ASK_FOR_HELP)

        with self.assertRaises(ValueError):
            LoopReviewDecision(None, DecisionStatus.RESOLVED, 0.9, 1.0, "jev")
        with self.assertRaises(ValueError):
            LoopReviewDecision(None, "unavailable", 0.0, 1.0, "timeout")
        with self.assertRaises(ValueError):
            LoopReviewDecision(None, DecisionStatus.UNCERTAIN, math.nan, 1.0, "jev")
        with self.assertRaises(ValueError):
            LoopReviewDecision(None, DecisionStatus.UNAVAILABLE, 0.0, -1.0, "timeout")
        with self.assertRaises(ValueError):
            LoopReviewDecision(None, DecisionStatus.UNAVAILABLE, 0.0, 1.0, "")
        with self.assertRaises(ValueError):
            LoopReviewDecision(None, DecisionStatus.UNAVAILABLE, 0.0, 1.0, "timeout", None)


if __name__ == "__main__":
    unittest.main()
