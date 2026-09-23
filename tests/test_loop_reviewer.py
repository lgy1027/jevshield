import asyncio
import json
import math
import unittest
from dataclasses import FrozenInstanceError

from jevshield.review import (
    LoopReviewAction,
    LoopReviewDecision,
    LoopReviewer,
    LoopReviewInput,
)
from jevshield.loop import LoopAction, LoopPolicy, LoopStep, LoopTerminator
from jevshield.runtime import ChoiceAnswer, DecisionStatus


class RecordingDecisionClient:
    def __init__(self, answers):
        self.answers = list(answers)
        self.states = []
        self.questions = []

    def choose(self, state, question):
        self.states.append(state)
        self.questions.append(question)
        return self.answers.pop(0)

    async def achoose(self, state, question):
        return self.choose(state, question)


def answer(value, confidence=0.9):
    return ChoiceAnswer(
        value,
        confidence,
        DecisionStatus.RESOLVED,
        2.5,
        "jev",
        "reviewed",
    )


def unavailable_answer():
    return ChoiceAnswer(
        None,
        0.0,
        DecisionStatus.UNAVAILABLE,
        3.0,
        "timeout",
        "unavailable",
    )


def review_input():
    return LoopReviewInput(
        "Find answer from approved evidence.",
        "evidence_insufficient",
        3,
        spent_budget=1.5,
        step_summaries=("searched approved source", "no sufficient evidence"),
        evidence_summary="Evidence remains insufficient.",
    )


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


class TestLoopReviewer(unittest.TestCase):
    def test_review_maps_choice_and_redacts_complete_state(self):
        secret = "sk-abcdefghijklmnopqrstuvwxyz123456"
        client = RecordingDecisionClient([answer("ask_for_help")])

        result = LoopReviewer(client, min_confidence=0.7).review(
            LoopReviewInput(
                "Find answer from approved evidence.",
                "evidence_insufficient",
                3,
                spent_budget=1.5,
                step_summaries=("searched approved source",),
                evidence_summary=secret,
            )
        )

        self.assertEqual(result.action, LoopReviewAction.ASK_FOR_HELP)
        self.assertEqual(result.status, DecisionStatus.RESOLVED)
        self.assertEqual(client.questions[0].name, "loop_review")
        self.assertEqual(
            set(client.questions[0].criteria),
            {"continue", "ask_for_help", "stop_stalled"},
        )
        self.assertNotIn(secret, client.states[0])
        payload = json.loads(client.states[0].split(": ", 1)[1])
        self.assertEqual(
            payload,
            {
                "checkpoint": "evidence_insufficient",
                "evidence_summary": "[REDACTED_SECRET]",
                "iteration": 3,
                "spent_budget": 1.5,
                "step_summaries": ["searched approved source"],
                "trusted_objective": "Find answer from approved evidence.",
            },
        )

    def test_unavailable_low_confidence_and_unknown_have_no_action(self):
        unavailable = LoopReviewer(
            RecordingDecisionClient([unavailable_answer()])
        ).review(review_input())
        low_confidence = LoopReviewer(
            RecordingDecisionClient([answer("continue", 0.4)]),
            min_confidence=0.7,
        ).review(review_input())
        unknown = LoopReviewer(
            RecordingDecisionClient([answer("unknown")])
        ).review(review_input())

        self.assertIsNone(unavailable.action)
        self.assertEqual(unavailable.status, DecisionStatus.UNAVAILABLE)
        self.assertIsNone(low_confidence.action)
        self.assertEqual(low_confidence.status, DecisionStatus.UNCERTAIN)
        self.assertIsNone(unknown.action)
        self.assertEqual(unknown.status, DecisionStatus.UNCERTAIN)

    def test_areview_matches_sync_review(self):
        sync_result = LoopReviewer(
            RecordingDecisionClient([answer("stop_stalled")])
        ).review(review_input())
        async_result = asyncio.run(
            LoopReviewer(
                RecordingDecisionClient([answer("stop_stalled")])
            ).areview(review_input())
        )

        self.assertEqual(async_result, sync_result)


class TestLoopReviewerComposition(unittest.TestCase):
    def test_terminal_local_decision_skips_reviewer(self):
        terminator = LoopTerminator(LoopPolicy(max_iterations=1))
        client = RecordingDecisionClient([answer("continue")])

        local = terminator.observe(
            LoopStep(tool_call_key="retrieve", observation_key="same")
        )
        if local.action is LoopAction.CONTINUE:
            LoopReviewer(client).review(review_input())

        self.assertEqual(local.action, LoopAction.STOP_STALLED)
        self.assertEqual(client.states, [])

    def test_rag_evidence_checkpoint_can_ask_for_help(self):
        result = LoopReviewer(
            RecordingDecisionClient([answer("ask_for_help")])
        ).review(
            LoopReviewInput(
                "Answer only from retrieved evidence.",
                "evidence_insufficient",
                2,
                step_summaries=("retrieval added no support",),
            )
        )

        self.assertEqual(result.action, LoopReviewAction.ASK_FOR_HELP)


if __name__ == "__main__":
    unittest.main()
