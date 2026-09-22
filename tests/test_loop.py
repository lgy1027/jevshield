import unittest

from jevshield.loop import LoopAction, LoopDecision, LoopPolicy, LoopStep, LoopTerminator


class TestLoopTerminator(unittest.TestCase):
    def test_public_package_exports_loop_api(self):
        from jevshield import LoopAction as PublicLoopAction
        from jevshield import LoopDecision as PublicLoopDecision
        from jevshield import LoopPolicy as PublicLoopPolicy
        from jevshield import LoopStep as PublicLoopStep
        from jevshield import LoopTerminator as PublicLoopTerminator

        self.assertIs(PublicLoopAction, LoopAction)
        self.assertIs(PublicLoopDecision, LoopDecision)
        self.assertIs(PublicLoopPolicy, LoopPolicy)
        self.assertIs(PublicLoopStep, LoopStep)
        self.assertIs(PublicLoopTerminator, LoopTerminator)

    def test_explicit_completed_step_stops_successfully(self):
        terminator = LoopTerminator()

        decision = terminator.observe(LoopStep(goal_completed=True))

        self.assertEqual(decision.action, LoopAction.STOP_SUCCESS)
        self.assertEqual(decision.reason, "goal_completed")

    def test_iteration_budget_stops_before_another_iteration(self):
        terminator = LoopTerminator(LoopPolicy(max_iterations=2))

        self.assertEqual(terminator.observe(LoopStep()).action, LoopAction.CONTINUE)
        decision = terminator.observe(LoopStep())

        self.assertEqual(decision.action, LoopAction.STOP_STALLED)
        self.assertEqual(decision.reason, "max_iterations")

    def test_repeated_tool_call_stops_on_configured_limit(self):
        terminator = LoopTerminator(LoopPolicy(max_repeated_tool_calls=3))

        self.assertEqual(
            terminator.observe(LoopStep(tool_call_key="read:config")).action,
            LoopAction.CONTINUE,
        )
        self.assertEqual(
            terminator.observe(LoopStep(tool_call_key="read:config")).action,
            LoopAction.CONTINUE,
        )
        decision = terminator.observe(LoopStep(tool_call_key="read:config"))

        self.assertEqual(decision.action, LoopAction.STOP_STALLED)
        self.assertEqual(decision.reason, "repeated_tool_call")

    def test_stagnation_can_escalate_for_help(self):
        terminator = LoopTerminator(
            LoopPolicy(
                max_stagnant_iterations=2,
                stall_action=LoopAction.ASK_FOR_HELP,
            )
        )

        self.assertEqual(
            terminator.observe(LoopStep(observation_key="no-results")).action,
            LoopAction.CONTINUE,
        )
        decision = terminator.observe(LoopStep(observation_key="no-results"))

        self.assertEqual(decision.action, LoopAction.ASK_FOR_HELP)
        self.assertEqual(decision.reason, "stagnant_observation")

    def test_budget_exhaustion_stops_even_without_tool_or_observation(self):
        terminator = LoopTerminator(LoopPolicy(max_budget=5.0))

        decision = terminator.observe(LoopStep(spent_budget=5.0))

        self.assertEqual(decision.action, LoopAction.STOP_STALLED)
        self.assertEqual(decision.reason, "budget_exhausted")

    def test_goal_completion_requires_a_boolean_flag(self):
        with self.assertRaises(ValueError):
            LoopStep(goal_completed="true")

    def test_success_step_cannot_bypass_decreasing_budget_validation(self):
        terminator = LoopTerminator(LoopPolicy(max_budget=20.0))
        terminator.observe(LoopStep(spent_budget=10.0))

        with self.assertRaises(ValueError):
            terminator.observe(LoopStep(goal_completed=True, spent_budget=5.0))

    def test_invalid_step_does_not_consume_an_iteration(self):
        terminator = LoopTerminator(LoopPolicy(max_iterations=2))
        terminator.observe(LoopStep(spent_budget=10.0))

        with self.assertRaises(ValueError):
            terminator.observe(LoopStep(spent_budget=5.0))
        decision = terminator.observe(LoopStep(spent_budget=10.0))

        self.assertEqual(decision.iteration, 2)
        self.assertEqual(decision.reason, "max_iterations")

    def test_stall_action_requires_a_loop_action(self):
        with self.assertRaises(ValueError):
            LoopPolicy(stall_action="ask_for_help")

    def test_step_keys_require_opaque_strings(self):
        with self.assertRaises(ValueError):
            LoopStep(tool_call_key={"command": "rm -rf /"})
        with self.assertRaises(ValueError):
            LoopStep(observation_key=["raw", "tool", "output"])


if __name__ == "__main__":
    unittest.main()
