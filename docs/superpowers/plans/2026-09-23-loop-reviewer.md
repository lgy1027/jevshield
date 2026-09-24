# LoopReviewer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an optional framework-independent semantic checkpoint that recommends `continue`, `ask_for_help`, or `stop_stalled`, without weakening local loop rules or Guard.

**Architecture:** Create `jevshield/review.py` with immutable contracts plus a Choice-backed `LoopReviewer`. The host calls `LoopTerminator` first and chooses explicit checkpoints; the reviewer owns no loop, retriever, memory, tools, execution, or framework state.

**Tech Stack:** Python 3.9 stdlib, `DecisionClient`, `ChoiceQuestion`, `DecisionStatus`, `build_decision_state`, stdlib `unittest`.

**Spec:** `docs/superpowers/specs/2026-09-23-loop-review-tool-pruning-design.md`

## Global Constraints

- No core framework imports; all types use Python 3.9-compatible typing.
- The host invokes review only at explicit checkpoints; review cannot revive a terminal `LoopTerminator` result.
- Review never returns `stop_success` and never executes or authorizes tools.
- Trusted objective and untrusted summaries are separated and redacted/bounded before remote calls.
- `UNCERTAIN` and `UNAVAILABLE` always return `action=None`; caller fallback is explicit.
- ToolPruner and framework adapters are excluded: ToolPruner needs a validated generic multi-select runtime, and adapters require a selected production framework.

---

### Task 1: Immutable contracts

**Files:** Create `jevshield/review.py`; modify `jevshield/__init__.py`; create `tests/test_loop_reviewer.py`.

**Produces:** `LoopReviewAction`, `LoopReviewInput`, `LoopReviewDecision`.

- [ ] **Step 1: Write failing tests**

```python
def test_review_input_is_immutable_and_validated(self):
    value = LoopReviewInput("Answer from evidence.", "evidence_insufficient", 3,
                            spent_budget=1.5, step_summaries=("no new evidence",))
    with self.assertRaises(FrozenInstanceError): value.iteration = 4
    with self.assertRaises(ValueError): LoopReviewInput("", "checkpoint", 1)
    with self.assertRaises(ValueError): LoopReviewInput("goal", "", 1)
    with self.assertRaises(ValueError): LoopReviewInput("goal", "checkpoint", 0)

def test_unavailable_decision_cannot_have_action(self):
    with self.assertRaises(ValueError):
        LoopReviewDecision(LoopReviewAction.CONTINUE, DecisionStatus.UNAVAILABLE, 0.0, 1.0, "timeout")
```

- [ ] **Step 2: Verify red** — Run `python -m unittest tests.test_loop_reviewer.TestLoopReviewContracts -v`; expect `ModuleNotFoundError: No module named 'jevshield.review'`.

- [ ] **Step 3: Implement contracts**

```python
class LoopReviewAction(str, Enum):
    CONTINUE = "continue"
    ASK_FOR_HELP = "ask_for_help"
    STOP_STALLED = "stop_stalled"

@dataclass(frozen=True)
class LoopReviewInput:
    trusted_objective: str
    checkpoint: str
    iteration: int
    spent_budget: Optional[float] = None
    step_summaries: Tuple[str, ...] = ()
    evidence_summary: Optional[str] = None

@dataclass(frozen=True)
class LoopReviewDecision:
    action: Optional[LoopReviewAction]
    status: DecisionStatus
    confidence: float
    latency_ms: float
    source: str
    reason: str = ""
```

Validate non-empty exact strings, positive iteration, finite non-negative numeric fields, tuple summaries, non-empty source, and `action is None` unless status is resolved. Export all types.

- [ ] **Step 4: Verify green** — Run `python -m unittest tests.test_loop_reviewer.TestLoopReviewContracts -v`; expect PASS.
- [ ] **Step 5: Commit** — Run `git add jevshield/review.py jevshield/__init__.py tests/test_loop_reviewer.py && git commit -m "feat: add loop review contracts"`.

### Task 2: Sync and async reviewer

**Files:** Modify `jevshield/review.py`; modify `tests/test_loop_reviewer.py`.

**Consumes:** Task 1 contracts, `DecisionClient`, `ChoiceQuestion`, `build_decision_state`.

**Produces:** `LoopReviewer(client, min_confidence=0.0)`, `review(input)`, and `areview(input)` returning `LoopReviewDecision`.

- [ ] **Step 1: Write failing behavior tests**

```python
def test_review_maps_choice_and_redacts_state(self):
    client = RecordingDecisionClient([answer("ask_for_help")])
    result = LoopReviewer(client, min_confidence=0.7).review(
        LoopReviewInput("Find answer from approved evidence.", "evidence_insufficient", 3,
                        evidence_summary="sk-abcdefghijklmnopqrstuvwxyz123456"))
    self.assertEqual(result.action, LoopReviewAction.ASK_FOR_HELP)
    self.assertEqual(client.questions[0].name, "loop_review")
    self.assertNotIn("sk-abcdefghijklmnopqrstuvwxyz123456", client.states[0])

def test_unavailable_low_confidence_and_unknown_have_no_action(self):
    self.assertIsNone(LoopReviewer(RecordingDecisionClient([unavailable_answer()])).review(review_input()).action)
    self.assertIsNone(LoopReviewer(RecordingDecisionClient([answer("continue", 0.4)]), 0.7).review(review_input()).action)
    self.assertIsNone(LoopReviewer(RecordingDecisionClient([answer("unknown")])).review(review_input()).action)
```

Also test async parity with `asyncio.run(reviewer.areview(review_input()))`.

- [ ] **Step 2: Verify red** — Run `python -m unittest tests.test_loop_reviewer.TestLoopReviewer -v`; expect `NameError: name 'LoopReviewer' is not defined`.

- [ ] **Step 3: Implement reviewer**

Create question `loop_review` with criteria `continue`, `ask_for_help`, and `stop_stalled`. Frame exactly objective, checkpoint, iteration, spent budget, summaries, and evidence with `build_decision_state`. Map unavailable directly to unavailable/no action; map unknown/below-threshold to uncertain/no action; map only validated choices to `LoopReviewAction`. Do not call `LoopTerminator`, execute tools, or retry.

- [ ] **Step 4: Verify green** — Run `python -m unittest tests.test_loop_reviewer -v`; expect PASS.
- [ ] **Step 5: Commit** — Run `git add jevshield/review.py tests/test_loop_reviewer.py && git commit -m "feat: add semantic loop reviewer"`.

### Task 3: Plain-Python Agent/RAG composition

**Files:** Modify `README.md`; modify `tests/test_loop_reviewer.py`.

**Consumes:** `LoopTerminator.observe(LoopStep)` and `LoopReviewer.review(LoopReviewInput)`.

- [ ] **Step 1: Write failing composition tests**

```python
def test_terminal_local_decision_skips_reviewer(self):
    terminator = LoopTerminator(LoopPolicy(max_iterations=1))
    client = RecordingDecisionClient([answer("continue")])
    local = terminator.observe(LoopStep(tool_call_key="retrieve", observation_key="same"))
    if local.action is LoopAction.CONTINUE: LoopReviewer(client).review(review_input())
    self.assertEqual(local.action, LoopAction.STOP_STALLED)
    self.assertEqual(client.states, [])

def test_rag_evidence_checkpoint_can_ask_for_help(self):
    result = LoopReviewer(RecordingDecisionClient([answer("ask_for_help")])).review(
        LoopReviewInput("Answer only from retrieved evidence.", "evidence_insufficient", 2,
                        step_summaries=("retrieval added no support",)))
    self.assertEqual(result.action, LoopReviewAction.ASK_FOR_HELP)
```

- [ ] **Step 2: Verify red** — Run `python -m unittest tests.test_loop_reviewer.TestLoopReviewerComposition -v`; expect FAIL before composition coverage exists.

- [ ] **Step 3: Document composition**

Add README Agent and RAG examples: call local `observe()` first; return any non-continue local action; only then call reviewer at an explicit checkpoint; act only on non-`None` reviewer action. RAG passes safe retrieval/evidence summaries, never raw documents/framework objects. State that Guard remains mandatory for tool execution.

- [ ] **Step 4: Verify all behavior** — Run `python -m unittest tests.test_loop_reviewer tests.test_loop -v && python -m unittest discover -s tests -v`; expect PASS.
- [ ] **Step 5: Build and commit** — Run `python -m build --wheel --no-isolation && git add README.md tests/test_loop_reviewer.py && git commit -m "docs: add loop reviewer composition guidance"`.

## Plan self-review

- Tasks 1-2 cover typed optional semantic review, redaction, sync/async parity, and explicit uncertainty.
- Task 3 proves terminal local authority and documents plain-Python Agent/RAG integration.
- ToolPruner and adapters remain separate by design; no framework type crosses into core.
