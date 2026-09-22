# Guard Intent-Consistency Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans task-by-task.

**Goal:** Block a guarded tool call when its Jev-classified observed intent conflicts with a trusted host-provided task objective.

**Architecture:** A context provider supplies only trusted metadata. `IntentPolicy` classifies the trusted objective and a separately framed observed invocation through the existing typed `IntentClassifier`; it returns only skip, ask, or deny. Guard enforces that restrictive result before its existing risk evaluator and never treats a matching intent as permission.

**Spec:** `docs/superpowers/specs/2026-09-22-jevshield-decision-control-sdk-design.md`

## Global Constraints

- Python 3.9-compatible typing; no framework imports in core modules.
- Existing `guard()` callers remain behaviorally compatible when new arguments are omitted.
- `context_provider` can add trusted intent/environment/actor/resource metadata but cannot alter tool name, description, or arguments.
- Expected intent and observed invocation use separate redacted/bounded state; observed state must omit trusted intent.
- Missing trusted intent skips the new gate; mismatch/unavailable/uncertain can only ask or deny, never allow.
- Production defaults deny mismatch, uncertainty, and unavailability.
- Intent gate never overrides a Fast-Deny or existing Guard denial.

---

### Task 1: Trusted metadata and observed-invocation framing

**Files:** Modify `jevshield/models.py`, `jevshield/redaction.py`; create `tests/test_intent_policy.py`.

- [ ] Write failing tests for immutable `GuardContextMetadata`, provider metadata merging without tool/argument spoofing, and observed state that contains tool fields but omits `intent` while redacting credentials.
- [ ] Run `python -m unittest tests.test_intent_policy -v` and observe failure.
- [ ] Add `GuardContextMetadata(intent, environment, actor_id, resource_scope)` with strict strings/tuple validation, `merge_context_metadata(context, metadata)`, and `build_observed_intent_state(context)` using existing redaction/bounds.
- [ ] Run focused/full tests and commit `feat: add trusted guard intent context`.

### Task 2: Intent policy assessment

**Files:** Create `jevshield/intent.py`; modify `jevshield/__init__.py`; modify `tests/test_intent_policy.py`.

- [ ] Write failing tests using a recording `DecisionClient`: no trusted intent skips without classifier call; matching expected/observed intent passes; mismatch returns configured deny; low confidence/unavailable return configured deny or ask; observed classification input omits trusted objective.
- [ ] Run focused tests and observe failure.
- [ ] Add immutable `IntentPolicy` with `classifier`, `on_mismatch`, `on_uncertain`, `on_unavailable`, and optional relation callback. Restrict actions to ASK/DENY. Add `IntentAssessment` containing status, expected/observed values, action, and a safe reason; sync/async assessment APIs.
- [ ] Export public types; run focused/full tests and commit `feat: add guard intent consistency policy`.

### Task 3: Decorator enforcement and audit-safe decisions

**Files:** Modify `jevshield/decorators.py`, `jevshield/core.py` only if a small reusable enforcement helper is needed; modify `tests/test_jev_guard.py`, `tests/test_intent_policy.py`.

- [ ] Write failing sync/async guarded-function tests proving: no provider preserves old behavior; matching intent reaches existing evaluator; mismatch prevents wrapped execution and existing evaluator network call; production unavailable intent prevents execution; context provider cannot spoof invocation; ASK uses current confirmer/audit path.
- [ ] Run focused tests and observe failure.
- [ ] Add optional keyword-only `context_provider` and `intent_policy` to `guard()`. Invoke local Fast-Deny first, build trusted context, assess intent, then create an audit-safe `GuardDecision` whose explicit action is enforced through existing `enforce()`/`aenforce()`. Use a synthetic non-secret `Evaluation(source="intent_mismatch"|"intent_uncertain"|"intent_unavailable")`; do not route through `decide()` when explicit intent action must be preserved.
- [ ] Run full tests/build and commit `feat: enforce guard intent consistency`.

### Task 4: End-to-end adversarial evals and docs

**Files:** Create `evals/cases/guard_intent_consistency.json`; modify `evals/runner.py`, `evals/run.py`, `tests/test_evals.py`, `README.md`.

- [ ] Write failing deterministic end-to-end tests with a recording client and harmless guarded function for injection-like and goal-drift cases; assert dangerous observed intent is denied before function execution.
- [ ] Implement a `guard_intent_consistency` eval suite that records only safe IDs/outcomes and separately reports `dangerous_calls_blocked`, `dangerous_calls_allowed`, and high-confidence dangerous leaks.
- [ ] Add 20 frozen cases based on security holdout patterns with trusted objective plus tool invocation metadata.
- [ ] Document framework-free provider usage and run full tests, build, and optional real eval only with local `.env`; commit `docs: add intent consistency evals`.
