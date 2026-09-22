# Real Jev Evals Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans task-by-task.

**Goal:** Add a local, real-Jev evaluation harness for the public classification and routing SDK APIs.

**Architecture:** Checked-in JSON scenario corpora are validated by a framework-free loader. The runner loads a key from environment or `.env`, invokes public SDK APIs against a real `JevClient`, and emits a minimal safe report. Unit tests use no network; live calls are only an explicit CLI action.

**Tech Stack:** Python 3.9+, stdlib `argparse/json/os/pathlib`, existing `JevClient`, `IntentClassifier`, `Router`, and `unittest`.

**Spec:** `docs/superpowers/specs/2026-09-22-real-jev-evals-design.md`

## Global Constraints

- Never print, persist, commit, or log `JEV_API_KEY`.
- Load environment first and only then project-root `.env`; missing key must stop before network I/O.
- Normal unit tests and CI remain network-free; real Jev calls require `python -m evals.run`.
- Reports exclude prompt text, candidate descriptions, raw responses, and request payloads.
- Use public SDK APIs only; do not call private payload builders.
- Preserve Python 3.9 compatibility and existing Guard behavior.

---

### Task 1: Case schema, corpus, and loader

**Files:** Create `evals/__init__.py`, `evals/cases/classify.json`, `evals/cases/route.json`, `evals/loader.py`, `tests/test_evals.py`.

- [ ] Write failing tests for rejecting duplicate IDs, missing expected values, non-string candidates, and loading valid cases.
- [ ] Run `python -m unittest tests.test_evals -v` and observe import failure.
- [ ] Implement frozen `EvalCase` and `load_cases(path)` with explicit `ValueError` messages; include 15 Chinese cases per suite spanning normal, adjacent, ambiguous, multi-intent, similar-description, and human-route scenarios.
- [ ] Run the focused tests and commit `feat: add eval scenario corpus`.

### Task 2: Credential loading and safe report model

**Files:** Create `evals/runner.py`; modify `tests/test_evals.py`.

- [ ] Write failing tests that environment takes priority over `.env`, `.env` is parsed without printing a value, missing key raises `MissingCredentialError`, and serialized report excludes `input`, `candidates`, and raw response fields.
- [ ] Run focused tests and observe failure.
- [ ] Implement `load_api_key(project_root)`, `MissingCredentialError`, immutable case-result/report types, aggregation, and timestamped report writing. `.env` parser accepts `KEY=value`, optional `export ` prefix, comments, and quoted values without third-party dependencies.
- [ ] Run focused tests and commit `feat: add secure eval runner primitives`.

### Task 3: Real public-API classify and route execution

**Files:** Modify `evals/runner.py`, `tests/test_evals.py`.

- [ ] Write failing tests with a recording fake `JevClient`/DecisionClient proving classify and route evaluators call public `IntentClassifier`/`Router`, aggregate resolved/incorrect/uncertain/unavailable outcomes, and never include case text in report output.
- [ ] Run focused tests and observe failure.
- [ ] Implement `run_classify_suite()` and `run_route_suite()` using an Enum constructed from case candidates, public `IntentClassifier`, public `Router`, and a real `JevClient` supplied by the CLI. A case passes only on resolved exact match.
- [ ] Run focused tests plus `python -m unittest discover -s tests -v`, then commit `feat: run real jev decision evals`.

### Task 4: CLI and documentation

**Files:** Create `evals/run.py`; modify `README.md`, `tests/test_evals.py`.

- [ ] Write failing CLI tests for `--suite`, `--report-dir`, missing key non-zero exit, and invalid suite rejection.
- [ ] Run focused tests and observe failure.
- [ ] Implement `python -m evals.run --suite classify|route|all [--report-dir PATH] [--min-confidence FLOAT]`; print aggregate counts and report path only, never any credential or prompt content. Ensure live command exits non-zero if any case is incorrect, uncertain, or unavailable.
- [ ] Document setup with ignored `.env`, explicit manual invocation, report privacy, and the fact that evals measure a bounded corpus rather than prove general safety.
- [ ] Run `python -m unittest discover -s tests -v`, `python -m build`, `git diff --check`; commit `docs: add real jev eval instructions`.

## Verification Gate

Before claiming completion, run the complete deterministic suite and build. Then, only when `.env` is present locally, run `python -m evals.run --suite all`; report aggregate metrics and the report path without exposing inputs, raw gateway output, or credentials.
