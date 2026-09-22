# Contributing to JevShield

Thanks for your interest in contributing! JevShield is a small, focused project — a security-gate middleware for AI agent tool calls powered by TypeSafe's Jev model — and we aim to keep it that way.

## Getting Started

```bash
git clone https://github.com/lgy1027/jevshield.git
cd jevshield
pip install -e ".[langchain]"   # langchain extra makes all tests run (otherwise they skip)
python -m unittest discover -s tests -v
```

No API key is required for development: without one, the library runs in deterministic heuristic fallback mode, which is also what the test suite exercises (network calls are mocked).

To test against the real Jev backend:

```bash
export TYPESAFE_API_KEY="ts-..."          # or OPENROUTER_API_KEY with JEV_BACKEND=openrouter
python examples/01_async_and_sql.py
```

## Ground Rules

These invariants are the project's core value — PRs that break them will not be merged:

1. **Keep the public and structured evaluation paths distinct.** Legacy `evaluate` / `aevaluate` preserve their heuristic fallback contract. `evaluate_context` / `aevaluate_context` may raise a typed evaluator error when a policy selects fail-closed behavior; the decorator must convert that error into a denial before the protected function runs.
2. **Production must fail closed.** `ProductionPolicy()` denies evaluator timeouts, malformed responses, transport failures, and local-rule failures. Unknown risk tiers, missing blast-radius scores, a headless `ASK` without a confirmer, and failed or timed-out approval must never become an allow.
3. **No Fast-Pass and no secret escape path.** A local rule may Fast-Deny without evaluator I/O, but it must not fast-allow. Secrets must be redacted before evaluator requests and again before decisions, exceptions, confirmers, and audit sinks; tests must assert this boundary.
4. **Sync and async paths stay in lockstep.** Any change to `evaluate_context` must be mirrored in `aevaluate_context` (and vice versa); the same applies to the two wrappers in `guard()`.
5. **Protocol compatibility.** Response parsing keeps its backward-compatible field fallbacks (`choice`/`selected`/`value`, `noul`/`p_true`, `answers`/`results`/`questions`) unless a documented gateway release removes them.
6. **Zero hard dependencies beyond `httpx`.** Optional integrations (e.g. LangChain) belong in extras and must degrade gracefully when not installed.

## Pull Requests

* Keep changes focused; one concern per PR.
* Add or update tests for behavior changes. The suite is stdlib `unittest` — no test framework dependencies, please.
* Run `python -m unittest discover -s tests -v` before pushing; it must pass on Python 3.9+ (the CI matrix covers 3.9–3.13).
* Treat `policy=` as the required public configuration surface. Do not add legacy decorator keywords such as `risk_threshold`, `interactive`, or `min_confidence`.
* Match the existing code style: concise Chinese comments are used throughout the implementation; public API docstrings are currently Chinese and may be anglicized over time — keep whichever language the surrounding code uses.

## Commit Style

Short, imperative, prefixed when useful (`feat:`, `fix:`, `docs:`, `test:`). No AI-generated-by trailers. Example:

```
fix(client): retry-after 头解析兜底非法值
```

## Reporting Bugs / Requesting Features

Use GitHub issues for everything except security vulnerabilities — see [SECURITY.md](SECURITY.md) for the security reporting process.
