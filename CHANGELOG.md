# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-09-20

### Fixed

* Runtime banner and exception docstrings no longer print the legacy "Jev-Guard" brand name; all user-facing strings now read "JevShield".

## [0.1.0] - 2026-09-20

Initial release of JevShield, a sub-100ms runtime security gate for AI agent tool calls powered by TypeSafe's Jev (System One) model.

### Added

* `@guard` decorator for any Python function (sync and async paths), evaluating each invocation before execution.
* Single-request, three-primitive evaluation (`Choice` risk tier + `Noul` irreversibility probability + `Score` blast radius) against the official System One protocol.
* Dual-backend support with automatic resolution: TypeSafe direct (`api.typesafe.ai`) and OpenRouter (`openrouter.ai/api/v1/systemone`), overridable via `JEV_BACKEND`.
* Two-factor blocking policy: `(tier ≥ threshold ∧ P_destructive > 0.75) ∨ (blast_radius ≥ 3 ∧ is_destructive)`.
* **Calibrated-confidence routing**: `min_confidence` on `@guard` escalates low-confidence (or confidence-missing) "safe" verdicts to operator confirmation.
* **Fail-closed parsing**: unknown risk tiers, missing risk choices, and missing blast-radius scores are treated as worst-case.
* **Prompt-injection framing**: tool docstrings/arguments are wrapped in an explicit data-not-instructions preamble before evaluation.
* **Rate-limit resilience**: `429`/`529` responses are retried once, honoring the `retry-after` header (capped to protect the latency budget).
* **Zero-config heuristic fallback**: deterministic local evaluation when no API key is present or the gateway fails; the gate never raises from its evaluation path.
* Interactive operator confirmation on TTY; `SecurityViolationError` with structured details otherwise.
* LangChain integration (`guard_langchain_tool`) patching both `_run` and `_arun` with original-signature preservation.
* 32 unit tests (stdlib `unittest`, zero third-party test dependencies).

### Notes

* JevShield is an independent community project and is not affiliated with TypeSafe AI. See the Disclaimer section in the README.
