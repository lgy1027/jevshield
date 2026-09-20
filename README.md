# JevShield 🛡️

[![PyPI version](https://img.shields.io/badge/pypi-v0.1.1-blue.svg)](https://pypi.org/)
[![License](https://img.shields.io/badge/License-Apache_2.0-green.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python Versions](https://img.shields.io/badge/python-3.9+-blue.svg)](https://python.org)

**Sub-100ms, non-autoregressive runtime security gate for AI Agents powered by Jev (System-1 Models).**

Traditional LLM guardrails rely on slow, autoregressive generation: calling GPT-4o or Claude to review an action can take 1.5 to 4 seconds, burn thousands of output tokens, and occasionally fail due to JSON parsing syntax errors.

`jevshield` cuts out the conversational fluff. By taking advantage of **TypeSafe AI's Jev model**, it performs single-pass, typed evaluations directly on logits:
* **Zero Output Token Billing** (Jev charges $0 for output generation).
* **True Sub-100ms Evaluation** via prefill logits readout.
* **Dual-Validation Matrix**: Cross-evaluates **Severity Tier (Choice)** with **Irreversibility Probability (Noul/Boolean)** to eliminate false alarms.
* **Zero-Config Local Fallback**: Instant local heuristic evaluation out of the box when no API key is provided.

---

## Architecture: System-1 vs. System-2 Division

<p align="center">
  <img src="https://raw.githubusercontent.com/lgy1027/jevshield/main/docs/architecture.svg" alt="JevShield architecture: the System 2 agent prepares a tool call; the System 1 JevShield middleware evaluates it in sub-100ms via Choice/Noul/Score primitives and either passes safe calls or halts destructive ones.">
</p>

---

## Quick Start

### 1. Installation

```bash
pip install jevshield
```

For LangChain tool integrations:

```bash
pip install "jevshield[langchain]"
```

### 2. Basic Decorator Usage (Sync & Async)

```python
import os
from jevshield import guard, SecurityViolationError

# Works immediately in heuristic mock mode without an API key!
# Set your key to switch to the Jev neural model:
# export JEV_API_KEY="your-typesafe-or-openrouter-key"

@guard(risk_threshold="critical_danger", interactive=True)
def run_terminal(cmd: str):
    """Executes arbitrary bash commands on the local machine."""
    print(f"Executing: {cmd}")
    return "OK"

# 1. Safe operations pass instantly
run_terminal("ls -la /var/log")

# 2. Destructive operations are halted before invocation
try:
    run_terminal("rm -rf /etc/kubernetes")
except SecurityViolationError as e:
    print(f"Blocked: {e.reason}")
```

---

## Security Posture

* **Prompt-Injection Framing**: tool docstrings and arguments are wrapped in an explicit *data, not instructions* preamble before being sent for evaluation, mitigating Jev-1.13's known susceptibility to hostile content embedded in `state`.
* **Fail-Closed Parsing**: unknown risk tiers, missing risk choices, and missing blast-radius scores are all treated as worst-case rather than silently passing.
* **Calibrated-Confidence Routing**: set `min_confidence` on `@guard` to escalate any evaluation the model is unsure about (or that lacks a confidence field) to operator confirmation instead of trusting a low-confidence "safe" verdict.
* **Rate-Limit Retry**: `429` / `529` responses are retried once with backoff before falling back to the local heuristic engine, so transient gateway throttling does not silently downgrade evaluation quality.

```python
# Low-confidence evaluations are routed to the operator even when not blocked
@guard(risk_threshold="critical_danger", interactive=True, min_confidence=0.6)
def run_terminal(cmd: str):
    ...
```

---

## Supported Primitives & Policy Matrix

`jevshield` structures the security evaluation strictly into three Jev primitives on every pass:

| Primitive | Query | Return Type | Role in Gate |
| --- | --- | --- | --- |
| **Choice** | Risk Tier Assignment | `safe`, `medium_risk`, `critical_danger` | Sets nominal danger bracket. |
| **Noul** | `is_destructive` Statement | P(True) ∈ [0.0, 1.0] | Assesses irreversible damage (data loss, kill). |
| **Score** | Failure Blast Radius | 0–4 weighted position across 5 ordered levels | Quantifies systemic exposure. |

An action is blocked if:

```
(Tier ≥ Threshold ∧ P_destructive > 0.75) ∨ (BlastRadius ≥ 3 ∧ IsDestructive = True)
```

---

## Supported Providers & Gateway Endpoints

`jevshield` implements the official System One protocol and supports two backends:

```bash
# Option A: TypeSafe Official Direct Access (default)
export TYPESAFE_API_KEY="ts-..."
# Optional: pin a model version (default jev-latest)
export JEV_MODEL="jev-1.13.0"

# Option B: OpenRouter (OpenRouter System One endpoint — same protocol, extra id/provider/usage.cost fields)
export JEV_BACKEND="openrouter"
export OPENROUTER_API_KEY="sk-or-v1-..."
# Optional: default model is typesafe/jev-1.13; use ~typesafe/jev-latest for the rolling alias
```

Backend resolution order: `JevClient(backend=...)` argument > `JEV_BACKEND` env var > auto-detect
(TypeSafe key present -> official direct; only an OpenRouter key -> OpenRouter).

| Backend | Endpoint | Default model | Notes |
| --- | --- | --- | --- |
| `typesafe` (default) | `https://api.typesafe.ai/v1/systemone` | `jev-latest` | Official direct access |
| `openrouter` | `https://openrouter.ai/api/v1/systemone` | `typesafe/jev-1.13` | Response additionally carries `id` / `provider` / `usage.cost`; the alpha endpoint `/api/alpha/decisions` can be used instead via `JEV_BASE_URL` |

> ⚠️ Vercel AI Gateway (experimental `evaluate` interface; Noul is called Boolean there) and Cloudflare
> Workers AI (`env.AI.run('typesafe/jev')`) use different request/response shapes and are not adapted yet.

If neither key is present, `jevshield` automatically runs in **Deterministic Heuristic Fallback Mode**, ensuring test suites and Docker builds never crash on initialization.

---

## LangChain Integration

```python
from langchain_core.tools import tool
from jevshield import guard_langchain_tool

@tool
def format_volume(device: str):
    """Erases and formats a block storage partition."""
    return f"Formatted {device}"

# Automatically patches both sync (_run) and async (_arun) paths
guarded_format = guard_langchain_tool(format_volume, interactive=False)
```

---

## License

This project is licensed under the **Apache License, Version 2.0**. See the [LICENSE](LICENSE) file for details.

## Disclaimer

JevShield is an independent, community-driven project and is **not affiliated with, endorsed by, or sponsored by TypeSafe AI**. "Jev", "System One", and "TypeSafe" are trademarks of TypeSafe AI. JevShield interacts with TypeSafe's public API under their published terms of use.
