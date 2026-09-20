# Security Policy

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, use one of the following channels:

1. **GitHub private vulnerability reporting** — open the repository's *Security* tab and click *Report a vulnerability*. This is the preferred channel.
2. If private reporting is unavailable, email the maintainer directly (see the author email in `pyproject.toml`).

Please include:

* A description of the vulnerability and its potential impact.
* Steps to reproduce, or a proof-of-concept.
* The affected version(s) and any relevant configuration.

## Response Timeline

* **Acknowledgement** within 72 hours.
* **Initial assessment** within 7 days, including a severity judgement and remediation plan.
* **Fix and disclosure** coordinated with the reporter. We follow coordinated disclosure and will credit reporters (unless they prefer otherwise).

## Scope

**In scope** — vulnerabilities in JevShield itself:

* Guardrail bypasses (e.g. an input that is incorrectly assessed as `safe` and executed).
* Prompt-injection weaknesses in the way tool state is framed or transmitted.
* Fail-open behavior in policy enforcement or response parsing.
* Credential handling flaws (API keys leaked to logs, third parties, or error messages).
* Dependency and supply-chain issues in the shipped package.

**Out of scope**:

* Vulnerabilities in the Jev model or the TypeSafe / OpenRouter backends themselves — report those to TypeSafe AI or OpenRouter respectively.
* Social engineering, denial-of-service against the upstream gateways, or issues requiring physical access to the operator's machine.
* The local heuristic fallback is a best-effort convenience engine, not a security boundary; reports about its bypass rate (e.g. dangerous phrasing that evades its regexes) are welcome as regular issues, not security advisories.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x: (pre-release, unrevised) |

## Security Design Notes

* Policy enforcement is **fail-closed**: unknown risk tiers, missing blast-radius scores, and low-confidence evaluations are treated as worst-case.
* No API keys are ever logged; state sent to upstream gateways is documented in the README.
* The `interactive` confirmation prompt only engages on a TTY and never in headless/CI environments.
