# Live Agent and RAG Examples Design

## Goal

Demonstrate the existing framework-independent control APIs in two executable,
plain-Python flows that can make real Jev decisions when credentials are
explicitly configured:

1. a bounded multi-tool Agent loop; and
2. a bounded retrieval-and-evidence RAG flow.

The examples must demonstrate that `LoopTerminator`, optional
`LoopReviewer`, and execution-time `guard()` have separate responsibilities.
They must not introduce a framework dependency or claim to be a general Agent
or RAG runtime.

## Scope

Add two examples:

- `examples/04_live_agent_loop.py`
- `examples/05_live_rag_checkpoint.py`

Each example receives an explicitly constructed real `JevClient` through the
existing environment-backed configuration. It must fail before making a
network request when the required Jev credential is absent, and it must not
print credentials, raw decision payloads, or raw remote responses.

The Agent example uses application-owned, deterministic demonstration tools
and opaque step identifiers. Its host loop calls `LoopTerminator.observe()`
after each completed step, returns immediately for any terminal local action,
and calls `LoopReviewer.review()` only at an explicit semantic checkpoint.
Each demonstration tool is wrapped with `@guard(policy=ProductionPolicy())`
so a reviewer recommendation never substitutes for execution authorization.

The RAG example uses an application-owned in-memory evidence corpus. It sends
only a short derived evidence summary and step summaries to `LoopReviewer`;
it never sends the complete documents, retriever result objects, or a vector
store object. The host first processes the local termination result, then
reviews only the `evidence_insufficient` or `evidence_conflict` checkpoint.

## Non-goals

- No LangChain, LlamaIndex, vector database, web-search, or embedding
  dependency.
- No `ToolPruner`, framework adapter, generic agent executor, or retriever.
- No automated always-on network test in the ordinary test suite.
- No claim that a semantic recommendation proves task success or makes tool
  execution safe.

## Runtime behavior

The examples are launched explicitly with `python examples/<file>.py`. They
load their normal `JevClient` configuration from the environment. When the
credential is absent or invalid, the example presents a short actionable
failure without manufacturing an evaluator result. A successful live run
prints only its final local/review action, status, and safe reason category.

An opt-in command, documented in the README, runs both examples in live mode.
It is separate from `python -m unittest discover -s tests -v`; CI and ordinary
local tests remain network-free. The live command is successful only if each
example obtains a well-formed real decision or an explicitly typed
`UNAVAILABLE` outcome. It never treats an unavailable service as proof that a
review decision works.

## Test strategy

Unit tests cover the application-owned orchestration without external I/O:

- a terminal `LoopTerminator` result prevents the Agent reviewer checkpoint;
- the Agent invokes the reviewer only after its configured checkpoint;
- RAG builds a derived evidence summary and does not forward source documents;
- missing credentials fail before client invocation; and
- displayed results are safe summaries rather than raw states or responses.

The opt-in live command is the provider validation layer. It uses the current
real environment credentials and asserts only stable protocol guarantees:
typed result, an allowed action or `None`, and no secret leakage in stdout.

## Integration boundary

The examples call the public `jevshield` API only. Existing LangChain support
continues to guard tool invocation independently. A future framework adapter
may translate that framework's state into the same `LoopStep` and
`LoopReviewInput` values only after a real production framework is selected
and evaluated.
