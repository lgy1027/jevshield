# Examples

Choose an example by the kind of integration you are building. JevShield stays
a pre-check layer in every case: your application owns Agent invocation,
delegation, retries, and the final response.

## Start here: runnable without credentials

| Example | What it demonstrates |
| --- | --- |
| `00_minimal_agent.py` | Router selects an application-owned role; a child role calls a Guard-protected tool. |
| `01_async_and_sql.py` | Sync and async Guard calls, including local Fast-Deny. |
| `02_langchain_integration.py` | Fresh guarded LangChain Tool instances on every build. |
| `03_custom_client.py` | Offline custom-client configuration; replace the explicit empty key with a real key only in an application deployment. |

Run one with:

```bash
git clone https://github.com/lgy1027/jevshield.git
cd jevshield
python -m pip install -e .
python examples/00_minimal_agent.py
```

For `02_langchain_integration.py`, install the optional dependency from the
same checkout with `python -m pip install -e ".[langchain]"`.

## Real Jev demonstrations: require a credential

Export `JEV_API_KEY`, `TYPESAFE_API_KEY`, or `OPENROUTER_API_KEY` before using
these scripts. They call the real decision service and are deliberately not
the first-run path.

| Example | What it demonstrates |
| --- | --- |
| `04_live_agent_loop.py` | Guarded Agent step, local loop control, semantic checkpoint. |
| `05_live_rag_checkpoint.py` | RAG evidence summary sent to a semantic checkpoint, never source documents. |

## Development evaluations: not application tutorials

These scripts measure or calibrate bounded behavior. They do not belong in a
production request path.

| Example | Purpose |
| --- | --- |
| `06_live_loop_review_eval.py` | Aggregate semantic checkpoint smoke evaluation. |
| `07_live_multi_agent_handoff_eval.py` | Real routing plus a tracked child return and second delegation. |
| `08_live_multi_agent_handoff_stability_eval.py` | Repeats the handoff evaluation and reports aggregate stability. |
| `09_live_multi_agent_prompt_calibration_eval.py` | Compares candidate routing prompts with aggregate metrics. |
