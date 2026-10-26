# Prompt for Google Antigravity

How to use: unzip `driftguard.zip`, open the `driftguard` folder as your workspace in Antigravity,
then paste everything below the line into the agent chat.

---

You are working on **DriftGuard**, a hackathon prototype for the problem statement
"Identity Drift Detection in Autonomous AI Agents" (D3COY 1.0).

## The problem in one paragraph
Companies give AI agents their own tokens and permissions. Security tools only check whether the
credentials are valid, not whether the agent still behaves like the role it was created for. A hidden
instruction in a document, a poisoned tool or a stolen token can change what an agent does while
every permission check still passes. Build a system that learns normal agent behaviour, compares it
with the declared role, detects drift even when credentials are valid, explains every alert with a
risk score, and restricts or isolates the agent without disrupting legitimate work.
Example: a Procurement Agent reads a supplier PDF with a hidden instruction, then opens HR salary
files and sends data to an unknown server.

## What already exists (do not rewrite it, build on it)
Python 3.10+, Flask, PyYAML, Pydantic. Read `README.md` first, then `core/gateway.py`.
* `core/gateway.py`: every agent action goes through `Gateway._act`. It scores the action
  (role contract, learned baseline, injection trace, chain state, drift budget, honeypot), picks a
  response level (allow / watch / hold / restrict / quarantine) and records an `Event` with plain-language reasons.
* `core/scenarios.py`: scripted agents, 7 attack scenarios, 2 legitimate-change scenarios.
* `core/evaluate.py`: detection, false alarms, damage prevented, ablation table.
* `server.py` + `static/index.html`: dashboard (agent cards, Drift Report Cards, chain graph,
  contracts, evaluation, how-it-works).
* `tests/test_core.py`: 13 tests.

## Step 1: verify (do this before changing anything)
1. `pip install -r requirements.txt`
2. `python tests/test_core.py` must print "13 tests passed".
3. `python -m core.evaluate` and read the output.
4. `python server.py`, open http://127.0.0.1:5000, run every scenario button, and open every tab.
Report anything that is broken before you start new work.

## Step 2: improvements, in this order
1. **Approve / Deny for held actions.** Actions at level 2 (HOLD FOR APPROVAL) currently just stop.
   Add a pending-approvals panel with Approve and Deny buttons. Approve lets the action through once
   and, optionally, offers "register as planned change". Deny keeps it blocked. Add tests.
2. **Export a Drift Report Card** as a PNG (or print-friendly page) from the alerts tab, so it can go on a slide.
3. **Optional LLM explanation layer.** Add `core/explain_llm.py` that rewrites an alert summary in
   friendlier language using an LLM if an API key is set in an environment variable, and falls back
   to the existing template text when it is not. The LLM must only explain. It must never change a
   score or a decision.
4. **Replace one scripted agent with a real LLM agent** (for example the Procurement Agent) that
   calls tools through the Gateway, so the demo can show a real model being hijacked by the poisoned
   PDF. Keep the scripted agents for repeatable evaluation.
5. **Persist events** to SQLite so a restart does not lose history.
6. **Screenshots for the PPT.** Use Playwright to capture clean 1600x900 screenshots of: the agent cards after the
   attack, a Drift Report Card, the chain graph, and the evaluation tab. Save them in `docs/shots/`.

## Rules you must follow
* **Rules and statistics decide. An LLM may only explain.** Do not let a model make or change a security decision.
* **Credentials are valid in every scenario.** Never add a feature that depends on a credential being invalid.
* **Do not fabricate numbers.** Everything on the Evaluation tab comes from `core/evaluate.py` running on the
  simulator. Do not hard-code statistics, and do not claim real-world accuracy.
* **Keep the baseline clean.** Only allowed, low-risk actions may update a baseline.
* **Keep the tests passing**, and add tests for each new feature.
* **No external CDNs** in the dashboard; it must work offline.
* Keep the UI simple, readable and accessible (keyboard focus, contrast, no colour-only meaning).
* Keep dependencies minimal. Ask before adding any.

## Done means
* All tests pass, `python -m core.evaluate` runs without errors, and the dashboard shows no console errors.
* Each new feature has a short note in `README.md`.
* You list, at the end, what you changed, what you could not do, and any known limitations.
