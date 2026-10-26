# SelfSameAi: identity drift detection for autonomous AI agents

Prototype for the D3COY 1.0 problem statement. Credentials are always valid in every scenario;
the system judges **behaviour against the declared role**, explains each alert with a 0-100 risk
score, and restricts or isolates the agent without stopping its normal work.

## Run it

```bash
pip install -r requirements.txt
python tests/test_core.py        # 13 tests, a few seconds
python -m core.evaluate          # benchmark + ablation table (about 6 s)
python server.py                 # dashboard at http://127.0.0.1:5000
```

Python 3.10+ (developed on 3.13). No internet, API keys or GPU needed.

## What is in it

| Folder / file | What it does |
|---|---|
| `contracts/*.yaml` | Role contracts: allowed actions, data zones, destinations, who it may delegate to |
| `core/world.py` | Fake company: zones with sensitivity, a clean and a poisoned supplier PDF, decoy files |
| `core/gateway.py` | Every agent action passes here: score, decide, enforce, record, learn |
| `core/baseline.py` | Per-agent, per-role and frozen baselines (learns only clean actions) |
| `core/trace.py` | Spots instruction-like text in documents so alerts can name the trigger |
| `core/scenarios.py` | Scripted agents, 7 attacks, 2 legitimate-change cases |
| `core/evaluate.py` | Detection, false alarms, damage prevented, ablation (one component off at a time) |
| `server.py`, `static/index.html` | Flask dashboard: live agents, Drift Report Cards, chain graph, contracts, evaluation |

## How each hard part of the problem is handled

| Challenge | Answer in the code |
|---|---|
| Valid credentials hide the attack | Actions are scored against the role contract, not permissions |
| Indirect prompt injection | Documents are scanned; the alert names the file read just before the change |
| Legitimate change vs drift | Admin-registered, auto-expiring changes; unregistered ones are held for a human, not quarantined |
| Little or no history | New agents inherit the role baseline and are judged by the contract from action one |
| Chains of agents | Delegation tracking; poison read by a sub-agent is traced back through the chain; carriers marked at risk |
| Evasion | Destination and volume are scored (copying order does not help); a drift budget adds up small steps; decoys; frozen baseline; baseline learns only clean actions |

Response ladder: 0-29 allow, 30-59 watch, 60-79 hold for approval, 80-94 block and revoke
sensitive access and outside sending (normal work continues), 95+ or decoy touched: quarantine.

## Honest limits (say these in the deck too)

* Agents are **scripted**, not real LLM agents. Results are from our own simulation, not real-world accuracy.
* Benign behaviour is regular, so the 0 false-alarm figure is optimistic.
* Injection detection is rule-based; a paraphrased attack could slip past the *trace* (the role contract still catches the behaviour).
* A big transfer to a legitimate destination is only caught by the volume rule, and a small one is not.
* Held actions have no approve/deny button yet.

## Numbers for slides (from `python -m core.evaluate`, 10 runs per attack)

Always quote them as "on our simulator". Re-run the command and copy the live output rather than trusting this file.
