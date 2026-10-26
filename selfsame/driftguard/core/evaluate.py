"""Benchmark on the simulator: detection, false alarms, damage prevented, and ablations.

IMPORTANT: these are results on a scripted simulation we built ourselves. They show the
logic works and which component catches which attack. They are NOT real-world accuracy.
"""
from __future__ import annotations
import random
from . import world
from .gateway import ALL_FEATURES
from .scenarios import SCENARIOS, build, benign_session, AGENTS

SEEDS = range(10)
ATTACKS = [k for k, v in SCENARIOS.items() if v[2]]
INJECTION_ATTACKS = {"injected_exfil", "chain", "cold_start"}


def _run(key: str, seed: int, features=None, enforce=True):
    gw = build(features=features, enforce=enforce, seed=seed)
    SCENARIOS[key][1](gw, random.Random(seed + 100))
    return gw


def _attack_stats(gw) -> dict:
    mal = [e for e in gw.live_events() if e.label == "malicious"]
    first = next((i for i, e in enumerate(mal, 1) if e.level >= 2), None)
    return {
        "detected": first is not None,
        "ttd": first,   # number of malicious actions seen up to and including the first stop
        "offrole_reads_through": sum(1 for e in mal if e.action == "read_file" and e.outcome == "allowed" and e.level >= 1),
        "kb_leaked": sum(e.size_kb for e in mal if e.action == "send_data" and e.outcome == "allowed" and not world.is_internal(e.target)),
        "kb_attempted": sum(e.size_kb for e in mal if e.action == "send_data" and not world.is_internal(e.target)),
        # did the alert name the poisoned file (and, in a chain, the agent that carried it)?
        "named_source": any(e.cause == "inbox/quote_globex.pdf" for e in mal if e.level >= 2),
        "named_carrier": any(e.via for e in mal if e.level >= 2),
    }


def evaluate_attacks(features=None) -> dict:
    out = {}
    for key in ATTACKS:
        runs = [_attack_stats(_run(key, s, features)) for s in SEEDS]
        det = [r for r in runs if r["detected"]]
        out[key] = {
            "detection_rate": len(det) / len(runs),
            "mean_actions_before_stop": round(sum(r["ttd"] for r in det) / len(det), 1) if det else None,
            "kb_leaked": round(sum(r["kb_leaked"] for r in runs) / len(runs)),
            "kb_attempted": round(sum(r["kb_attempted"] for r in runs) / len(runs)),
            "source_named_rate": round(sum(r["named_source"] for r in det) / len(det), 2) if det and key in INJECTION_ATTACKS else None,
        }
    return out


def evaluate_false_alarms(sessions_per_agent: int = 60, seeds=range(5)) -> dict:
    total = flagged = watched = 0
    for s in seeds:
        gw = build(seed=s)
        rng = random.Random(s + 500)
        gw.label = "benign"
        for _ in range(sessions_per_agent):
            for a in AGENTS:
                benign_session(gw, a, rng)
        ev = gw.live_events()
        total += len(ev)
        flagged += sum(1 for e in ev if e.level >= 2)
        watched += sum(1 for e in ev if e.level == 1)
    return {"benign_actions": total, "held_or_blocked": flagged, "watch_only": watched,
            "false_stop_rate": round(flagged / total, 5) if total else 0.0}


def evaluate_legit_changes() -> dict:
    res = {}
    for key in ("legit_registered", "legit_unregistered"):
        stops = []
        for s in SEEDS:
            gw = _run(key, s)
            ev = [e for e in gw.live_events() if e.label == "benign" and e.target in ("finance/invoices.csv", "procurement/audit_notes.csv")]
            stops.append(sum(1 for e in ev if e.level >= 2))
        res[key] = {"avg_legit_actions_stopped": round(sum(stops) / len(stops), 2)}
    return res


ABLATIONS = {
    "Full system": None,
    "No role contract": ALL_FEATURES - {"contract"},
    "No learned baseline": ALL_FEATURES - {"baseline"},
    "No injection tracing": ALL_FEATURES - {"taint"},
    "No drift budget": ALL_FEATURES - {"budget"},
    "No honeypots": ALL_FEATURES - {"honeypot"},
}


def evaluate_ablation() -> dict:
    out = {}
    for name, feats in ABLATIONS.items():
        res = evaluate_attacks(feats)
        out[name] = {k: v["detection_rate"] for k, v in res.items()}
        out[name]["_source_named"] = res["injected_exfil"]["source_named_rate"]
    return out


def run_all() -> dict:
    return {
        "attacks": evaluate_attacks(),
        "false_alarms": evaluate_false_alarms(),
        "legit_changes": evaluate_legit_changes(),
        "ablation": evaluate_ablation(),
        "iam_only": {"detection_rate": 0.0, "note": "every attack action uses a valid token, so permission checks alone stop none of them"},
        "attack_titles": {k: SCENARIOS[k][0] for k in ATTACKS},
    }


if __name__ == "__main__":
    r = run_all()
    print("\nATTACK DETECTION (10 runs each)")
    for k, v in r["attacks"].items():
        print(f"  {SCENARIOS[k][0]:52} detected {v['detection_rate']:.0%}  actions before stop {v['mean_actions_before_stop']}  leaked {v['kb_leaked']} KB of {v['kb_attempted']} KB attempted")
    print("\nFALSE ALARMS (benign)", r["false_alarms"])
    print("LEGIT CHANGES", r["legit_changes"])
    print("\nABLATION (detection rate per attack)")
    heads = list(r["attacks"])
    print(" " * 24 + " ".join(f"{h[:9]:>9}" for h in heads) + "  names-trigger")
    for name, row in r["ablation"].items():
        print(f"  {name:22}" + " ".join(f"{row[h]:>9.0%}" for h in heads) + f"  {row['_source_named']:.0%}")
