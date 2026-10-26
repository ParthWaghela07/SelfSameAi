"""Run with:  python -m pytest -q   (or just: python tests/test_core.py)"""
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.scenarios import build, SCENARIOS, P, S, F, H   # noqa: E402
from core.gateway import THRESH                            # noqa: E402


def run(key, seed=3, **kw):
    gw = build(seed=seed, **kw)
    SCENARIOS[key][1](gw, random.Random(seed + 100))
    return gw


def stopped(gw, label="malicious"):
    return [e for e in gw.live_events() if e.label == label and e.level >= 2]


def test_normal_day_has_no_stops():
    gw = run("normal_day")
    assert not [e for e in gw.live_events() if e.level >= 2]


def test_same_file_different_role():
    """HR reading salaries is normal; the Procurement Agent reading them is not."""
    gw = build()
    assert gw.read_file(H, "hr/salaries.xlsx").score < THRESH["watch"]
    assert gw.read_file(P, "hr/salaries.xlsx").score >= THRESH["approval"]


def test_poisoned_pdf_attack_is_stopped_and_traced():
    gw = run("injected_exfil")
    assert stopped(gw)
    assert gw.states[P].status == "quarantined"
    ev = stopped(gw)[0]
    assert ev.cause == "inbox/quote_globex.pdf"
    assert not [e for e in gw.live_events() if e.action == "send_data" and e.outcome == "allowed" and e.label == "malicious"]


def test_chain_attack_names_the_carrier():
    gw = run("chain")
    ev = stopped(gw)[0]
    assert ev.via == [S]
    assert P in gw.states[S].at_risk_from


def test_honeypot_inside_allowed_zone_is_caught_only_with_honeypots():
    assert stopped(run("honeypot"))
    off = build(features={"contract", "baseline", "taint", "chain", "budget"})
    SCENARIOS["honeypot"][1](off, random.Random(1))
    assert not stopped(off)


def test_mimicry_lookalike_domain_is_held():
    assert stopped(run("mimicry"))


def test_volume_dump_to_legit_destination_is_held():
    assert stopped(run("volume_dump"))


def test_slow_drift_needs_the_drift_budget():
    assert stopped(run("slow_drift"))
    gw = build(features={"contract", "baseline", "taint", "chain", "honeypot"})
    SCENARIOS["slow_drift"][1](gw, random.Random(1))
    assert not stopped(gw)


def test_cold_start_agent_is_judged_by_its_role():
    gw = run("cold_start")
    assert stopped(gw)


def test_registered_change_is_not_drift_but_unregistered_is():
    assert not [e for e in run("legit_registered").live_events() if e.level >= 2]
    assert [e for e in run("legit_unregistered").live_events() if e.level >= 2]


def test_restricted_agent_keeps_doing_its_normal_job():
    gw = run("injected_exfil")
    gw2 = build()
    gw2.read_file(P, "inbox/quote_globex.pdf")
    gw2.read_file(P, "hr/salaries.xlsx")                       # -> restricted
    assert gw2.states[P].status in ("restricted", "quarantined")
    if gw2.states[P].status == "restricted":
        assert gw2.read_file(P, "procurement/supplier_prices.csv").allowed
    assert gw.states[F].status == "normal"                      # other agents untouched


def test_monitor_only_mode_lets_everything_through():
    gw = build(enforce=False)
    SCENARIOS["injected_exfil"][1](gw, random.Random(1))
    leaked = [e for e in gw.live_events() if e.action == "send_data" and e.outcome == "allowed"]
    assert leaked and gw.alerts()


def test_baseline_is_not_poisoned_by_attacks():
    gw = build()
    before = gw.baselines.agent[P].n
    gw.read_file(P, "hr/salaries.xlsx")
    assert gw.baselines.agent[P].n == before


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print("ok  ", fn.__name__)
    print(f"\n{len(fns)} tests passed")
