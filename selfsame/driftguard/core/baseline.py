"""Learned behaviour baselines.

Three layers so that every hard case in the problem statement has an answer:
  * per-agent profile      -> what THIS agent normally does
  * per-role profile       -> new agents of the same role inherit it (little/no history)
  * frozen snapshot        -> never moves, so slow drift cannot "drag" the baseline along
Only clean, allowed, low-risk events are ever learned (baseline-poisoning protection).
"""
from __future__ import annotations
import copy
import math
from collections import Counter

MIN_EVENTS_TO_TRUST = 20   # below this a profile is not used (cold start -> contract only)
FREEZE_AT = 60             # snapshot a frozen copy after this many clean events


class Profile:
    def __init__(self) -> None:
        self.n = 0
        self.combos: Counter = Counter()    # (action, zone)
        self.bigrams: Counter = Counter()   # (previous action, action)
        self.zones: Counter = Counter()
        self.send_sizes: list[int] = []

    def update(self, action: str, zone: str | None, prev_action: str | None, size_kb: int) -> None:
        self.n += 1
        self.combos[(action, zone)] += 1
        self.bigrams[(prev_action, action)] += 1
        if zone:
            self.zones[zone] += 1
        if action == "send_data":
            self.send_sizes.append(size_kb)

    def knows_combo(self, action: str, zone: str | None) -> bool:
        return self.combos[(action, zone)] > 0

    def knows_bigram(self, prev_action: str | None, action: str) -> bool:
        return self.bigrams[(prev_action, action)] > 0

    def max_send(self) -> int:
        return max(self.send_sizes) if self.send_sizes else 0

    def size_z(self, size_kb: int) -> float | None:
        if len(self.send_sizes) < 5:
            return None
        mean = sum(self.send_sizes) / len(self.send_sizes)
        var = sum((s - mean) ** 2 for s in self.send_sizes) / len(self.send_sizes)
        return (size_kb - mean) / max(math.sqrt(var), 1.0)


def js_distance(a: Counter, b: Counter) -> float:
    """Jensen-Shannon distance (0..1) between two count distributions."""
    keys = set(a) | set(b)
    if not keys:
        return 0.0
    ta, tb = sum(a.values()) or 1, sum(b.values()) or 1
    pa = [a[k] / ta for k in keys]
    pb = [b[k] / tb for k in keys]
    m = [(x + y) / 2 for x, y in zip(pa, pb)]

    def kl(p, q):
        return sum(x * math.log2(x / y) for x, y in zip(p, q) if x > 0)

    return math.sqrt(max(0.0, (kl(pa, m) + kl(pb, m)) / 2))


class BaselineStore:
    def __init__(self) -> None:
        self.agent: dict[str, Profile] = {}
        self.role: dict[str, Profile] = {}
        self.frozen: dict[str, Profile] = {}

    def learn(self, agent_id: str, role: str, action: str, zone: str | None, prev_action: str | None, size_kb: int) -> None:
        for store, key in ((self.agent, agent_id), (self.role, role)):
            store.setdefault(key, Profile()).update(action, zone, prev_action, size_kb)
        p = self.agent[agent_id]
        if p.n == FREEZE_AT and agent_id not in self.frozen:
            self.frozen[agent_id] = copy.deepcopy(p)

    def profile_for(self, agent_id: str, role: str) -> tuple[Profile | None, str]:
        p = self.agent.get(agent_id)
        if p and p.n >= MIN_EVENTS_TO_TRUST:
            return p, "agent"
        r = self.role.get(role)
        if r and r.n >= MIN_EVENTS_TO_TRUST:
            return r, "role"
        return None, "none"
