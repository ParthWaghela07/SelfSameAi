"""Role contracts: the declared job description of each agent role.

A contract is what lets us judge a brand-new agent on day one (no history needed)
and is the "declared role" the problem statement asks us to compare behaviour to.
Admins can also register *planned* changes so legitimate new work is not drift.
"""
from __future__ import annotations
from pathlib import Path
import yaml
from pydantic import BaseModel, Field


class Contract(BaseModel):
    role: str
    description: str = ""
    allowed_actions: list[str]
    read_zones: list[str] = Field(default_factory=list)
    write_zones: list[str] = Field(default_factory=list)
    allowed_domains: list[str] = Field(default_factory=list)
    can_delegate_to: list[str] = Field(default_factory=list)


class ChangeRequest(BaseModel):
    """A planned, admin-approved change to what an agent may do (e.g. a Q4 audit task)."""
    agent_id: str
    reason: str
    add_read_zones: list[str] = Field(default_factory=list)
    add_actions: list[str] = Field(default_factory=list)
    add_domains: list[str] = Field(default_factory=list)
    created_at_event: int = 0
    valid_for_events: int = 40  # expires automatically

    def active(self, now_event: int) -> bool:
        return now_event < self.created_at_event + self.valid_for_events


def load_contracts(directory: str | Path | None = None) -> dict[str, Contract]:
    directory = Path(directory) if directory else Path(__file__).resolve().parent.parent / "contracts"
    out: dict[str, Contract] = {}
    for f in sorted(directory.glob("*.yaml")):
        c = Contract(**yaml.safe_load(f.read_text()))
        out[c.role] = c
    return out


def apply_changes(base: Contract, changes: list[ChangeRequest]) -> Contract:
    if not changes:
        return base
    data = base.model_dump()
    for ch in changes:
        data["read_zones"] = sorted(set(data["read_zones"]) | set(ch.add_read_zones))
        data["allowed_actions"] = sorted(set(data["allowed_actions"]) | set(ch.add_actions))
        data["allowed_domains"] = sorted(set(data["allowed_domains"]) | set(ch.add_domains))
    return Contract(**data)
