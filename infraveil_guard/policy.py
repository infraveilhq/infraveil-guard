"""The policy: how risky an action has to be before a human must approve it.

Two knobs, both environment variables, both with safe defaults:

  INFRAVEIL_GUARD_THRESHOLD   none|low|medium|high|critical   (default: high)
      Actions at or above this severity are gated  -  blocked until a human
      approves them out of band.

  INFRAVEIL_GUARD_MODE        enforce|audit                   (default: enforce)
      enforce: gate per the threshold (the agent must wait for approval).
      audit:   never block; record everything and let the agent proceed.
               Use this to watch what your agent does before you trust the gate.
"""

from __future__ import annotations

import os
from typing import Any

from .classify import SEVERITY_ORDER

_DEFAULT_THRESHOLD = "high"
_DEFAULT_MODE = "enforce"


def threshold() -> str:
    t = (os.environ.get("INFRAVEIL_GUARD_THRESHOLD") or _DEFAULT_THRESHOLD).strip().lower()
    return t if t in SEVERITY_ORDER else _DEFAULT_THRESHOLD


def mode() -> str:
    m = (os.environ.get("INFRAVEIL_GUARD_MODE") or _DEFAULT_MODE).strip().lower()
    return m if m in ("enforce", "audit") else _DEFAULT_MODE


def decide(classification: dict[str, Any]) -> dict[str, Any]:
    risk = classification.get("risk", "none")
    at_or_above = SEVERITY_ORDER.get(risk, 0) >= SEVERITY_ORDER[threshold()]
    if mode() == "audit":
        return {"gate": False, "reason": "audit mode  -  recorded, not blocked", "threshold": threshold(), "mode": "audit"}
    if at_or_above:
        return {"gate": True, "reason": f"risk '{risk}' is at or above threshold '{threshold()}'", "threshold": threshold(), "mode": "enforce"}
    return {"gate": False, "reason": f"risk '{risk}' is below threshold '{threshold()}'", "threshold": threshold(), "mode": "enforce"}
