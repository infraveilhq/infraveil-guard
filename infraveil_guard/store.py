"""On-disk state for the guard: where the ledger lives and the queue of actions
that are blocked waiting for a human to approve them out of band.

Everything lives under one directory (default ~/.infraveil-guard, override with
INFRAVEIL_GUARD_HOME). No network, no database  -  just files you own.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Any


def home() -> str:
    d = os.environ.get("INFRAVEIL_GUARD_HOME") or os.path.join(os.path.expanduser("~"), ".infraveil-guard")
    os.makedirs(d, exist_ok=True)
    return d


def ledger_path() -> str:
    return os.path.join(home(), "ledger.jsonl")


def pending_path() -> str:
    return os.path.join(home(), "pending.json")


def now() -> int:
    return int(time.time())


def action_id(action: str) -> str:
    return hashlib.sha256((action or "").strip().encode("utf-8")).hexdigest()[:12]


def code_hash(code: str) -> str:
    return hashlib.sha256(("infraveil-guard:" + (code or "")).encode("utf-8")).hexdigest()


def load_pending() -> dict[str, Any]:
    p = pending_path()
    if not os.path.exists(p):
        return {}
    try:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def save_pending(data: dict[str, Any]) -> None:
    p = pending_path()
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, separators=(",", ":"))
    os.replace(tmp, p)
