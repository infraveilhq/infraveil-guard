"""The guard's decision logic, shared by the MCP server (what the agent talks to)
and the CLI (what the human uses to approve).

The one rule that makes this trustworthy: the agent path (guard) NEVER mints or
sees an approval code. Only the human path (approve), run in a separate
terminal, mints the one-time code. So an agent cannot approve its own
destructive action  -  by construction, not by good behavior.
"""

from __future__ import annotations

import hashlib
import secrets
from typing import Any

from . import ledger, policy, store
from .classify import classify

APPROVAL_TTL_SECONDS = 900


def _full_hash(action: str) -> str:
    return hashlib.sha256((action or "").encode("utf-8")).hexdigest()


def _log(event: str, fields: dict[str, Any]) -> dict[str, Any]:
    return ledger.append(store.ledger_path(), {"event": event, **fields}, store.now())


def assess(action: str) -> dict[str, Any]:
    return classify(action)


def guard(action: str, approval_code: str = "") -> dict[str, Any]:
    action = action or ""
    cls = classify(action)
    decision = policy.decide(cls)
    aid = store.action_id(action)
    common = {
        "risk": cls["risk"],
        "reversible": cls["reversible"],
        "assessment": cls["summary"],
        "categories": [c["label"] for c in cls["categories"]],
        "policy": decision,
    }

    if not decision["gate"]:
        rec = _log("allow", {"action": action[:1000], "action_sha256": _full_hash(action),
                             "risk": cls["risk"], "reason": decision["reason"]})
        return {"decision": "allow", "proceed": True, "ledger_seq": rec["seq"],
                "ledger_hash": rec["hash"], **common}

    pend = store.load_pending()
    entry = pend.get(aid)

    if approval_code:
        valid = (
            entry is not None
            and entry.get("status") == "approved"
            and not entry.get("consumed")
            and (store.now() - int(entry.get("approved_ts", 0))) <= APPROVAL_TTL_SECONDS
            and secrets.compare_digest(store.code_hash(approval_code), entry.get("code_hash", ""))
        )
        if valid:
            entry["consumed"] = True
            entry["consumed_ts"] = store.now()
            pend[aid] = entry
            store.save_pending(pend)
            rec = _log("approved", {"action": action[:1000], "action_sha256": _full_hash(action),
                                    "risk": cls["risk"], "action_id": aid, "approved_by": "human"})
            return {"decision": "approved", "proceed": True, "ledger_seq": rec["seq"],
                    "ledger_hash": rec["hash"], **common}
        _log("approval_rejected", {"action_id": aid, "risk": cls["risk"]})
        return {"decision": "denied", "proceed": False, "action_id": aid,
                "reason": "Approval code is invalid, already used, or expired. A human must run "
                          f"`infraveil-guard approve {aid}` in a separate terminal and give you the fresh code.",
                **common}

    if not entry or entry.get("status") != "pending":
        pend[aid] = {
            "action": action[:2000], "action_sha256": _full_hash(action),
            "risk": cls["risk"], "summary": cls["summary"],
            "categories": [c["label"] for c in cls["categories"]],
            "status": "pending", "created_ts": store.now(),
        }
        store.save_pending(pend)
        _log("blocked", {"action": action[:1000], "action_sha256": _full_hash(action),
                         "risk": cls["risk"], "action_id": aid})

    return {
        "decision": "blocked", "proceed": False, "action_id": aid,
        "how_to_approve": (
            f"This action is BLOCKED. A human must review and approve it out of band: in a separate "
            f"terminal run `infraveil-guard approve {aid}`, then give the agent the one-time code it "
            f"prints. You (the agent) cannot approve this yourself."
        ),
        **common,
    }


def mint_approval(action_id_or_prefix: str) -> dict[str, Any]:
    pend = store.load_pending()
    aid = _resolve(action_id_or_prefix, pend, want_status="pending")
    if aid is None:
        return {"ok": False, "message": f"No pending action matching '{action_id_or_prefix}'."}
    code = secrets.token_hex(3)
    entry = pend[aid]
    entry["status"] = "approved"
    entry["code_hash"] = store.code_hash(code)
    entry["approved_ts"] = store.now()
    entry["consumed"] = False
    pend[aid] = entry
    store.save_pending(pend)
    _log("human_approved", {"action_id": aid, "risk": entry.get("risk")})
    return {"ok": True, "action_id": aid, "code": code, "entry": entry, "ttl_seconds": APPROVAL_TTL_SECONDS}


def deny(action_id_or_prefix: str) -> dict[str, Any]:
    pend = store.load_pending()
    aid = _resolve(action_id_or_prefix, pend)
    if aid is None:
        return {"ok": False, "message": f"No action matching '{action_id_or_prefix}'."}
    entry = pend.pop(aid)
    store.save_pending(pend)
    _log("human_denied", {"action_id": aid, "risk": entry.get("risk")})
    return {"ok": True, "action_id": aid, "entry": entry}


def pending_list() -> list[dict[str, Any]]:
    pend = store.load_pending()
    out = []
    for aid, e in pend.items():
        if e.get("status") == "pending":
            out.append({"action_id": aid, **e})
    return sorted(out, key=lambda x: x.get("created_ts", 0), reverse=True)


def verify_ledger() -> dict[str, Any]:
    return ledger.verify(store.ledger_path())


def recent(limit: int = 20) -> list[dict[str, Any]]:
    return ledger.tail(store.ledger_path(), max(1, min(int(limit), 500)))


def _resolve(prefix: str, pend: dict, want_status: str | None = None):
    prefix = (prefix or "").strip()
    if prefix in pend and (want_status is None or pend[prefix].get("status") == want_status):
        return prefix
    matches = [aid for aid in pend if aid.startswith(prefix) and prefix
               and (want_status is None or pend[aid].get("status") == want_status)]
    return matches[0] if len(matches) == 1 else None
