"""A local, append-only, tamper-evident ledger of every guard decision.

Each line is a JSON record hash-chained to the one before it: the record's
"hash" is sha256 over its canonical form, and "prev" links to the prior
record's hash, with a monotonic "seq". Editing, deleting, reordering, or
inserting any line breaks the chain  -  and verify() will tell you exactly where.

This is plain stdlib you can read and reimplement. The guard never phones home;
the ledger is your evidence, on your disk, that you can inspect at any time.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from typing import Any, Optional

_LOCK = threading.Lock()


def _canonical(obj) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _hash_record(rec: dict) -> str:
    body = {k: v for k, v in rec.items() if k != "hash"}
    return hashlib.sha256(_canonical(body)).hexdigest()


def _read_lines(path: str) -> list[str]:
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return [ln for ln in f.read().splitlines() if ln.strip()]


def head(path: str) -> tuple[Optional[str], int]:
    lines = _read_lines(path)
    if not lines:
        return None, 0
    last = json.loads(lines[-1])
    return last.get("hash"), int(last.get("seq", 0))


def append(path: str, entry: dict[str, Any], now_ts: int) -> dict[str, Any]:
    with _LOCK:
        prev_hash, prev_seq = head(path)
        rec = dict(entry)
        rec["seq"] = prev_seq + 1
        rec["ts"] = int(now_ts)
        rec["prev"] = prev_hash or ""
        rec["hash"] = _hash_record(rec)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, separators=(",", ":"), ensure_ascii=False) + "\n")
        return rec


def verify(path: str) -> dict[str, Any]:
    lines = _read_lines(path)
    if not lines:
        return {"ok": True, "count": 0, "head": None, "message": "Ledger is empty."}
    prev_hash = None
    prev_seq = None
    for i, raw in enumerate(lines, 1):
        try:
            rec = json.loads(raw)
        except json.JSONDecodeError as exc:
            return {"ok": False, "count": i, "message": f"entry {i}: invalid JSON ({exc})"}
        stored = rec.get("hash")
        if not stored:
            return {"ok": False, "count": i, "message": f"entry {i}: missing hash"}
        if _hash_record(rec) != stored:
            return {"ok": False, "count": i, "message": f"TAMPERED at seq {rec.get('seq')}: record was modified (hash mismatch)"}
        seq = rec.get("seq")
        if prev_hash is not None:
            if rec.get("prev") != prev_hash:
                return {"ok": False, "count": i, "message": f"BROKEN CHAIN at seq {seq}: prev link does not match the prior entry"}
            if seq != prev_seq + 1:
                return {"ok": False, "count": i, "message": f"SEQUENCE GAP: expected seq {prev_seq + 1}, found {seq}"}
        prev_hash = stored
        prev_seq = seq
    return {"ok": True, "count": len(lines), "head": prev_hash,
            "message": f"Hash chain verified across {len(lines)} entries - no tampering."}


def tail(path: str, limit: int = 20) -> list[dict[str, Any]]:
    lines = _read_lines(path)
    out = []
    for raw in lines[-limit:]:
        try:
            out.append(json.loads(raw))
        except json.JSONDecodeError:
            continue
    return list(reversed(out))
