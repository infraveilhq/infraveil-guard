"""Classify the blast radius of an action an AI agent is about to take.

Pure stdlib, no network, no state. Given a command, SQL statement, or tool
invocation as text, it returns a structured risk assessment: the highest
severity matched, the specific dangerous capabilities found, whether the action
is reversible, and a plain-language recommendation.

This is deliberately conservative about *destruction* (the thing that ends a
company) and quiet about ordinary work. It is readable on purpose  -  you should
be able to audit exactly why your guard blocked something.
"""

from __future__ import annotations

import re
from typing import Any

SEVERITY_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class Rule:
    __slots__ = ("id", "severity", "label", "pattern", "irreversible", "why")

    def __init__(self, id, severity, label, pattern, irreversible, why):
        self.id = id
        self.severity = severity
        self.label = label
        self.pattern = re.compile(pattern, re.IGNORECASE) if pattern else None
        self.irreversible = irreversible
        self.why = why


_DELETE_NO_WHERE = re.compile(r"\bdelete\s+from\b((?!\bwhere\b).)*$", re.IGNORECASE | re.DOTALL)
_UPDATE_NO_WHERE = re.compile(r"\bupdate\s+\w[\w.\"`\[\]]*\s+set\b((?!\bwhere\b).)*$", re.IGNORECASE | re.DOTALL)

RULES = [
    Rule("no_preserve_root", "critical", "rm with --no-preserve-root",
         r"--no-preserve-root", True, "Explicitly removes the safety that stops rm from eating /."),
    Rule("drop_db", "critical", "DROP DATABASE / SCHEMA",
         r"\bdrop\s+(?:database|schema)\b", True, "Destroys an entire database. Irreversible without a backup."),
    Rule("drop_table", "critical", "DROP TABLE",
         r"\bdrop\s+table\b", True, "Destroys a table and its data. Irreversible without a backup."),
    Rule("truncate", "critical", "TRUNCATE",
         r"\btruncate\s+table\b|\btruncate\s+\w", True, "Empties a table instantly; usually not transactional. Irreversible without a backup."),
    Rule("mkfs_dd", "critical", "Disk format / raw block write",
         r"\bmkfs(\.\w+)?\b|\bdd\b[^\n]*\bof=/dev/|>\s*/dev/(sd|nvme|disk|hd)", True, "Formats or overwrites a block device. Destroys everything on it."),
    Rule("fork_bomb", "critical", "Fork bomb",
         r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", True, "Process fork bomb  -  will hang or crash the host."),
    Rule("tf_destroy", "critical", "terraform destroy",
         r"\bterraform\s+destroy\b", True, "Tears down all managed infrastructure. Irreversible for stateful resources."),
    Rule("cloud_delete", "critical", "Delete/terminate cloud resources",
         r"\b(?:aws|gcloud|az)\b[^\n]*(?:\bterminate-instances\b|\bdelete-bucket\b|\brb\b[^\n]*--force|\bdelete-db-instance\b|\bdelete-cluster\b|\bdelete-stack\b|\binstances\s+delete\b|\bsql\s+instances\s+delete\b)",
         True, "Deletes or terminates managed cloud resources (DBs, buckets, instances). Often irreversible."),
    Rule("k8s_delete_broad", "critical", "kubectl delete namespace / --all",
         r"\bkubectl\s+delete\b[^\n]*(?:\bnamespace\b|--all\b)", True, "Deletes a whole namespace or every object of a kind."),
    Rule("delete_no_where", "critical", "DELETE without WHERE",
         None, True, "DELETE FROM with no WHERE clause removes every row in the table."),
    Rule("update_no_where", "high", "UPDATE without WHERE",
         None, False, "UPDATE with no WHERE clause rewrites every row in the table."),
    Rule("find_delete", "high", "find ... -delete / -exec rm",
         r"\bfind\b[^\n]*(?:-delete\b|-exec\s+rm\b)", True, "find can delete many files in one pass; check the path and predicate."),
    Rule("force_push", "high", "git push --force",
         r"\bgit\s+push\b[^\n]*(?:--force\b|-f\b|\+\w)", False, "Force-push can overwrite shared history and orphan commits. Hard to recover."),
    Rule("git_reset_hard", "medium", "git reset --hard",
         r"\bgit\s+reset\s+--hard\b", False, "Discards uncommitted work and moves the branch. Recoverable via reflog for a while."),
    Rule("git_clean", "medium", "git clean -fd",
         r"\bgit\s+clean\b[^\n]*-\w*f", True, "Deletes untracked files permanently; they are not in git history."),
    Rule("pipe_to_shell", "high", "Pipe remote content into a shell",
         r"\b(?:curl|wget|iwr|invoke-webrequest)\b[^\n|]*\|\s*(?:sudo\s+)?(?:bash|sh|zsh|python\d?|node|pwsh|powershell)\b",
         False, "Runs code downloaded from the internet with no review  -  classic supply-chain / RCE risk."),
    Rule("chmod_777", "high", "World-writable permissions",
         r"\bchmod\s+(?:-\w+\s+)*(?:0?777|a\+rwx|ugo\+rwx)\b", False, "Makes files world-writable; a common privilege-escalation foothold."),
    Rule("chown_recursive", "medium", "Recursive ownership change",
         r"\bchown\s+(?:-\w*\s+)*-\w*[rR]\b", False, "Recursively changes ownership; can lock you out of files or break a service."),
    Rule("firewall_flush", "high", "Flush firewall rules",
         r"\biptables\s+-F\b|\bufw\s+disable\b|\bnft\s+flush\s+ruleset\b", False, "Drops all firewall rules  -  exposes the host."),
    Rule("kill_broad", "medium", "Mass process kill",
         r"\bpkill\b|\bkillall\b|\bkill\s+-9\s+-1\b", False, "Kills processes by name/pattern; easy to take down the wrong thing."),
    Rule("k8s_delete", "high", "kubectl delete",
         r"\bkubectl\s+delete\b", False, "Deletes a Kubernetes resource. Controllers may not recreate stateful ones."),
    Rule("docker_prune", "high", "docker prune / volume rm",
         r"\bdocker\s+(?:system\s+prune|volume\s+rm)\b|\bdocker\s+volume\s+prune\b", True, "Removes volumes/images; named-volume data does not come back."),
    Rule("secrets_exfil", "high", "Send secrets/env over the network",
         r"(?:printenv|env|cat\s+[^\n|]*\.env|cat\s+[^\n|]*(?:id_rsa|credentials|secrets))\b[^\n]*\|\s*(?:curl|wget|nc|netcat)\b|\b(?:curl|wget)\b[^\n]*(?:\$[A-Z_]*(?:TOKEN|KEY|SECRET|PASSWORD)|--data[^\n]*(?:token|secret|password))",
         False, "Pipes credentials or environment to a network destination  -  possible exfiltration."),
    Rule("sudo", "medium", "Elevated privileges (sudo)",
         r"(?:^|\s|;|&&|\|)\s*sudo\s+\S", False, "Runs with root privileges; widens the blast radius of whatever follows."),
    Rule("deploy_prod", "medium", "Production deploy / migration",
         r"\b(?:deploy[_-]?prod\w*|deploy\s+(?:--)?prod\w*|alembic\s+downgrade|flask\s+db\s+downgrade|prisma\s+migrate\s+reset|rails\s+db:drop)\b",
         False, "Changes production or a schema. Have a rollback path before running."),
    Rule("overwrite_redirect", "low", "Overwrites a file via redirect",
         r"(?<![>\d])>(?!>)\s*[^\s&|]+", False, "A single > overwrites the target file. Use >> to append if you meant to keep it."),
]


_RM_SEG = re.compile(r"\brm\b([^;&|]*)", re.IGNORECASE)
_BROAD_TARGET = re.compile(
    r"^(?:/|~|\$HOME|\*|/\*|\.\.?/\*|"
    r"/(?:bin|boot|dev|etc|home|lib|lib64|opt|proc|root|run|sbin|srv|sys|usr|var)(?:/\*?)?)$",
    re.IGNORECASE)


def _rm_hits(text):
    hits = []
    for m in _RM_SEG.finditer(text):
        seg = m.group(1)
        toks = seg.split()
        shorts = [t for t in toks if re.match(r"^-[a-z]+$", t, re.IGNORECASE)]
        longs = [t.lower() for t in toks if t.startswith("--")]
        recursive = ("--recursive" in longs) or any("r" in t[1:].lower() for t in shorts)
        force = ("--force" in longs) or any("f" in t[1:].lower() for t in shorts)
        if not recursive:
            continue
        targets = [t for t in toks if not t.startswith("-")]
        broad = ("*" in seg) or any(_BROAD_TARGET.match(t) for t in targets) or any(t in ("/", "~", "$HOME") for t in targets)
        severity = "critical" if broad else "high"
        why = ("Recursive delete targeting a root, system, or wildcard path can erase the machine. Irreversible."
               if broad else "Recursive force delete. Check the path before running; there is no undo.")
        hits.append({
            "id": "rm_recursive", "severity": severity, "label": "Recursive file delete",
            "irreversible": True, "why": why, "matched": ("rm" + seg).strip()[:80],
        })
    return hits


def _matches(rule, text):
    if rule.id == "delete_no_where":
        return _DELETE_NO_WHERE.search(text)
    if rule.id == "update_no_where":
        return _UPDATE_NO_WHERE.search(text)
    return rule.pattern.search(text)


def classify(action: str) -> dict[str, Any]:
    text = (action or "").strip()
    if not text:
        return {
            "risk": "none", "reversible": True, "categories": [],
            "summary": "Empty action  -  nothing to assess.",
            "recommendation": "allow",
        }

    hits = []
    for rule in RULES:
        m = _matches(rule, text)
        if not m:
            continue
        matched = str(m.group(0)).strip()[:80]
        hits.append({
            "id": rule.id, "severity": rule.severity, "label": rule.label,
            "irreversible": rule.irreversible, "why": rule.why, "matched": matched,
        })

    hits.extend(_rm_hits(text))

    if not hits:
        return {
            "risk": "none", "reversible": True, "categories": [],
            "summary": "No destructive or high-risk capability detected.",
            "recommendation": "allow",
        }

    risk = max(hits, key=lambda h: SEVERITY_ORDER[h["severity"]])["severity"]
    irreversible = any(h["irreversible"] for h in hits)
    top = sorted(hits, key=lambda h: SEVERITY_ORDER[h["severity"]], reverse=True)
    lead = top[0]["label"].lower()
    extra = f" (+{len(hits) - 1} more)" if len(hits) > 1 else ""
    summary = f"{risk.upper()} risk: {lead}{extra}." + (" Irreversible." if irreversible else "")
    recommendation = "block_pending_approval" if SEVERITY_ORDER[risk] >= SEVERITY_ORDER["high"] else "allow_with_log"

    return {
        "risk": risk,
        "reversible": not irreversible,
        "categories": top,
        "summary": summary,
        "recommendation": recommendation,
    }
