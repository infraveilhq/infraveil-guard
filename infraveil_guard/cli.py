"""infraveil-guard command line.

With no arguments (or `serve`) it runs the MCP server over stdio  -  this is what
your MCP client launches. The other subcommands are for the human in the loop:

    infraveil-guard approvals          list actions blocked waiting for approval
    infraveil-guard approve <id>       review one and mint a one-time code
    infraveil-guard deny <id>          reject a blocked action
    infraveil-guard verify             verify the tamper-evident ledger
    infraveil-guard log [N]            show recent decisions
    infraveil-guard home               print the state directory
"""

from __future__ import annotations

import json
import sys

from . import core, store


def _serve() -> None:
    from .server import run
    run()


def _approvals() -> int:
    items = core.pending_list()
    if not items:
        print("Nothing is waiting for approval.")
        return 0
    print(f"{len(items)} action(s) blocked, waiting for approval:\n")
    for it in items:
        print(f"  [{it['action_id']}]  {it['risk'].upper():<8}  {it.get('summary', '')}")
        print(f"            {(it.get('action') or '')[:150]}")
        print(f"            approve with:  infraveil-guard approve {it['action_id']}\n")
    return 0


def _approve(rest: list[str]) -> int:
    args = [a for a in rest if not a.startswith("-")]
    yes = "--yes" in rest or "-y" in rest
    if not args:
        print("usage: infraveil-guard approve <action_id> [--yes]")
        return 2
    matches = [x for x in core.pending_list() if x["action_id"].startswith(args[0])]
    if not matches:
        print(f"No pending action matching '{args[0]}'. Run `infraveil-guard approvals`.")
        return 1
    if len(matches) > 1:
        print(f"'{args[0]}' is ambiguous  -  matches {len(matches)} actions. Use the full id.")
        return 1
    it = matches[0]
    print("\n  Action requesting approval")
    print(f"  id:        {it['action_id']}")
    print(f"  risk:      {it['risk'].upper()}  ({'reversible' if it.get('reversible', False) else 'IRREVERSIBLE'})")
    print(f"  why:       {it.get('summary', '')}")
    if it.get("categories"):
        print(f"  flags:     {', '.join(it['categories'])}")
    print(f"\n  command:\n    {it.get('action', '')}\n")
    if not yes:
        try:
            ans = input("  Approve this action? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            ans = ""
        if ans not in ("y", "yes"):
            print("  Left blocked. Run with the action and it stays pending.")
            return 0
    res = core.mint_approval(it["action_id"])
    if not res.get("ok"):
        print(f"  {res.get('message')}")
        return 1
    print("\n  APPROVED. Give the agent this one-time code:\n")
    print(f"      {res['code']}\n")
    print(f"  It is valid for {res['ttl_seconds'] // 60} minutes and works exactly once.")
    print("  The agent should call guard_action again with approval_code set to it.\n")
    return 0


def _deny(rest: list[str]) -> int:
    if not rest:
        print("usage: infraveil-guard deny <action_id>")
        return 2
    res = core.deny(rest[0])
    if not res.get("ok"):
        print(res.get("message"))
        return 1
    print(f"Denied and removed {res['action_id']}.")
    return 0


def _verify() -> int:
    res = core.verify_ledger()
    print(json.dumps(res, indent=2))
    return 0 if res.get("ok") else 1


def _log(rest: list[str]) -> int:
    n = 20
    if rest and rest[0].isdigit():
        n = int(rest[0])
    for e in core.recent(n):
        print(json.dumps(e, separators=(",", ":")))
    return 0


def main(argv=None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("serve", "stdio"):
        _serve()
        return
    cmd, rest = argv[0], argv[1:]
    if cmd in ("approvals", "pending", "list"):
        code = _approvals()
    elif cmd == "approve":
        code = _approve(rest)
    elif cmd == "deny":
        code = _deny(rest)
    elif cmd in ("verify", "verify-ledger"):
        code = _verify()
    elif cmd in ("log", "ledger", "recent"):
        code = _log(rest)
    elif cmd in ("home", "where"):
        print(store.home())
        code = 0
    elif cmd in ("-h", "--help", "help"):
        print(__doc__)
        code = 0
    else:
        print(f"unknown command '{cmd}'. Try `infraveil-guard --help`.")
        code = 2
    sys.exit(code)


if __name__ == "__main__":
    main()
