"""infraveil-guard  -  an MCP server that puts a governed, tamper-evident gate in
front of the destructive things an AI agent might do.

Wire it into your agent (Claude Code, Cursor, any MCP client) and instruct the
agent: "Before running any shell, SQL, infra, or cloud command, call
guard_action first and only proceed if it returns proceed=true." Dangerous
actions are then classified, blocked pending out-of-band human approval, and
written to a local hash-chained ledger you can inspect.

Offline by design: no account, no network, no telemetry. Run over stdio:
    infraveil-guard
"""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from . import core

mcp = FastMCP("infraveil-guard")


@mcp.tool()
def guard_action(action: str, approval_code: str = "") -> str:
    """Check an action BEFORE you run it. Pass the exact command, SQL statement,
    or tool invocation you are about to execute.

    Returns JSON with `proceed` (true/false). If proceed is false and decision
    is "blocked", the action is dangerous and a human must approve it out of
    band: tell the user to run `infraveil-guard approve <action_id>` in their own
    terminal, then call this tool again with the one-time `approval_code` they
    give you. You cannot approve your own action. Every decision is recorded in a
    local tamper-evident ledger.

    action: the exact command/SQL/tool call about to run (required).
    approval_code: the one-time code a human produced via the CLI (optional)."""
    if not action or not action.strip():
        return json.dumps({"error": "validation", "detail": "action is required"})
    return json.dumps(core.guard(action, approval_code or ""), indent=2)


@mcp.tool()
def assess_action(action: str) -> str:
    """Classify the blast radius of an action WITHOUT recording or gating it.
    Use this to reason about risk; use guard_action when you actually intend to
    run it. Returns risk (none/low/medium/high/critical), whether it is
    reversible, the specific dangerous capabilities found, and a recommendation.

    action: the command/SQL/tool call to assess (required)."""
    if not action or not action.strip():
        return json.dumps({"error": "validation", "detail": "action is required"})
    return json.dumps(core.assess(action), indent=2)


@mcp.tool()
def verify_ledger() -> str:
    """Verify the local guard ledger's hash chain  -  proves no decision has been
    edited, deleted, reordered, or inserted. Returns ok plus where any tampering
    was found. This is the 'trust by inspection' check; it reads only local
    files and trusts nothing remote."""
    return json.dumps(core.verify_ledger(), indent=2)


@mcp.tool()
def recent_decisions(limit: int = 20) -> str:
    """Return the most recent guard decisions from the local ledger (newest
    first): what was allowed, blocked, or approved, with risk and timestamps.

    limit: how many entries to return (1-500, default 20)."""
    return json.dumps(core.recent(limit), indent=2, default=str)


def run() -> None:
    mcp.run()


if __name__ == "__main__":
    run()
