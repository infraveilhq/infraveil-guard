<!-- mcp-name: io.github.infraveilhq/agent-guard -->

# infraveil-guard

**A seatbelt for your AI agent.** Put a governed, tamper-evident gate in front of
the destructive things an agent can do — `rm -rf`, `DROP TABLE`, `terraform
destroy`, `git push --force`, `kubectl delete namespace`, `DELETE FROM … `with no
`WHERE`. The agent proposes; the dangerous ones are **blocked until a human
approves them out of band**; every decision is written to a **local hash-chained
ledger you can verify**.

Offline by design: **no account, no network, no telemetry.** It runs entirely on
your machine. Open your network tab — it talks to nobody.

```bash
pip install infraveil-guard
```

---

## Why

Coding agents (Claude Code, Cursor, and friends) are great until the one time
they run `rm -rf` in the wrong directory, or drop the production database to "fix
a migration." You don't want to read every command — you want the *catastrophic*
ones to stop and wait for you. That's all this does, and it does it well.

## Wire it into your agent

Add it as an MCP server. For Claude Code / Cursor / any MCP client:

```json
{
  "mcpServers": {
    "infraveil-guard": {
      "command": "infraveil-guard"
    }
  }
}
```

Then add one rule to your agent's instructions (CLAUDE.md, system prompt, etc.):

> Before running any shell command, SQL statement, or infrastructure/cloud
> operation, first call `guard_action` with the exact command. Only proceed if it
> returns `proceed: true`. If it returns `decision: "blocked"`, stop and ask me to
> approve it — I'll give you a one-time code to pass back as `approval_code`.

That's it. Safe commands sail through (and are logged). Dangerous ones stop.

## How approval works (the part that matters)

When the agent hits something dangerous, `guard_action` returns `blocked` and an
`action_id`. **The agent cannot approve itself** — by construction, not by good
behavior. You approve in your *own* terminal:

```bash
$ infraveil-guard approvals
1 action(s) blocked, waiting for approval:

  [9b58e9c499b3]  CRITICAL  CRITICAL risk: drop table (+0 more). Irreversible.
            DROP TABLE users;
            approve with:  infraveil-guard approve 9b58e9c499b3

$ infraveil-guard approve 9b58e9c499b3

  Action requesting approval
  id:        9b58e9c499b3
  risk:      CRITICAL  (IRREVERSIBLE)
  why:       CRITICAL risk: drop table. Irreversible.
  command:
    DROP TABLE users;

  Approve this action? [y/N] y

  APPROVED. Give the agent this one-time code:

      8f2510

  It is valid for 15 minutes and works exactly once.
```

You hand the agent `8f2510`; it calls `guard_action("DROP TABLE users;",
approval_code="8f2510")`; the guard checks it, lets it through once, and records
the approval. The code is minted only by the human CLI, is single-use, and
expires — so an agent can't forge or replay it.

## Inspect everything — trust nothing

Every decision (allowed, blocked, approved, denied) is appended to a hash-chained
ledger at `~/.infraveil-guard/ledger.jsonl`. Editing, deleting, reordering, or
inserting any line breaks the chain:

```bash
$ infraveil-guard verify
{ "ok": true, "count": 42, "message": "Hash chain verified across 42 entries - no tampering." }

$ infraveil-guard log 10        # the last 10 decisions, raw
```

It's ~400 lines of plain stdlib Python. Read it. That's the point.

## Tools (MCP)

| Tool | What it does |
|------|--------------|
| `guard_action(action, approval_code="")` | Gate an action before running it. Returns `proceed` true/false. |
| `assess_action(action)` | Classify blast radius **without** recording or gating. |
| `verify_ledger()` | Verify the tamper-evident ledger's hash chain. |
| `recent_decisions(limit=20)` | The most recent decisions, newest first. |

## Configuration

| Env var | Default | Meaning |
|---------|---------|---------|
| `INFRAVEIL_GUARD_THRESHOLD` | `high` | Gate actions at/above this severity: `none\|low\|medium\|high\|critical`. |
| `INFRAVEIL_GUARD_MODE` | `enforce` | `enforce` blocks dangerous actions; `audit` logs everything but never blocks (use it to watch your agent before you trust the gate). |
| `INFRAVEIL_GUARD_HOME` | `~/.infraveil-guard` | Where the ledger and approval queue live. |

## What this is — and isn't

It **is** a high-signal classifier + an out-of-band human-approval gate + a
tamper-evident local log. It's the smallest honest version of "a human approves
before anything irreversible happens."

It is **not** a sandbox. It works because your agent is told to route actions
through `guard_action` — a cooperative guardrail, not an unbypassable jail. If you
need a gate the agent *cannot* skip — because the agent runs *inside* the governed
runtime, with central audit, least-privilege scoping, and one-click rollback
across a whole fleet — that's the full **[Infraveil](https://infraveil.com)**
control plane. This is the doorway; that's the house.

## License

AGPL-3.0-or-later. Use it, fork it, read every line. If you run a modified version
as a network service, share your changes. © Infraveil Corporation.
