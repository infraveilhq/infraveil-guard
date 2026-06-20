# Publishing infraveil-guard

Built and fully verified offline (47/47 tests, `twine check` PASSED, FastMCP
registers all 4 tools). These are the only steps left — all require your GitHub /
PyPI auth, which is why they weren't done autonomously. Same flow as
`infraveil-mcp` and `infraveil-cli`.

## 1. GitHub repo

```bash
# from infraveil-guard/
git init && git add -A && git commit -m "infraveil-guard 0.1.0"
gh repo create infraveilhq/infraveil-guard --public --source=. --push \
  --description "A seatbelt for your AI agent: gate destructive actions behind human approval, with a tamper-evident log."
```
Add topics: `mcp`, `ai-agents`, `claude-code`, `cursor`, `safety`, `guardrails`, `devops`, `security`.

## 2. PyPI (trusted publishing — no token)

On https://pypi.org/manage/account/publishing/ add a **pending publisher**:
- PyPI project name: `infraveil-guard`
- Owner: `infraveilhq`  · Repo: `infraveil-guard`
- Workflow: `publish.yml`  · Environment: `pypi`

Then cut a GitHub release (tag `v0.1.0`) — `.github/workflows/publish.yml` builds
and OIDC-publishes automatically:
```bash
gh release create v0.1.0 --title "infraveil-guard 0.1.0" --notes "First release."
```

## 3. MCP registry

The PyPI README already carries the `mcp-name: io.github.infraveilhq/agent-guard`
marker, and `server.json` is ready. After PyPI shows 0.1.0:
```bash
mcp-publisher login github      # OIDC via the infraveilhq org
mcp-publisher publish           # reads server.json
```
Aggregators (Smithery / Glama / PulseMCP) ingest from the registry within hours.

## 4. Then (and only then) ship the landing page

`seo/agent-guard.html` is built but HELD — deploying it before PyPI is live means a
broken `pip install` CTA (deindex risk). Once the package is live:
- `scp seo/agent-guard.html ivprod:/tmp/ && sudo cp` to `/var/www/html/agent-guard.html` (chown ubuntu, 644)
- add `"agent-guard"` to `GROWTH_TOOLS` in server.py (else its telemetry is dropped)
- add `https://infraveil.com/agent-guard` to `/var/www/html/sitemap.xml`
