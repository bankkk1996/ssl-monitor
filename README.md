# SSL Monitor

Watches websites' TLS certificates, uptime and domain registration expiry, and alerts on LINE.
Runs at **https://ssl.sorawich.in.th** (owner only, behind Cloudflare Access).

```
GitHub Actions (every 30 min)          Cloudflare Worker + D1 (SQLite)            LINE
checker/check.mjs ── TLS handshake ──▶ /api/ingest/results  ── alert texts ──▶ push message
  reads served certificate,            stores results, decides alerts
  HTTPS GET for uptime                 (state changes / thresholds only)
                                       RDAP/WHOIS registration expiry
                                       on add + cron (4 per run)
```

Workers cannot read a server's certificate, so certificate checks run on GitHub Actions
(`.github/workflows/ssl-monitor.yml` in `bankkk1996/personal-website`, which holds the LINE secrets).
GitHub's own schedule is unreliable, so the Worker's cron dispatches that workflow every 30 minutes
(GitHub's schedule stays as a backup). The UI warns when no check has landed for 2 hours or the
last dispatch failed (e.g. an expired token).

## Alerts

- site goes down / comes back (recovery only after the checker itself saw the outage)
- certificate error appears (expired, hostname mismatch, self-signed, incomplete chain…)
- certificate ≤ 14, 7, 3, 1, 0 days left — Let's Encrypt renews at 30, so ≤ 14 means renewal failed
- domain registration ≤ 60, 30, 14, 7, 3, 1, 0 days left

Each threshold alerts once; renewing resets it.

## Layout

| Path | What |
|---|---|
| `worker/index.js` | Worker: owner API (Access JWT), checker ingest (Bearer token), RDAP/WHOIS, alert rules, cron |
| `src/` | UI: React + Vite + Tailwind v4 + [shadcn/ui](https://ui.shadcn.com) (`src/components/ui`), built to `dist/` |
| `migrations/` | D1 schema |
| `checker/check.mjs` | Node 20+ checker, no dependencies |

## Secrets

- Worker: `INGEST_TOKEN` (`npx wrangler secret put INGEST_TOKEN`) and `GITHUB_DISPATCH_TOKEN`
  (fine-grained PAT, repository `personal-website` only, permission Actions: read and write)
- Checker workflow: `SSL_MONITOR_TOKEN` (same value), `LINE_CHANNEL_ACCESS_TOKEN`, `LINE_USER_ID`

The checker reaches the Worker on `ssl-monitor.banksine1735.workers.dev`, where only `/api/ingest/*` is served.

## Develop

```sh
printf 'DEV_BYPASS_AUTH=true\nINGEST_TOKEN=local-test-token\n' > .dev.vars
npm install
npx wrangler d1 migrations apply ssl-monitor-db --local
npm run build && npx wrangler dev --port 8789   # full app on :8789
npm run dev                                      # or: UI with hot reload on :5173 (proxies /api to :8789)
SSL_MONITOR_API=http://localhost:8789 SSL_MONITOR_TOKEN=local-test-token node checker/check.mjs
```

Add shadcn components with `npx shadcn@latest add <name>` (check the generated import is `@/lib/utils`).

Deploy: `npx wrangler d1 migrations apply ssl-monitor-db --remote && npm run deploy`.

*Earlier version (Vercel + Prisma/Postgres + Supabase auth + Resend) is in the git history.*
