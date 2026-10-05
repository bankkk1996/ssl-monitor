# SSL Monitor

Watches websites' TLS certificates, uptime and domain registration expiry, and alerts on LINE.
Runs at **https://ssl.sorawich.in.th** (owner only, behind Cloudflare Access).

```
GitHub Actions (every 30 min)          Cloudflare Worker + D1 (SQLite)            LINE
checker/check.mjs ── TLS handshake ──▶ /api/ingest/results  ── alert texts ──▶ push message
  reads served certificate,            stores results, decides alerts
  HTTPS GET for uptime                 (state changes / thresholds only)
                                       RDAP/WHOIS registration expiry
                                       on add + hourly cron (5 per run)
```

Workers cannot read a server's certificate, so certificate checks run on GitHub Actions
(`.github/workflows/ssl-monitor.yml` in `bankkk1996/personal-website`, which holds the LINE secrets).

## Alerts

- site goes down / comes back (recovery only after the checker itself saw the outage)
- certificate error appears (expired, hostname mismatch, self-signed, incomplete chain…)
- certificate ≤ 14, 7, 3, 1, 0 days left — Let's Encrypt renews at 30, so ≤ 14 means renewal failed
- domain registration ≤ 60, 30, 14, 7, 3, 1, 0 days left

Each threshold alerts once; renewing resets it.

## Layout

| Path | What |
|---|---|
| `src/index.js` | Worker: owner API (Access JWT), checker ingest (Bearer token), RDAP/WHOIS, alert rules, cron |
| `public/` | UI (vanilla JS) |
| `migrations/` | D1 schema |
| `checker/check.mjs` | Node 20+ checker, no dependencies |

## Secrets

- Worker: `INGEST_TOKEN` (`npx wrangler secret put INGEST_TOKEN`)
- Checker workflow: `SSL_MONITOR_TOKEN` (same value), `LINE_CHANNEL_ACCESS_TOKEN`, `LINE_USER_ID`

The checker reaches the Worker on `ssl-monitor.banksine1735.workers.dev`, where only `/api/ingest/*` is served.

## Develop

```sh
printf 'DEV_BYPASS_AUTH=true\nINGEST_TOKEN=local-test-token\n' > .dev.vars
npx wrangler d1 migrations apply ssl-monitor-db --local
npx wrangler dev --port 8789
SSL_MONITOR_API=http://localhost:8789 SSL_MONITOR_TOKEN=local-test-token node checker/check.mjs
```

Deploy: `npx wrangler d1 migrations apply ssl-monitor-db --remote && npx wrangler deploy`.

*Earlier version (Vercel + Prisma/Postgres + Supabase auth + Resend) is in the git history.*
