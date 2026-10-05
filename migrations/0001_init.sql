-- Monitored domains and their latest check results. Dates are ISO-8601 UTC strings.

CREATE TABLE domains (
  id                  INTEGER PRIMARY KEY AUTOINCREMENT,
  domain              TEXT NOT NULL UNIQUE,          -- hostname as entered, lower-case, punycode
  priority            TEXT NOT NULL DEFAULT 'Normal' CHECK (priority IN ('High', 'Normal', 'Low')),
  created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),

  -- uptime (HTTP + TLS handshake)
  is_alive            INTEGER,                       -- 1 up, 0 down, NULL not checked yet
  http_status         INTEGER,
  last_error          TEXT,

  -- TLS certificate (filled by the GitHub Actions checker)
  ssl_issuer          TEXT,
  ssl_valid_to        TEXT,
  ssl_error           TEXT,                          -- e.g. CERT_HAS_EXPIRED, hostname mismatch
  ssl_checked_at      TEXT,

  -- registration (RDAP / WHOIS, filled by the Worker)
  registered_domain   TEXT,                          -- e.g. sorawich.in.th for www.sorawich.in.th
  domain_valid_to     TEXT,
  domain_error        TEXT,
  domain_checked_at   TEXT,

  -- alert bookkeeping: lowest threshold (days) already alerted, NULL when healthy
  ssl_alert_level     INTEGER,
  domain_alert_level  INTEGER
);
