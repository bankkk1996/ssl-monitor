-- Small key/value store for operational state (e.g. the last checker dispatch result).
CREATE TABLE meta (
  key         TEXT PRIMARY KEY,
  value       TEXT,
  updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
