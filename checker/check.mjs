// Certificate + uptime checker, run by GitHub Actions on a schedule (Node 20+, no dependencies).
//
// 1. GET  $SSL_MONITOR_API/api/ingest/domains   → domains to check
// 2. For each: TLS handshake on :443 (read the served certificate) and an HTTPS GET.
// 3. POST $SSL_MONITOR_API/api/ingest/results   → the Worker stores results and returns alert texts
// 4. Send each alert to LINE (Messaging API push) when LINE_CHANNEL_ACCESS_TOKEN / LINE_USER_ID are set.
//
// Env: SSL_MONITOR_API, SSL_MONITOR_TOKEN, optional LINE_CHANNEL_ACCESS_TOKEN, LINE_USER_ID.

import tls from 'node:tls';

const API = (process.env.SSL_MONITOR_API || '').replace(/\/$/, '');
const TOKEN = process.env.SSL_MONITOR_TOKEN;
const CONCURRENCY = 5;
const TIMEOUT_MS = 10_000;

if (!API || !TOKEN) {
  console.error('SSL_MONITOR_API and SSL_MONITOR_TOKEN are required');
  process.exit(1);
}

function checkCertificate(host) {
  return new Promise((resolve) => {
    const socket = tls.connect({ host, port: 443, servername: host, rejectUnauthorized: false, timeout: TIMEOUT_MS });
    const done = (result) => { socket.destroy(); resolve(result); };
    socket.once('secureConnect', () => {
      const cert = socket.getPeerCertificate();
      if (!cert || !cert.valid_to) return done({ ok: true, ssl: { error: 'no certificate presented' } });
      done({
        ok: true,
        ssl: {
          issuer: cert.issuer?.O || cert.issuer?.CN || null,
          validTo: new Date(cert.valid_to).toISOString(),
          // e.g. CERT_HAS_EXPIRED, ERR_TLS_CERT_ALTNAME_INVALID, SELF_SIGNED_CERT_IN_CHAIN
          error: socket.authorized ? null : String(socket.authorizationError || 'untrusted certificate'),
        },
      });
    });
    socket.once('timeout', () => done({ ok: false, error: 'TLS timeout' }));
    socket.once('error', (err) => done({ ok: false, error: err.code || err.message }));
  });
}

async function checkHttp(host) {
  try {
    const res = await fetch(`https://${host}/`, {
      redirect: 'follow',
      signal: AbortSignal.timeout(TIMEOUT_MS),
      headers: { 'User-Agent': 'sorawich-ssl-monitor/1.0 (+https://github.com/bankkk1996/ssl-monitor)' },
    });
    await res.body?.cancel();
    return { status: res.status, error: res.status >= 500 ? `HTTP ${res.status}` : null };
  } catch (err) {
    // An untrusted certificate makes fetch fail; the TLS check above reports that separately.
    const code = err.cause?.code || err.name;
    return { status: null, error: code === 'TimeoutError' ? 'HTTP timeout' : String(code || err.message) };
  }
}

async function checkOne({ id, domain }) {
  const [tlsResult, http] = await Promise.all([checkCertificate(domain), checkHttp(domain)]);
  const certProblem = tlsResult.ssl?.error;
  const alive = tlsResult.ok && (http.status !== null ? http.status < 500 : Boolean(certProblem));
  const result = {
    id,
    alive,
    httpStatus: http.status,
    error: alive ? null : (tlsResult.ok ? http.error : tlsResult.error),
    ssl: tlsResult.ssl ?? null,
  };
  const days = result.ssl?.validTo ? Math.floor((Date.parse(result.ssl.validTo) - Date.now()) / 86_400_000) : '?';
  console.log(`${alive ? 'UP  ' : 'DOWN'} ${domain.padEnd(40)} ssl=${days}d ${result.ssl?.error || ''} ${result.error || ''}`);
  return result;
}

async function api(path, init = {}) {
  const res = await fetch(`${API}${path}`, {
    ...init,
    headers: { Authorization: `Bearer ${TOKEN}`, 'Content-Type': 'application/json', ...init.headers },
  });
  if (!res.ok) throw new Error(`${path}: HTTP ${res.status} ${await res.text()}`);
  return res.json();
}

async function sendLine(text) {
  const { LINE_CHANNEL_ACCESS_TOKEN: token, LINE_USER_ID: to } = process.env;
  if (!token || !to) return console.log(`(LINE not configured) ${text}`);
  const res = await fetch('https://api.line.me/v2/bot/message/push', {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ to, messages: [{ type: 'text', text: text.slice(0, 4900) }] }),
  });
  if (!res.ok) throw new Error(`LINE push failed: HTTP ${res.status} ${await res.text()}`);
}

const domains = await api('/api/ingest/domains');
console.log(`Checking ${domains.length} domain(s)`);
const results = [];
for (let i = 0; i < domains.length; i += CONCURRENCY) {
  results.push(...(await Promise.all(domains.slice(i, i + CONCURRENCY).map(checkOne))));
}
const { updated, alerts } = await api('/api/ingest/results', { method: 'POST', body: JSON.stringify({ results }) });
console.log(`Stored ${updated} result(s), ${alerts.length} alert(s)`);
for (const text of alerts) await sendLine(text);
