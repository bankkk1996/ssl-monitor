// SSL Monitor on Cloudflare Workers + D1 (SQLite).
//
// - UI and /api/* on ssl.sorawich.in.th are for the owner only (Cloudflare Access JWT, fail closed).
// - /api/ingest/* is for the GitHub Actions checker (Bearer INGEST_TOKEN). Workers cannot read a
//   server's TLS certificate, so certificate checks run there and results are posted back here.
// - Domain registration expiry (RDAP, falling back to WHOIS) is checked here: when a domain is
//   added, and by the hourly cron trigger (a few domains per run, each about once a day).
//
// Workers Free allows 50 subrequests and 50 D1 queries per invocation, so every handler keeps
// its work per invocation bounded no matter how many domains are monitored.

import { connect } from 'cloudflare:sockets';

const PRIORITIES = ['High', 'Normal', 'Low'];
// Let's Encrypt renews at 30 days left, so ≤ 14 days means automatic renewal has failed.
const SSL_LEVELS = [14, 7, 3, 1, 0];
const DOMAIN_LEVELS = [60, 30, 14, 7, 3, 1, 0];
const DAY = 86_400_000;
const APP_URL = 'https://ssl.sorawich.in.th';
const CRON_BATCH = 5;          // domains per cron run; each lookup may take several subrequests
const INGEST_BATCH = 25;       // results accepted per /api/ingest/results call (checker sends 20)

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const onWorkersDev = url.hostname.endsWith('.workers.dev');

    try {
      if (url.pathname.startsWith('/api/ingest/')) return await ingest(request, url, env);
      // workers.dev exists only so the checker can reach /api/ingest without going through Access.
      if (onWorkersDev) return new Response('Not found', { status: 404 });
      if (!url.pathname.startsWith('/api/')) return env.ASSETS.fetch(request);

      const user = await authenticate(request, env);
      if (!user) return json({ error: 'unauthorized' }, 401);
      if (request.method !== 'GET' && !(request.headers.get('Content-Type') || '').startsWith('application/json')) {
        throw new HttpError(415, 'expected application/json');
      }
      return await route(request, url, env, user);
    } catch (err) {
      if (err instanceof HttpError) return json({ error: err.message }, err.status);
      console.error(err);
      return json({ error: 'internal error' }, 500);
    }
  },

  // Hourly: refresh registration expiry for the few domains checked longest ago (> 20 h).
  async scheduled(event, env, ctx) {
    const { results } = await env.DB.prepare(
      `SELECT id, domain, registered_domain FROM domains
        WHERE domain_checked_at IS NULL OR domain_checked_at < ?
        ORDER BY domain_checked_at IS NOT NULL, domain_checked_at LIMIT ?`
    ).bind(iso(Date.now() - 20 * 3600_000), CRON_BATCH).all();
    for (const row of results) {
      await refreshRegistration(env, row).catch((err) => console.error(row.domain, err));
    }
  },
};

// ---------- owner API ----------

async function route(request, url, env, user) {
  const { pathname } = url;
  const method = request.method;
  const m = pathname.match(/^\/api\/domains\/(\d+)(\/refresh)?$/);

  if (pathname === '/api/me' && method === 'GET') return json({ email: user.email });

  if (pathname === '/api/domains' && method === 'GET') {
    const { results } = await env.DB.prepare('SELECT * FROM domains ORDER BY domain').all();
    return json(results);
  }

  if (pathname === '/api/domains' && method === 'POST') {
    const body = await readJson(request);
    const domain = normalizeHost(body.domain);
    const priority = PRIORITIES.includes(body.priority) ? body.priority : 'Normal';
    const row = await env.DB.prepare(
      `INSERT INTO domains (domain, priority, registered_domain) VALUES (?, ?, ?)
       ON CONFLICT (domain) DO NOTHING RETURNING *`
    ).bind(domain, priority, registeredDomain(domain)).first();
    if (!row) throw new HttpError(409, 'โดเมนนี้มีอยู่แล้ว');
    await Promise.all([checkAlive(env, row), refreshRegistration(env, row)]);
    return json(await getDomain(env, row.id), 201);
  }

  if (m && m[2] && method === 'POST') {
    const row = await getDomain(env, Number(m[1]));
    await Promise.all([checkAlive(env, row), refreshRegistration(env, row)]);
    return json(await getDomain(env, row.id));
  }

  if (m && !m[2] && method === 'PATCH') {
    const body = await readJson(request);
    if (!PRIORITIES.includes(body.priority)) throw new HttpError(400, 'invalid priority');
    await env.DB.prepare('UPDATE domains SET priority = ? WHERE id = ?').bind(body.priority, Number(m[1])).run();
    return json(await getDomain(env, Number(m[1])));
  }

  if (m && !m[2] && method === 'DELETE') {
    await env.DB.prepare('DELETE FROM domains WHERE id = ?').bind(Number(m[1])).run();
    return json({ ok: true });
  }

  throw new HttpError(404, 'not found');
}

async function getDomain(env, id) {
  const row = await env.DB.prepare('SELECT * FROM domains WHERE id = ?').bind(id).first();
  if (!row) throw new HttpError(404, 'ไม่พบโดเมนนี้');
  return row;
}

// Accepts "Example.com", "https://example.com/path", "example.com:443" → "example.com".
function normalizeHost(input) {
  const raw = String(input ?? '').trim();
  if (!raw || raw.length > 300) throw new HttpError(400, 'กรุณาใส่โดเมน');
  let host;
  try {
    host = new URL(/^[a-z]+:\/\//i.test(raw) ? raw : `https://${raw}`).hostname.toLowerCase();
  } catch {
    throw new HttpError(400, 'รูปแบบโดเมนไม่ถูกต้อง');
  }
  host = host.replace(/\.$/, '');
  const label = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;
  const parts = host.split('.');
  if (parts.length < 2 || !parts.every((p) => label.test(p)) || !/^(xn--[a-z0-9-]+|[a-z]{2,63})$/.test(parts.at(-1))) {
    throw new HttpError(400, 'รูปแบบโดเมนไม่ถูกต้อง (ใส่ได้เฉพาะชื่อโดเมนสาธารณะ เช่น example.com)');
  }
  return host;
}

// Good-enough registrable domain without the full Public Suffix List.
const TWO_LEVEL_SUFFIXES = new Set([
  'co.th', 'in.th', 'ac.th', 'go.th', 'or.th', 'net.th', 'mi.th',
  'co.uk', 'org.uk', 'ac.uk', 'com.au', 'net.au', 'org.au', 'co.jp', 'ne.jp', 'or.jp',
  'com.sg', 'com.my', 'com.cn', 'com.hk', 'co.id', 'co.kr', 'com.br', 'co.nz', 'com.vn', 'co.in',
]);
function registeredDomain(host) {
  const p = host.split('.');
  if (p.length <= 2) return host;
  return TWO_LEVEL_SUFFIXES.has(p.slice(-2).join('.')) ? p.slice(-3).join('.') : p.slice(-2).join('.');
}

// ---------- checks done by the Worker ----------

async function checkAlive(env, row) {
  let isAlive = 0, status = null, error = null, opaque = false;
  try {
    const res = await fetch(`https://${row.domain}/`, {
      redirect: 'follow',
      signal: AbortSignal.timeout(10_000),
      headers: { 'User-Agent': 'sorawich-ssl-monitor/1.0' },
    });
    status = res.status;
    isAlive = res.status < 500 ? 1 : 0;
    if (!isAlive) error = `HTTP ${res.status}`;
  } catch (err) {
    const msg = String(err.message || err);
    // Cloudflare reports TLS/DNS failures to the origin as an opaque "internal error; reference = …".
    error = err.name === 'TimeoutError' ? 'Timeout'
      : /internal error|reference =/i.test(msg) ? 'เชื่อมต่อ HTTPS ไม่สำเร็จ (DNS หรือใบรับรองมีปัญหา)'
      : msg.slice(0, 200);
    opaque = /internal error|reference =/i.test(msg);
  }
  // A site with a bad certificate is unreachable from Workers but may be up. Once the checker has
  // seen the site, trust its verdict instead of overwriting it with this opaque failure.
  if (opaque && row.ssl_checked_at) return;
  await env.DB.prepare('UPDATE domains SET is_alive = ?, http_status = ?, last_error = ? WHERE id = ?')
    .bind(isAlive, status, error, row.id).run();
}

async function refreshRegistration(env, row) {
  const name = row.registered_domain || registeredDomain(row.domain);
  let validTo = null, error = null;
  try {
    validTo = (await retry(() => rdapExpiry(name))) ?? (await retry(() => whoisExpiry(name)));
    if (!validTo) error = 'ไม่พบวันหมดอายุในข้อมูล RDAP/WHOIS';
  } catch (err) {
    error = String(err.message || err).slice(0, 200);
  }
  await env.DB.prepare(
    `UPDATE domains SET registered_domain = ?, domain_valid_to = COALESCE(?, domain_valid_to),
            domain_error = ?, domain_checked_at = ? WHERE id = ?`
  ).bind(name, validTo, error, iso(Date.now()), row.id).run();
}

let rdapBootstrap = null;
async function rdapExpiry(name) {
  if (!rdapBootstrap) {
    const res = await fetch('https://data.iana.org/rdap/dns.json', { signal: AbortSignal.timeout(10_000) });
    rdapBootstrap = (await res.json()).services;
  }
  const tld = name.split('.').at(-1);
  const service = rdapBootstrap.find(([tlds]) => tlds.includes(tld));
  if (!service) return null; // TLD has no RDAP (e.g. .th) → WHOIS
  const base = service[1][0].replace(/\/?$/, '/');
  const res = await fetch(`${base}domain/${name}`, {
    headers: { Accept: 'application/rdap+json' },
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) return null;
  const data = await res.json();
  const exp = (data.events || []).find((e) => e.eventAction === 'expiration');
  return exp ? iso(Date.parse(exp.eventDate)) : null;
}

const WHOIS_SERVERS = { th: 'whois.thnic.co.th' };
async function whoisExpiry(name) {
  const tld = name.split('.').at(-1);
  let server = WHOIS_SERVERS[tld];
  if (!server) {
    const iana = await whoisQuery('whois.iana.org', tld);
    server = iana.match(/^(?:refer|whois):\s*(\S+)/im)?.[1];
    if (!server) return null;
  }
  const text = await whoisQuery(server, name);
  const m = text.match(/^\s*(?:Registry Expiry Date|Registrar Registration Expiration Date|Expiration Date|Expiry Date|Exp date|Expires On|Expiration Time|paid-till|expires)\s*:\s*(.+)$/im);
  if (!m) return null;
  const t = Date.parse(m[1].trim());
  return Number.isNaN(t) ? null : iso(t);
}

async function whoisQuery(hostname, query) {
  const socket = connect({ hostname, port: 43 });
  const writer = socket.writable.getWriter();
  await writer.write(new TextEncoder().encode(`${query}\r\n`));
  const reader = socket.readable.getReader();
  const decoder = new TextDecoder();
  let text = '';
  const deadline = Date.now() + 10_000;
  try {
    while (Date.now() < deadline && text.length < 200_000) {
      const { value, done } = await Promise.race([
        reader.read(),
        new Promise((_, reject) => setTimeout(() => reject(new Error('WHOIS timeout')), deadline - Date.now())),
      ]);
      if (done) break;
      text += decoder.decode(value, { stream: true });
    }
  } finally {
    socket.close();
  }
  return text;
}

// ---------- checker ingest ----------

async function ingest(request, url, env) {
  const token = (request.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
  if (!env.INGEST_TOKEN || !token || !safeEqual(token, env.INGEST_TOKEN)) return json({ error: 'unauthorized' }, 401);

  if (url.pathname === '/api/ingest/domains' && request.method === 'GET') {
    const { results } = await env.DB.prepare('SELECT id, domain FROM domains ORDER BY id').all();
    return json(results);
  }

  if (url.pathname === '/api/ingest/results' && request.method === 'POST') {
    const { results } = await readJson(request);
    if (!Array.isArray(results)) throw new HttpError(400, 'results must be an array');
    if (results.length > INGEST_BATCH) throw new HttpError(413, `send at most ${INGEST_BATCH} results per request`);
    const now = Date.now();
    const alerts = [];
    const updates = [];
    // One query for all previous rows (D1 allows only 50 queries per invocation on Workers Free).
    const { results: rows } = await env.DB.prepare('SELECT * FROM domains').all();
    const byId = new Map(rows.map((row) => [row.id, row]));
    for (const r of results) {
      const prev = byId.get(Number(r.id));
      if (!prev) continue;
      const next = {
        is_alive: r.alive ? 1 : 0,
        http_status: Number.isInteger(r.httpStatus) ? r.httpStatus : null,
        last_error: r.alive ? null : String(r.error || 'unreachable').slice(0, 200),
        ssl_issuer: r.ssl?.issuer ? String(r.ssl.issuer).slice(0, 200) : prev.ssl_issuer,
        ssl_valid_to: r.ssl?.validTo && !Number.isNaN(Date.parse(r.ssl.validTo)) ? iso(Date.parse(r.ssl.validTo)) : prev.ssl_valid_to,
        ssl_error: r.ssl?.error ? String(r.ssl.error).slice(0, 200) : null,
        ssl_checked_at: r.ssl ? iso(now) : prev.ssl_checked_at,
      };
      const a = computeAlerts(prev, next, now);
      alerts.push(...a.messages);
      updates.push(env.DB.prepare(
        `UPDATE domains SET is_alive = ?, http_status = ?, last_error = ?, ssl_issuer = ?, ssl_valid_to = ?,
                ssl_error = ?, ssl_checked_at = ?, ssl_alert_level = ?, domain_alert_level = ? WHERE id = ?`
      ).bind(next.is_alive, next.http_status, next.last_error, next.ssl_issuer, next.ssl_valid_to,
        next.ssl_error, next.ssl_checked_at, a.sslLevel, a.domainLevel, prev.id));
    }
    if (updates.length) await env.DB.batch(updates);
    return json({ updated: updates.length, alerts });
  }

  throw new HttpError(404, 'not found');
}

// Alerts fire on state changes only: down/up transitions, a certificate error appearing, and the
// first time days-left drops to or below each threshold. Renewal (days back above the top
// threshold) resets the level so the next expiry is announced again.
function computeAlerts(prev, next, now) {
  const messages = [];
  const d = prev.domain;

  if (prev.is_alive !== 0 && next.is_alive === 0) messages.push(`🚨 ${d} เข้าไม่ได้: ${next.last_error}`);
  // Only announce recovery from an outage the checker itself observed (not the Worker's first look).
  if (prev.is_alive === 0 && next.is_alive === 1 && prev.ssl_checked_at) messages.push(`✅ ${d} กลับมาใช้งานได้แล้ว`);
  if (next.ssl_error && next.ssl_error !== prev.ssl_error) messages.push(`🔒 ${d} ใบรับรอง SSL มีปัญหา: ${next.ssl_error}`);

  const level = (validTo, levels, current, label, name) => {
    if (!validTo) return { level: current };
    const days = Math.floor((Date.parse(validTo) - now) / DAY);
    if (days > levels[0]) return { level: null };
    const hit = Math.min(...levels.filter((t) => days <= t));
    if (current === null || current === undefined || hit < current) {
      const when = days < 0 ? `หมดอายุไปแล้ว ${-days} วัน` : `เหลือ ${days} วัน`;
      messages.push(`${label} ${name} ${when} (หมดอายุ ${validTo.slice(0, 10)})`);
      return { level: hit };
    }
    return { level: current };
  };
  const ssl = level(next.ssl_valid_to, SSL_LEVELS, prev.ssl_alert_level, '🔒 SSL', d);
  const dom = level(prev.domain_valid_to, DOMAIN_LEVELS, prev.domain_alert_level, '🌐 โดเมน', prev.registered_domain || d);
  if (messages.length) messages.push(APP_URL);
  return { messages: messages.length ? [messages.join('\n')] : [], sslLevel: ssl.level, domainLevel: dom.level };
}

// ---------- Cloudflare Access JWT verification ----------

let certCache = { team: null, keys: null, at: 0 };

async function authenticate(request, env) {
  if (env.DEV_BYPASS_AUTH === 'true') return { email: 'dev@localhost' }; // only set in .dev.vars
  const team = env.ACCESS_TEAM_DOMAIN;
  const aud = env.ACCESS_AUD;
  const deny = (reason) => { console.warn(`auth denied: ${reason}`); return null; };
  if (!team || !aud) return deny('access not configured');

  const token = request.headers.get('Cf-Access-Jwt-Assertion') || cookie(request, 'CF_Authorization');
  if (!token) return deny('no access token');
  try {
    const [h, p, s] = token.split('.');
    const header = JSON.parse(b64urlText(h));
    const payload = JSON.parse(b64urlText(p));
    const key = (await accessKeys(team)).find((k) => k.kid === header.kid);
    if (!key) return deny(`unknown kid ${header.kid}`);
    if (header.alg !== 'RS256') return deny(`alg ${header.alg}`);
    const cryptoKey = await crypto.subtle.importKey('jwk', key, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
    const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', cryptoKey, b64urlBytes(s), new TextEncoder().encode(`${h}.${p}`));
    if (!ok) return deny('bad signature');
    const audOk = Array.isArray(payload.aud) ? payload.aud.includes(aud) : payload.aud === aud;
    if (!audOk) return deny(`aud mismatch ${JSON.stringify(payload.aud)}`);
    if (payload.iss !== `https://${team}`) return deny(`iss mismatch ${payload.iss}`);
    if (!(payload.exp > Math.floor(Date.now() / 1000))) return deny('expired');
    return { email: payload.email };
  } catch (err) {
    return deny(`error ${err.message}`);
  }
}

async function accessKeys(team) {
  if (certCache.team === team && Date.now() - certCache.at < 3600_000) return certCache.keys;
  const res = await fetch(`https://${team}/cdn-cgi/access/certs`);
  const { keys } = await res.json();
  certCache = { team, keys, at: Date.now() };
  return keys;
}

// ---------- helpers ----------

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
  });
}

async function readJson(request) {
  try { return await request.json(); } catch { throw new HttpError(400, 'invalid JSON'); }
}

async function retry(fn, attempts = 3) {
  for (let i = 1; ; i++) {
    try {
      return await fn();
    } catch (err) {
      if (i >= attempts) throw err;
      await new Promise((r) => setTimeout(r, 500 * i));
    }
  }
}

const iso = (ms) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');

function safeEqual(a, b) {
  const x = new TextEncoder().encode(a), y = new TextEncoder().encode(b);
  return x.length === y.length && crypto.subtle.timingSafeEqual(x, y);
}

function cookie(request, name) {
  const m = (request.headers.get('Cookie') || '').match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
  return m ? m[1] : null;
}

function b64urlBytes(s) {
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length / 4) * 4, '='));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

function b64urlText(s) {
  return new TextDecoder().decode(b64urlBytes(s));
}
