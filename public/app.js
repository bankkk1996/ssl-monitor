const $ = (s) => document.querySelector(s);
const DAY = 86_400_000;
const dateFmt = new Intl.DateTimeFormat('th-TH', { day: 'numeric', month: 'short', year: 'numeric' });
const timeFmt = new Intl.DateTimeFormat('th-TH', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });
const PRIORITY_LABEL = { High: 'สำคัญมาก', Normal: '', Low: 'ต่ำ' };
const PRIORITY_RANK = { High: 0, Normal: 1, Low: 2 };

let domains = [];

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
const daysLeft = (iso) => (iso ? Math.floor((Date.parse(iso) - Date.now()) / DAY) : null);

async function api(path, options = {}) {
  const res = await fetch(`/api${path}`, {
    ...options,
    headers: { 'Content-Type': 'application/json' },
    body: options.body ? JSON.stringify(options.body) : undefined,
    credentials: 'same-origin',
  });
  const data = await res.json().catch(() => ({}));
  if (res.status === 401) throw new Error('หมดเวลาเข้าสู่ระบบ — กรุณารีเฟรชหน้านี้เพื่อล็อกอินใหม่');
  if (!res.ok) throw new Error(data.error || `เกิดข้อผิดพลาด (${res.status})`);
  return data;
}

function showError(err) {
  $('#alert').textContent = err ? err.message || String(err) : '';
  $('#alert').hidden = !err;
}

// Status levels always come with a text label, never colour alone.
function expiryPill(days, warnAt, critAt, broken = false) {
  if (days === null) return '<span class="pill pending">⏳ รอเช็ก</span>';
  const cls = broken || days <= critAt ? 'critical' : days <= warnAt ? 'warning' : 'good';
  const icon = cls === 'good' ? '✓' : '⚠';
  const text = days < 0 ? `หมดแล้ว ${-days} วัน` : `${days} วัน`;
  return `<span class="pill ${cls}">${icon} <span class="days">${text}</span></span>`;
}

const SSL_ERRORS = {
  CERT_HAS_EXPIRED: 'ใบรับรองหมดอายุ',
  ERR_TLS_CERT_ALTNAME_INVALID: 'ชื่อโดเมนไม่ตรงกับใบรับรอง',
  DEPTH_ZERO_SELF_SIGNED_CERT: 'ใบรับรองแบบ self-signed',
  SELF_SIGNED_CERT_IN_CHAIN: 'มีใบรับรอง self-signed ใน chain',
  UNABLE_TO_VERIFY_LEAF_SIGNATURE: 'chain ใบรับรองไม่ครบ',
  UNABLE_TO_GET_ISSUER_CERT_LOCALLY: 'chain ใบรับรองไม่ครบ',
  CERT_NOT_YET_VALID: 'ใบรับรองยังไม่เริ่มใช้งาน',
  CERT_REVOKED: 'ใบรับรองถูกเพิกถอน',
};
const sslErrorText = (code) => SSL_ERRORS[code] || code;

function upPill(d) {
  if (d.is_alive === null) return '<span class="pill pending">⏳ รอเช็ก</span>';
  return d.is_alive ? '<span class="pill good">● ใช้งานได้</span>' : `<span class="pill critical" title="${esc(d.last_error)}">✕ เข้าไม่ได้</span>`;
}

function urgency(d) {
  const s = daysLeft(d.ssl_valid_to) ?? 9999;
  const r = daysLeft(d.domain_valid_to) ?? 9999;
  return [d.is_alive === 0 ? 0 : 1, d.ssl_error ? 0 : 1, Math.min(s, r), PRIORITY_RANK[d.priority], d.domain];
}
function compare(a, b) {
  const x = urgency(a), y = urgency(b);
  for (let i = 0; i < x.length; i++) if (x[i] !== y[i]) return x[i] < y[i] ? -1 : 1;
  return 0;
}

function render() {
  const ssl = domains.map((d) => daysLeft(d.ssl_valid_to));
  const reg = domains.map((d) => daysLeft(d.domain_valid_to));
  $('#sTotal').textContent = domains.length;
  $('#sDown').textContent = domains.filter((d) => d.is_alive === 0).length;
  $('#sSsl').textContent = domains.filter((d, i) => d.ssl_error || (ssl[i] !== null && ssl[i] <= 14)).length;
  $('#sDomain').textContent = reg.filter((n) => n !== null && n <= 60).length;

  if (!domains.length) {
    $('#list').innerHTML = '<p class="empty">ยังไม่มีโดเมน — เพิ่มโดเมนแรกจากช่องด้านบน</p>';
    return;
  }
  const rows = [...domains].sort(compare).map((d) => {
    const sslDays = daysLeft(d.ssl_valid_to);
    const regDays = daysLeft(d.domain_valid_to);
    const sslSub = d.ssl_error
      ? `<span class="pill critical wrap" title="${esc(d.ssl_error)}">⚠ ${esc(sslErrorText(d.ssl_error))}</span>`
      : d.ssl_valid_to ? `${dateFmt.format(new Date(d.ssl_valid_to))}${d.ssl_issuer ? ` · ${esc(d.ssl_issuer)}` : ''}` : 'เช็กภายใน 30 นาที';
    const regSub = d.domain_valid_to
      ? `${dateFmt.format(new Date(d.domain_valid_to))}${d.registered_domain && d.registered_domain !== d.domain ? ` · ${esc(d.registered_domain)}` : ''}`
      : d.domain_error ? esc(d.domain_error) : '';
    const checked = d.ssl_checked_at ? `เช็กล่าสุด ${timeFmt.format(new Date(d.ssl_checked_at))}` : '';
    return `<div class="row" data-id="${d.id}">
      <div class="name">
        <a href="https://${esc(d.domain)}" target="_blank" rel="noopener noreferrer">${esc(d.domain)}</a>${PRIORITY_LABEL[d.priority] ? `<span class="prio">${PRIORITY_LABEL[d.priority]}</span>` : ''}
        <div class="sub">${upPill(d)} ${checked}</div>
      </div>
      <div class="ssl"><div>SSL ${expiryPill(sslDays, 14, 7, Boolean(d.ssl_error))}</div><div class="sub">${sslSub}</div></div>
      <div class="dom"><div>โดเมน ${expiryPill(regDays, 60, 14)}</div><div class="sub">${regSub}</div></div>
      <div class="actions">
        <button type="button" class="icon-btn" data-refresh="${d.id}" title="เช็กเว็บและโดเมนอีกครั้ง" aria-label="เช็ก ${esc(d.domain)} อีกครั้ง">↻</button>
        <button type="button" class="icon-btn del" data-del="${d.id}" title="ลบ" aria-label="ลบ ${esc(d.domain)}">✕</button>
      </div>
    </div>`;
  });
  $('#list').innerHTML = `<div class="row row-head"><span>โดเมน</span><span>ใบรับรอง SSL</span><span>ทะเบียนโดเมน</span><span></span></div>${rows.join('')}`;
}

async function load() {
  const [list, status] = await Promise.all([api('/domains'), api('/status')]);
  domains = list;
  render();
  renderHealth(status);
}

// Make a stalled checker visible instead of silently showing stale SSL data.
function renderHealth({ lastSslCheck, dispatch }) {
  const problems = [];
  const hours = lastSslCheck ? (Date.now() - Date.parse(lastSslCheck)) / 3_600_000 : null;
  if (domains.length && hours !== null && hours > 2) {
    problems.push(`⚠ ตัวเช็ก SSL ไม่ได้รันมา ${Math.floor(hours)} ชั่วโมง (ล่าสุด ${timeFmt.format(new Date(lastSslCheck))})`);
  }
  if (dispatch && !dispatch.ok) {
    problems.push(`⚠ สั่งรันตัวเช็กบน GitHub ไม่สำเร็จ: ${dispatch.error} — token อาจหมดอายุ`);
  }
  $('#health').textContent = problems.join('\n');
  $('#health').hidden = !problems.length;
}

$('#addForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const f = e.target;
  const btn = $('#addBtn');
  btn.disabled = true;
  btn.textContent = 'กำลังเช็ก…';
  try {
    const row = await api('/domains', { method: 'POST', body: { domain: f.domain.value, priority: f.priority.value } });
    domains.push(row);
    f.domain.value = '';
    showError(null);
    render();
  } catch (err) {
    showError(err);
  } finally {
    btn.disabled = false;
    btn.textContent = 'เพิ่ม';
  }
});

$('#list').addEventListener('click', async (e) => {
  const del = e.target.closest('[data-del]');
  const ref = e.target.closest('[data-refresh]');
  try {
    if (del) {
      const d = domains.find((x) => x.id === Number(del.dataset.del));
      if (!confirm(`เลิกติดตาม ${d.domain}?`)) return;
      await api(`/domains/${d.id}`, { method: 'DELETE' });
      domains = domains.filter((x) => x.id !== d.id);
      render();
    } else if (ref) {
      ref.disabled = true;
      const row = await api(`/domains/${ref.dataset.refresh}/refresh`, { method: 'POST', body: {} });
      domains = domains.map((x) => (x.id === row.id ? row : x));
      render();
    }
    showError(null);
  } catch (err) {
    showError(err);
    if (ref) ref.disabled = false;
  }
});

$('#reload').addEventListener('click', () => load().then(() => showError(null), showError));

(async () => {
  try {
    const me = await api('/me');
    $('#who').textContent = `เข้าสู่ระบบเป็น ${me.email}`;
    await load();
  } catch (err) {
    showError(err);
    $('#list').innerHTML = '';
  }
})();
