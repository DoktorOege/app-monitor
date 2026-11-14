// App-Monitor – prüft jede Stunde Michaels Apps und schreibt status.json.
// Läuft in GitHub Actions (Node 20+, keine Zusatzpakete).
// Geheime Schlüssel kommen aus den GitHub-Secrets, nie aus dieser Datei:
//   NTFY_TOPIC      Name des Push-Kanals in der ntfy-App
//   CF_API_TOKEN    Cloudflare-Token mit "Account Analytics: Read"
//   CF_ACCOUNT_ID   Cloudflare-Konto-ID
//   GCP_SA_KEY      Google-Dienstkonto (JSON) mit Rolle "Monitoring-Betrachter"

import { readFile, writeFile } from 'node:fs/promises';
import { createSign } from 'node:crypto';

const MONITOR_URL = 'https://doktoroege.github.io/app-monitor/';
const WARN = 70, CRIT = 90;               // Prozent
const QUIET_FROM = 22, QUIET_TO = 7;      // nachts nur Rot
const env = process.env;
const now = new Date();

// ---------- Hilfen ----------
const fmt = n => Math.round(n).toLocaleString('de-DE');
const pct = (used, limit) => limit ? Math.min(999, (used / limit) * 100) : 0;
const levelOf = p => (p >= CRIT ? 'crit' : p >= WARN ? 'warn' : 'ok');
const RANK = { off: 0, ok: 1, warn: 2, crit: 3 };
const worst = list => list.reduce((a, b) => (RANK[b] > RANK[a] ? b : a), 'ok');

function partsIn(tz, d = now) {
  const p = Object.fromEntries(new Intl.DateTimeFormat('en-GB', { timeZone: tz, hourCycle: 'h23', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' }).formatToParts(d).map(x => [x.type, x.value]));
  return { y: +p.year, m: +p.month, d: +p.day, h: +p.hour, min: +p.minute, s: +p.second };
}
// Mitternacht von heute in einer Zeitzone, als Date
function startOfDay(tz) {
  const p = partsIn(tz);
  const offset = Date.UTC(p.y, p.m - 1, p.d, p.h, p.min, p.s) - Math.floor(now.getTime() / 1000) * 1000;
  return new Date(Date.UTC(p.y, p.m - 1, p.d) - offset);
}
const berlinTime = d => d.toLocaleTimeString('de-DE', { timeZone: 'Europe/Berlin', hour: '2-digit', minute: '2-digit' });
const berlinDay = (d = now) => { const p = partsIn('Europe/Berlin', d); return `${p.y}-${String(p.m).padStart(2, '0')}-${String(p.d).padStart(2, '0')}`; };
const nextReset = tz => new Date(startOfDay(tz).getTime() + 24 * 3600 * 1000);
const resetText = tz => `Startet um ${berlinTime(nextReset(tz)).replace(/^0/, '')} Uhr neu.`;

async function get(url, opts = {}, tries = 2) {
  for (let i = 0; i < tries; i++) {
    try {
      const r = await fetch(url, { ...opts, signal: AbortSignal.timeout(15000) });
      return r;
    } catch (e) { if (i === tries - 1) throw e; await new Promise(r => setTimeout(r, 3000)); }
  }
}
async function reachable(url) {
  try { const r = await get(url, { headers: { 'cache-control': 'no-cache' } }); return r.ok; } catch { return false; }
}

// ---------- Cloudflare: Aufrufe heute (ganzes Konto) ----------
async function cloudflareRequests() {
  if (!env.CF_API_TOKEN || !env.CF_ACCOUNT_ID) return null;
  const since = startOfDay('UTC').toISOString();
  const query = `query($acc:String!,$since:Time!,$until:Time!){viewer{accounts(filter:{accountTag:$acc}){workersInvocationsAdaptive(limit:10000,filter:{datetime_geq:$since,datetime_leq:$until}){sum{requests}}}}}`;
  const r = await get('https://api.cloudflare.com/client/v4/graphql', {
    method: 'POST',
    headers: { authorization: `Bearer ${env.CF_API_TOKEN.trim()}`, 'content-type': 'application/json' },
    body: JSON.stringify({ query, variables: { acc: env.CF_ACCOUNT_ID.trim(), since, until: now.toISOString() } })
  });
  const j = await r.json();
  if (j.errors && j.errors.length) throw new Error('Cloudflare: ' + j.errors.map(e => e.message).join('; '));
  const rows = j.data?.viewer?.accounts?.[0]?.workersInvocationsAdaptive || [];
  return rows.reduce((n, row) => n + (row.sum?.requests || 0), 0);
}

// ---------- Google: Firestore-Zugriffe heute ----------
async function googleToken(sa) {
  const b64u = s => Buffer.from(s).toString('base64url');
  const iat = Math.floor(Date.now() / 1000);
  const head = b64u(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const claims = b64u(JSON.stringify({ iss: sa.client_email, scope: 'https://www.googleapis.com/auth/monitoring.read', aud: 'https://oauth2.googleapis.com/token', iat, exp: iat + 3600 }));
  const sig = createSign('RSA-SHA256').update(`${head}.${claims}`).sign(sa.private_key).toString('base64url');
  const r = await get('https://oauth2.googleapis.com/token', {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion: `${head}.${claims}.${sig}` })
  });
  const j = await r.json();
  if (!j.access_token) throw new Error('Google-Anmeldung fehlgeschlagen: ' + (j.error_description || j.error || r.status));
  return j.access_token;
}
async function metricSum(token, project, types, since) {
  for (const type of types) {
    const q = new URLSearchParams({
      filter: `metric.type="firestore.googleapis.com/${type}"`,
      'interval.startTime': since.toISOString(), 'interval.endTime': now.toISOString(),
      'aggregation.alignmentPeriod': '3600s', 'aggregation.perSeriesAligner': 'ALIGN_SUM', 'aggregation.crossSeriesReducer': 'REDUCE_SUM'
    });
    const r = await get(`https://monitoring.googleapis.com/v3/projects/${project}/timeSeries?${q}`, { headers: { authorization: `Bearer ${token}` } });
    const j = await r.json();
    if (j.error) { if (r.status === 400 || r.status === 404) continue; throw new Error('Google: ' + j.error.message); }
    if (!j.timeSeries) continue; // Metrik ohne Daten -> nächsten Namen probieren
    return j.timeSeries.reduce((n, ts) => n + ts.points.reduce((m, p) => m + Number(p.value.int64Value ?? p.value.doubleValue ?? 0), 0), 0);
  }
  return 0;
}
async function firestoreUsage() {
  if (!env.GCP_SA_KEY) return null;
  const sa = JSON.parse(env.GCP_SA_KEY);
  const token = await googleToken(sa);
  const since = startOfDay('America/Los_Angeles'); // Firestore-Gratislimits starten um Mitternacht Pazifikzeit neu
  const project = sa.project_id;
  const [reads, writes, deletes] = await Promise.all([
    metricSum(token, project, ['document/read_ops_count', 'document/read_count'], since),
    metricSum(token, project, ['document/write_ops_count', 'document/write_count'], since),
    metricSum(token, project, ['document/delete_ops_count', 'document/delete_count'], since)
  ]);
  return { reads, writes, deletes };
}

// ---------- Die einzelnen Apps ----------
function bar(label, used, limit, unit = '') {
  const p = pct(used, limit);
  return { label, used, limit, text: `${fmt(used)} / ${fmt(limit)}${unit}`, pct: Math.round(p), level: levelOf(p) };
}

async function checkWeed() {
  const app = { id: 'weed', name: 'Weed!', bars: [], notes: [] };
  const base = 'https://weed-kma.kma-online.workers.dev';
  const up = await reachable(base + '/');
  let pushOk = false;
  try { const r = await get(base + '/api/push'); pushOk = r.ok && (await r.json()).ok === true; } catch { /* bleibt false */ }

  let cf = null, fs = null;
  try { cf = await cloudflareRequests(); } catch (e) { app.notes.push(String(e.message || e)); }
  try { fs = await firestoreUsage(); } catch (e) { app.notes.push(String(e.message || e)); }

  if (cf !== null) app.bars.push({ ...bar('Aufrufe heute (Cloudflare)', cf, 100000), reset: resetText('UTC'), what: 'Aufrufe', kind: 'cf' });
  if (fs) {
    app.bars.push({ ...bar('Spieldaten gelesen heute', fs.reads, 50000), reset: resetText('America/Los_Angeles'), what: 'Lesezugriffe', kind: 'fs' });
    app.bars.push({ ...bar('Spieldaten gespeichert heute', fs.writes, 20000), reset: resetText('America/Los_Angeles'), what: 'Speicherzugriffe', kind: 'fs' });
    app.bars.push({ ...bar('Spieldaten gelöscht heute', fs.deletes, 20000), reset: resetText('America/Los_Angeles'), what: 'Löschzugriffe', kind: 'fs' });
  }

  if (!up) {
    return { ...app, level: 'crit', label: 'Nicht erreichbar', text: 'Die Spielseite antwortet gerade nicht.', todo: 'Melde dich bei Claude – dann schauen wir bei Cloudflare nach.' };
  }
  const top = app.bars.slice().sort((a, b) => b.pct - a.pct)[0];
  if (top && top.level !== 'ok') {
    const crit = top.level === 'crit';
    const full = top.pct >= 100;
    return {
      ...app, level: top.level, label: full ? 'Voll' : crit ? 'Fast voll' : 'Wird knapp', focus: top.label,
      text: `${top.label}: ${top.pct} % vom Gratis-Kontingent. ${top.reset}`,
      todo: full ? 'Das Spiel hakt bis zum Neustart. Melde dich, dann mache ich es sparsamer.' : 'Nichts tun – nur wenn es öfter passiert, melde dich.'
    };
  }
  if (!pushOk) {
    return { ...app, level: 'warn', label: 'Push gestört', text: 'Das Spiel läuft, aber „Du bist dran“-Meldungen werden gerade nicht verschickt.', todo: 'Melde dich bei Claude – vermutlich fehlt der Push-Schlüssel bei Cloudflare.' };
  }
  const missing = [cf === null && 'Cloudflare', fs === null && 'Firebase'].filter(Boolean);
  return {
    ...app, level: 'ok', label: 'Alles gut',
    text: missing.length ? `Läuft. Verbrauch von ${missing.join(' und ')} wird noch nicht gemessen.` : 'Läuft. Weit weg von jeder Grenze.',
    todo: missing.length ? 'Schlüssel eintragen – siehe Anleitung.' : ''
  };
}

async function checkNba() {
  const app = { id: 'nba', name: 'NBA Aktuell', bars: [], notes: [] };
  const url = 'https://doktoroege.github.io/nba-aktuell/';
  let updated = null;
  try { const r = await get(url + 'data.json?t=' + Date.now()); if (r.ok) updated = new Date((await r.json()).updated); } catch { /* nicht erreichbar */ }
  if (!updated || isNaN(updated)) {
    const up = await reachable(url);
    return { ...app, level: 'crit', label: up ? 'Keine Daten' : 'Nicht erreichbar', text: up ? 'Die App ist da, aber die Daten fehlen.' : 'Die App antwortet gerade nicht.', todo: 'Melde dich bei Claude.' };
  }
  const hours = (now - updated) / 3600000;
  const when = berlinDay(updated) === berlinDay() ? `heute um ${berlinTime(updated)} Uhr` : `am ${updated.toLocaleDateString('de-DE', { timeZone: 'Europe/Berlin', day: 'numeric', month: 'numeric' })} um ${berlinTime(updated)} Uhr`;
  app.facts = [`Letztes Daten-Update: ${when}`];
  if (hours > 26) return { ...app, level: 'crit', label: 'Veraltet', text: `Seit über einem Tag keine neuen Daten (zuletzt ${when}).`, todo: 'Melde dich bei Claude – das automatische Update läuft nicht mehr.' };
  if (hours > 14) return { ...app, level: 'warn', label: 'Update fehlt', text: `Das letzte Update war ${when}. Eins wurde wohl ausgelassen.`, todo: 'Nichts tun – wenn es morgen noch so ist, melde dich.' };
  return { ...app, level: 'ok', label: 'Alles gut', text: `Die Daten wurden ${when} aktualisiert.`, todo: '' };
}

async function checkContainer() {
  const app = { id: 'container', name: 'Container-Scanner', bars: [], notes: [] };
  const up = await reachable('https://doktoroege.github.io/container-scanner/');
  return up
    ? { ...app, level: 'ok', label: 'Alles gut', text: 'Läuft.', todo: '' }
    : { ...app, level: 'crit', label: 'Nicht erreichbar', text: 'Die App antwortet gerade nicht.', todo: 'Melde dich bei Claude.' };
}

// ---------- Push über ntfy ----------
async function push(title, message, priority = 3, tags = []) {
  if (!env.NTFY_TOPIC) { console.log('(kein NTFY_TOPIC – Push übersprungen)', title); return true; }
  const r = await get('https://ntfy.sh/', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ topic: env.NTFY_TOPIC.trim(), title, message, priority, tags, click: MONITOR_URL })
  });
  console.log('Push', r.status, title);
  return r.ok;
}

// ---------- Ablauf ----------
let old = {};
try { old = JSON.parse(await readFile('status.json', 'utf8')); } catch { /* erster Lauf */ }
const state = old.state || { notified: {}, warnDay: {} };
const history = old.history || [];

const apps = [];
for (const [id, name, fn] of [['weed', 'Weed!', checkWeed], ['nba', 'NBA Aktuell', checkNba], ['container', 'Container-Scanner', checkContainer]]) {
  try { apps.push(await fn()); }
  catch (e) { apps.push({ id, name, level: 'off', label: 'Prüfung fehlgeschlagen', text: String(e.message || e), bars: [], notes: [] }); }
}

const hour = partsIn('Europe/Berlin').h;
const quiet = hour >= QUIET_FROM || hour < QUIET_TO;
const today = berlinDay();

if (env.TEST_PUSH === 'true') await push('Test vom App-Monitor', 'Wenn du das liest, kommen die Warnungen auf deinem Handy an.', 3, ['white_check_mark']);

for (const a of apps) {
  const told = state.notified[a.id] || 'ok';
  const log = text => history.unshift({ t: now.toISOString(), id: a.id, level: a.level, text });
  if (a.level === 'crit' && told !== 'crit') {
    if (await push(`${a.name}: ${a.label}`, `${a.text}\n${a.todo}`.trim(), 5, ['rotating_light'])) { state.notified[a.id] = 'crit'; log(`${a.name}: ${a.label}`); }
  } else if (a.level === 'warn' && RANK[told] < RANK.warn) {
    if (!quiet && state.warnDay[a.id] !== today) {
      if (await push(`${a.name}: ${a.label}`, `${a.text}\n${a.todo}`.trim(), 3, ['warning'])) { state.notified[a.id] = 'warn'; state.warnDay[a.id] = today; log(`${a.name}: ${a.label}`); }
    }
  } else if (a.level === 'warn' && told === 'crit') {
    state.notified[a.id] = 'warn';
  } else if (a.level === 'ok' && told !== 'ok') {
    if (told === 'crit' && !quiet) await push(`${a.name}: wieder in Ordnung`, a.text, 2, ['white_check_mark']);
    if (told !== 'crit' || !quiet) { state.notified[a.id] = 'ok'; log(`${a.name}: wieder in Ordnung`); }
  }
}

const out = { checkedAt: now.toISOString(), thresholds: { warn: WARN, crit: CRIT }, apps, state, history: history.slice(0, 15) };
await writeFile('status.json', JSON.stringify(out, null, 1) + '\n');
console.log(apps.map(a => `${a.name}: ${a.level} – ${a.text}${a.notes?.length ? ' [' + a.notes.join(' | ') + ']' : ''}`).join('\n'));
