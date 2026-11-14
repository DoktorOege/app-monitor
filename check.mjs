// App-Monitor – prüft jede Stunde Michaels Apps und schreibt status.json.
// Welche Apps geprüft werden, steht in apps.json (Apps ohne url = nicht online, werden ausgelassen).
// Läuft in GitHub Actions (Node 20+, keine Zusatzpakete).
// Geheime Schlüssel kommen aus den GitHub-Secrets, nie aus dieser Datei:
//   NTFY_TOPIC      Name des Push-Kanals in der ntfy-App
//   CF_API_TOKEN    Cloudflare-Token mit "Account Analytics: Read"
//   CF_ACCOUNT_ID   Cloudflare-Konto-ID
//   GCP_SA_KEY      Google-Dienstkonto (JSON) mit Rolle "Monitoring-Betrachter"
//   GITHUB_TOKEN    kommt automatisch aus GitHub Actions

import { readFile, writeFile } from 'node:fs/promises';
import { createSign } from 'node:crypto';

const MONITOR_URL = 'https://doktoroege.github.io/app-monitor/';
const WARN = 70, CRIT = 90;               // Prozent
const QUIET_FROM = 22, QUIET_TO = 7;      // nachts nur Rot
const LIMITS = {
  cfRequests: 100000,  // Cloudflare Workers, pro Tag, ganzes Konto
  kvReads: 100000,     // Cloudflare KV, pro Tag
  kvWrites: 1000,      // Cloudflare KV, pro Tag
  fsReads: 50000,      // Firestore, pro Tag
  fsWrites: 20000,
  fsDeletes: 20000,
  ghSiteMB: 1024       // GitHub Pages, Größe der Seite
};
const env = process.env;
const now = new Date();

// ---------- Hilfen ----------
const fmt = n => Math.round(n).toLocaleString('de-DE');
const pct = (used, limit) => (limit ? Math.min(999, (used / limit) * 100) : 0);
const levelOf = p => (p >= CRIT ? 'crit' : p >= WARN ? 'warn' : 'ok');
const RANK = { off: 0, ok: 1, warn: 2, crit: 3 };

function partsIn(tz, d = now) {
  const p = Object.fromEntries(new Intl.DateTimeFormat('en-GB', { timeZone: tz, hourCycle: 'h23', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' }).formatToParts(d).map(x => [x.type, x.value]));
  return { y: +p.year, m: +p.month, d: +p.day, h: +p.hour, min: +p.minute, s: +p.second };
}
function startOfDay(tz) { // Mitternacht von heute in einer Zeitzone
  const p = partsIn(tz);
  const offset = Date.UTC(p.y, p.m - 1, p.d, p.h, p.min, p.s) - Math.floor(now.getTime() / 1000) * 1000;
  return new Date(Date.UTC(p.y, p.m - 1, p.d) - offset);
}
const berlinTime = d => d.toLocaleTimeString('de-DE', { timeZone: 'Europe/Berlin', hour: '2-digit', minute: '2-digit' });
const berlinDay = (d = now) => { const p = partsIn('Europe/Berlin', d); return `${p.y}-${String(p.m).padStart(2, '0')}-${String(p.d).padStart(2, '0')}`; };
const resetText = tz => `Startet um ${berlinTime(new Date(startOfDay(tz).getTime() + 864e5)).replace(/^0/, '')} Uhr neu.`;

async function get(url, opts = {}, tries = 2) {
  for (let i = 0; i < tries; i++) {
    try { return await fetch(url, { ...opts, signal: AbortSignal.timeout(15000) }); }
    catch (e) { if (i === tries - 1) throw e; await new Promise(r => setTimeout(r, 3000)); }
  }
}
async function reachable(url) {
  try { return (await get(url, { headers: { 'cache-control': 'no-cache' } })).ok; } catch { return false; }
}
function bar(provider, label, used, limit, opts = {}) {
  const p = pct(used, limit);
  return { provider, label, used, limit, text: `${fmt(used)} / ${fmt(limit)}${opts.unit || ''}`, pct: Math.round(p), level: levelOf(p), ...opts };
}

// ---------- Cloudflare (einmal pro Lauf, für alle Apps) ----------
async function cloudflare() {
  if (!env.CF_API_TOKEN || !env.CF_ACCOUNT_ID) return null;
  const since = startOfDay('UTC').toISOString();
  const query = `query($acc:String!,$since:Time!,$until:Time!){viewer{accounts(filter:{accountTag:$acc}){
    workers:workersInvocationsAdaptive(limit:10000,filter:{datetime_geq:$since,datetime_leq:$until}){sum{requests} dimensions{scriptName}}
    kv:kvOperationsAdaptiveGroups(limit:10000,filter:{datetime_geq:$since,datetime_leq:$until}){sum{requests} dimensions{actionType}}
  }}}`;
  const r = await get('https://api.cloudflare.com/client/v4/graphql', {
    method: 'POST',
    headers: { authorization: `Bearer ${env.CF_API_TOKEN.trim()}`, 'content-type': 'application/json' },
    body: JSON.stringify({ query, variables: { acc: env.CF_ACCOUNT_ID.trim(), since, until: now.toISOString() } })
  });
  const j = await r.json();
  const acc = j.data?.viewer?.accounts?.[0];
  if (!acc) throw new Error('Cloudflare: ' + (j.errors || []).map(e => e.message).join('; '));
  const byScript = {};
  let total = 0;
  for (const row of acc.workers || []) { const n = row.sum?.requests || 0; const s = row.dimensions?.scriptName || '?'; total += n; byScript[s] = (byScript[s] || 0) + n; }
  const kv = { read: 0, write: 0 };
  for (const row of acc.kv || []) {
    const t = row.dimensions?.actionType || '';
    if (t === 'read') kv.read += row.sum?.requests || 0;
    else if (['write', 'delete', 'list'].includes(t)) kv.write += row.sum?.requests || 0; // zählen alle gegen das 1.000er-Limit
  }
  return { total, byScript, kv };
}

// ---------- Google Firestore ----------
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
    if (!j.timeSeries) continue;
    return j.timeSeries.reduce((n, ts) => n + ts.points.reduce((m, p) => m + Number(p.value.int64Value ?? p.value.doubleValue ?? 0), 0), 0);
  }
  return 0;
}
let gToken = null;
async function firestore(project) {
  if (!env.GCP_SA_KEY) return null;
  const sa = JSON.parse(env.GCP_SA_KEY);
  gToken ||= await googleToken(sa);
  const since = startOfDay('America/Los_Angeles'); // Firestore-Limits starten um Mitternacht Pazifikzeit neu
  const p = project || sa.project_id;
  const [reads, writes, deletes] = await Promise.all([
    metricSum(gToken, p, ['document/read_ops_count', 'document/read_count'], since),
    metricSum(gToken, p, ['document/write_ops_count', 'document/write_count'], since),
    metricSum(gToken, p, ['document/delete_ops_count', 'document/delete_count'], since)
  ]);
  return { reads, writes, deletes };
}

// ---------- GitHub ----------
async function githubRepo(repo) {
  const headers = { accept: 'application/vnd.github+json', 'user-agent': 'app-monitor' };
  if (env.GITHUB_TOKEN) headers.authorization = `Bearer ${env.GITHUB_TOKEN}`;
  const r = await get(`https://api.github.com/repos/${repo}`, { headers });
  if (!r.ok) throw new Error(`GitHub ${repo}: ${r.status}`);
  return (await r.json()).size / 1024; // KB -> MB
}

// ---------- Eine App prüfen ----------
async function checkApp(cfg, cf) {
  const app = { id: cfg.id, name: cfg.name, url: cfg.url, providers: [], bars: [], facts: [], notes: [], problems: [] };
  const note = e => app.notes.push(String(e.message || e));

  if (!(await reachable(cfg.url))) app.problems.push({ level: 'crit', label: 'Nicht erreichbar', text: 'Die App antwortet gerade nicht.', todo: 'Melde dich bei Claude.' });

  if (cfg.cloudflare) {
    app.providers.push('Cloudflare');
    if (cf) {
      const mine = cfg.cloudflare.script ? (cf.byScript[cfg.cloudflare.script] || 0) : null;
      app.bars.push(bar('Cloudflare', 'Aufrufe heute', cf.total, LIMITS.cfRequests, {
        sub: (mine !== null ? `davon diese App: ${fmt(mine)} · ` : '') + 'Limit gilt für alle Cloudflare-Apps zusammen',
        reset: resetText('UTC')
      }));
      if (cfg.cloudflare.kv) {
        app.bars.push(bar('Cloudflare', 'Speicher gelesen heute', cf.kv.read, LIMITS.kvReads, { reset: resetText('UTC') }));
        app.bars.push(bar('Cloudflare', 'Speicher beschrieben heute', cf.kv.write, LIMITS.kvWrites, { reset: resetText('UTC') }));
      }
    } else app.facts.push({ provider: 'Cloudflare', text: env.CF_API_TOKEN ? 'Verbrauch gerade nicht abrufbar.' : 'Noch kein Schlüssel eingetragen.' });
  }

  if (cfg.firebase) {
    app.providers.push('Firebase');
    try {
      const fs = await firestore(cfg.firebase.project);
      if (fs) {
        const reset = resetText('America/Los_Angeles');
        app.bars.push(bar('Firebase', 'Daten gelesen heute', fs.reads, LIMITS.fsReads, { reset }));
        app.bars.push(bar('Firebase', 'Daten gespeichert heute', fs.writes, LIMITS.fsWrites, { reset }));
        app.bars.push(bar('Firebase', 'Daten gelöscht heute', fs.deletes, LIMITS.fsDeletes, { reset }));
      } else app.facts.push({ provider: 'Firebase', text: 'Noch kein Schlüssel eingetragen.' });
    } catch (e) { note(e); app.facts.push({ provider: 'Firebase', text: 'Verbrauch gerade nicht abrufbar.' }); }
  }

  if (cfg.github) {
    app.providers.push('GitHub');
    try {
      const mb = await githubRepo(cfg.github.repo);
      app.bars.push(bar('GitHub', 'Speicherplatz der Seite', mb, LIMITS.ghSiteMB, { text: `${mb < 10 ? mb.toFixed(1).replace('.', ',') : fmt(mb)} / ${fmt(LIMITS.ghSiteMB)} MB` }));
    } catch (e) { note(e); app.facts.push({ provider: 'GitHub', text: 'Verbrauch gerade nicht abrufbar.' }); }
  }

  if (cfg.pushCheck) {
    let ok = false;
    try { const r = await get(cfg.pushCheck); ok = r.ok && (await r.json()).ok === true; } catch { /* bleibt false */ }
    if (!ok) app.problems.push({ level: 'warn', label: 'Push gestört', text: 'Die App läuft, aber „Du bist dran“-Meldungen gehen gerade nicht raus.', todo: 'Melde dich bei Claude – vermutlich fehlt der Push-Schlüssel bei Cloudflare.' });
  }

  if (cfg.dataJson) {
    try {
      const r = await get(cfg.dataJson + '?t=' + Date.now());
      const updated = new Date((await r.json()).updated);
      if (isNaN(updated)) throw new Error('kein Datum');
      const hours = (now - updated) / 36e5;
      const when = berlinDay(updated) === berlinDay() ? `heute um ${berlinTime(updated)} Uhr` : `am ${updated.toLocaleDateString('de-DE', { timeZone: 'Europe/Berlin', day: 'numeric', month: 'numeric' })} um ${berlinTime(updated)} Uhr`;
      app.dataText = `Läuft. Daten aktualisiert ${when}.`;
      if (hours > 26) app.problems.push({ level: 'crit', label: 'Daten veraltet', text: `Seit über einem Tag keine neuen Daten (zuletzt ${when}).`, todo: 'Melde dich bei Claude – das automatische Update läuft nicht mehr.' });
      else if (hours > 14) app.problems.push({ level: 'warn', label: 'Update fehlt', text: `Das letzte Daten-Update war ${when}.`, todo: 'Nichts tun – wenn es morgen noch so ist, melde dich.' });
    } catch { app.problems.push({ level: 'crit', label: 'Keine Daten', text: 'Die Daten der App fehlen.', todo: 'Melde dich bei Claude.' }); }
  }

  for (const b of app.bars) {
    if (b.level === 'ok') continue;
    const full = b.pct >= 100;
    app.problems.push({
      level: b.level, label: full ? 'Voll' : b.level === 'crit' ? 'Fast voll' : 'Wird knapp',
      text: `${b.provider}: ${b.label} – ${b.pct} % vom Gratis-Kontingent. ${b.reset || ''}`.trim(),
      todo: full ? 'Die App hakt bis zum Neustart. Melde dich, dann mache ich sie sparsamer.' : 'Nichts tun – nur wenn es öfter passiert, melde dich.'
    });
  }

  const top = app.problems.sort((a, b) => RANK[b.level] - RANK[a.level])[0];
  delete app.problems;
  if (top) return { ...app, level: top.level, label: top.label, text: top.text, todo: top.todo };
  return { ...app, level: 'ok', label: 'Alles gut', text: app.dataText || 'Läuft. Weit weg von jeder Grenze.', todo: '' };
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
const config = JSON.parse(await readFile('apps.json', 'utf8')).filter(a => a.url); // ohne Adresse = nicht online
let old = {};
try { old = JSON.parse(await readFile('status.json', 'utf8')); } catch { /* erster Lauf */ }
const state = old.state || { notified: {}, warnDay: {} };
const history = old.history || [];

let cf = null, cfError = null;
if (config.some(a => a.cloudflare)) { try { cf = await cloudflare(); } catch (e) { cfError = String(e.message || e); } }

const apps = [];
for (const cfg of config) {
  try {
    const a = await checkApp(cfg, cf);
    if (cfError && cfg.cloudflare) a.notes.push(cfError);
    apps.push(a);
  } catch (e) { apps.push({ id: cfg.id, name: cfg.name, level: 'off', label: 'Prüfung fehlgeschlagen', text: String(e.message || e), bars: [], facts: [], notes: [], providers: [] }); }
}

const hour = partsIn('Europe/Berlin').h;
const quiet = hour >= QUIET_FROM || hour < QUIET_TO;
const today = berlinDay();

if (env.TEST_PUSH === 'true') await push('Test vom App-Monitor', 'Wenn du das liest, kommen die Warnungen auf deinem Handy an.', 3, ['white_check_mark']);

for (const a of apps) {
  const told = state.notified[a.id] || 'ok';
  const log = text => history.unshift({ t: now.toISOString(), id: a.id, level: a.level, text });
  const msg = `${a.text}\n${a.todo || ''}`.trim();
  if (a.level === 'crit' && told !== 'crit') {
    if (await push(`${a.name}: ${a.label}`, msg, 5, ['rotating_light'])) { state.notified[a.id] = 'crit'; log(`${a.name}: ${a.label}`); }
  } else if (a.level === 'warn' && RANK[told] < RANK.warn) {
    if (!quiet && state.warnDay[a.id] !== today && await push(`${a.name}: ${a.label}`, msg, 3, ['warning'])) {
      state.notified[a.id] = 'warn'; state.warnDay[a.id] = today; log(`${a.name}: ${a.label}`);
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
