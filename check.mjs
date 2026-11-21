// App-Monitor – prüft jede Stunde Michaels Apps und schreibt status.json.
// Welche Apps geprüft werden, steht in apps.json (Apps ohne url = nicht online, werden ausgelassen).
// Läuft in GitHub Actions (Node 20+, keine Zusatzpakete).
// Geheime Schlüssel kommen aus den GitHub-Secrets, nie aus dieser Datei:
//   NTFY_TOPIC      Name des Push-Kanals in der ntfy-App
//   CF_API_TOKEN    Cloudflare-Token mit "Account Analytics: Read"
//   CF_ACCOUNT_ID   (optional) Cloudflare-Konto-ID, sonst die eingetragene
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
  doRequests: 100000,  // Durable Objects, pro Tag
  doRowsRead: 5000000,
  doRowsWritten: 100000,
  doGbs: 13000,        // Durable Objects Rechenzeit (GB-Sekunden), pro Tag
  fsReads: 50000,      // Firestore, pro Tag
  fsWrites: 20000,
  fsDeletes: 20000,
  ghSiteMB: 1024       // GitHub Pages, Größe der Seite
};
const env = process.env;
const CF_ACCOUNT_ID = (env.CF_ACCOUNT_ID || '1ca86790493de4518fd1b1c410173613').trim(); // Konto-ID ist kein Geheimnis
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
  const t0 = Date.now();
  try { const r = await get(url, { headers: { 'cache-control': 'no-cache' } }); await r.arrayBuffer(); return { ok: r.ok, ms: Date.now() - t0 }; }
  catch { return { ok: false, ms: null }; }
}
const median = arr => { const a = arr.filter(n => n != null).sort((x, y) => x - y); return a.length ? a[Math.floor(a.length / 2)] : null; };
function bar(provider, label, used, limit, opts = {}) {
  const p = pct(used, limit);
  return { provider, label, used, limit, text: `${fmt(used)} / ${fmt(limit)}${opts.unit || ''}`, pct: Math.round(p), level: levelOf(p), ...opts };
}

// ---------- Cloudflare (einmal pro Lauf, für alle Apps) ----------
async function cloudflare() {
  if (!env.CF_API_TOKEN) return null;
  const since = startOfDay('UTC').toISOString();
  const query = `query($acc:String!,$since:Time!,$until:Time!){viewer{accounts(filter:{accountTag:$acc}){
    workers:workersInvocationsAdaptive(limit:10000,filter:{datetime_geq:$since,datetime_leq:$until}){sum{requests errors} dimensions{scriptName}}
    kv:kvOperationsAdaptiveGroups(limit:10000,filter:{datetime_geq:$since,datetime_leq:$until}){sum{requests} dimensions{actionType}}
  }}}`;
  const r = await get('https://api.cloudflare.com/client/v4/graphql', {
    method: 'POST',
    headers: { authorization: `Bearer ${env.CF_API_TOKEN.trim()}`, 'content-type': 'application/json' },
    body: JSON.stringify({ query, variables: { acc: CF_ACCOUNT_ID, since, until: now.toISOString() } })
  });
  const j = await r.json();
  const acc = j.data?.viewer?.accounts?.[0];
  if (!acc) throw new Error('Cloudflare: ' + (j.errors || []).map(e => e.message).join('; '));
  const byScript = {}, errByScript = {};
  let total = 0;
  for (const row of acc.workers || []) { const n = row.sum?.requests || 0; const s = row.dimensions?.scriptName || '?'; total += n; byScript[s] = (byScript[s] || 0) + n; errByScript[s] = (errByScript[s] || 0) + (row.sum?.errors || 0); }
  const kv = { read: 0, write: 0 };
  for (const row of acc.kv || []) {
    const t = row.dimensions?.actionType || '';
    if (t === 'read') kv.read += row.sum?.requests || 0;
    else if (['write', 'delete', 'list'].includes(t)) kv.write += row.sum?.requests || 0; // zählen alle gegen das 1.000er-Limit
  }
  return { total, byScript, errByScript, kv };
}

// ---------- Durable Objects (z. B. Kniffel-Spielräume), ganzes Konto ----------
async function durableObjects() {
  if (!env.CF_API_TOKEN) return null;
  const since = startOfDay('UTC').toISOString();
  const variants = [
    'inv:durableObjectsInvocationsAdaptiveGroups(limit:1000,filter:{datetime_geq:$since,datetime_leq:$until}){sum{requests}} per:durableObjectsPeriodicGroups(limit:1000,filter:{datetime_geq:$since,datetime_leq:$until}){sum{activeTime rowsRead rowsWritten}}',
    'inv:durableObjectsInvocationsAdaptiveGroups(limit:1000,filter:{datetime_geq:$since,datetime_leq:$until}){sum{requests}} per:durableObjectsPeriodicGroups(limit:1000,filter:{datetime_geq:$since,datetime_leq:$until}){sum{activeTime}}',
    'inv:durableObjectsInvocationsAdaptiveGroups(limit:1000,filter:{datetime_geq:$since,datetime_leq:$until}){sum{requests}}'
  ];
  let lastErr = '';
  for (const body of variants) {
    const r = await get('https://api.cloudflare.com/client/v4/graphql', {
      method: 'POST',
      headers: { authorization: `Bearer ${env.CF_API_TOKEN.trim()}`, 'content-type': 'application/json' },
      body: JSON.stringify({ query: `query($acc:String!,$since:Time!,$until:Time!){viewer{accounts(filter:{accountTag:$acc}){${body}}}}`, variables: { acc: CF_ACCOUNT_ID, since, until: now.toISOString() } })
    });
    const j = await r.json();
    const acc = j.data?.viewer?.accounts?.[0];
    if (!acc) { lastErr = (j.errors || []).map(e => e.message).join('; '); continue; }
    const sum = (rows, f) => (rows || []).reduce((n, x) => n + (x.sum?.[f] || 0), 0);
    return {
      requests: sum(acc.inv, 'requests'),
      gbs: acc.per ? sum(acc.per, 'activeTime') / 1e6 * 0.125 : null,
      rowsRead: acc.per && acc.per[0]?.sum && 'rowsRead' in acc.per[0].sum ? sum(acc.per, 'rowsRead') : null,
      rowsWritten: acc.per && acc.per[0]?.sum && 'rowsWritten' in acc.per[0].sum ? sum(acc.per, 'rowsWritten') : null
    };
  }
  throw new Error('Durable Objects: ' + lastErr);
}

// ---------- Besucher (Cloudflare Web Analytics, ohne Cookies) ----------
async function visitors() {
  if (!env.CF_API_TOKEN) return null;
  const since = new Date(now.getTime() - 7 * 864e5).toISOString();
  const query = `query($acc:String!,$since:Time!,$until:Time!){viewer{accounts(filter:{accountTag:$acc}){
    rum:rumPageloadEventsAdaptiveGroups(limit:10000,filter:{datetime_geq:$since,datetime_leq:$until}){count dimensions{requestHost requestPath datetimeMinute}}
  }}}`;
  const r = await get('https://api.cloudflare.com/client/v4/graphql', {
    method: 'POST',
    headers: { authorization: `Bearer ${env.CF_API_TOKEN.trim()}`, 'content-type': 'application/json' },
    body: JSON.stringify({ query, variables: { acc: CF_ACCOUNT_ID, since, until: now.toISOString() } })
  });
  const j = await r.json();
  const rows = j.data?.viewer?.accounts?.[0]?.rum;
  if (!rows) throw new Error('Besucher: ' + (j.errors || []).map(e => e.message).join('; '));
  return rows.map(x => ({ host: x.dimensions.requestHost, path: x.dimensions.requestPath || '/', t: new Date(x.dimensions.datetimeMinute), n: x.count || 0 }));
}
function visitStats(rows, v) {
  const mine = rows.filter(x => x.host === v.host && x.path.startsWith(v.path));
  const today = berlinDay();
  let last = null, todayN = 0, weekN = 0;
  const dayKeys = [...Array(7)].map((_, i) => berlinDay(new Date(now.getTime() - (6 - i) * 864e5)));
  const days = dayKeys.map(() => 0);
  const hours = Array(24).fill(0);
  for (const x of mine) {
    hours[partsIn('Europe/Berlin', x.t).h] += x.n;
    weekN += x.n; const k = berlinDay(x.t);
    if (k === today) todayN += x.n;
    const i = dayKeys.indexOf(k); if (i >= 0) days[i] += x.n;
    if (!last || x.t > last) last = x.t;
  }
  return { lastVisit: last ? last.toISOString() : null, today: todayN, week: weekN, days, hours };
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
  const j = await r.json();
  return { mb: j.size / 1024, pushed: j.pushed_at ? new Date(j.pushed_at) : null };
}
function whenText(d) {
  if (!d || isNaN(d)) return null;
  const t = berlinTime(d) + ' Uhr';
  if (berlinDay(d) === berlinDay()) return `heute, ${t}`;
  if (berlinDay(d) === berlinDay(new Date(now.getTime() - 864e5))) return `gestern, ${t}`;
  return `${d.toLocaleDateString('de-DE', { timeZone: 'Europe/Berlin', day: 'numeric', month: 'numeric', year: 'numeric' })}, ${t}`;
}

// ---------- Eine App prüfen ----------
async function checkApp(cfg, cf, rum, state, dob) {
  const app = { id: cfg.id, name: cfg.name, group: cfg.group || 'Sonstiges', url: cfg.url, providers: [], bars: [], facts: [], notes: [], problems: [] };
  const note = e => app.notes.push(String(e.message || e));

  // erreichbar? + Ladezeit
  const reach = await reachable(cfg.url);
  if (!reach.ok) app.problems.push({ level: 'crit', label: 'Nicht erreichbar', text: 'Die App antwortet gerade nicht.', todo: 'Melde dich bei Claude.' });
  app.ms = reach.ms;
  // Erreichbarkeit der letzten 30 Tage
  const up = (state.uptime[cfg.id] ||= {});
  const d = berlinDay(); up[d] = up[d] || [0, 0]; up[d][0] += reach.ok ? 1 : 0; up[d][1] += 1;
  for (const k of Object.keys(up).sort().slice(0, -30)) delete up[k];
  const [okN, allN] = Object.values(up).reduce((s2, [o, t]) => [s2[0] + o, s2[1] + t], [0, 0]);
  app.uptime = allN ? Math.floor((okN / allN) * 1000) / 10 : null;
  app.uptimeDays = Object.keys(up).sort().slice(-30).map(k => ({ d: k, pct: Math.round((up[k][0] / up[k][1]) * 1000) / 10 }));
  // langsam? (deutlich langsamer als sonst, zweimal hintereinander)
  const speeds = (state.speed[cfg.id] ||= []);
  const usual = median(speeds);
  const slowNow = reach.ok && reach.ms != null && usual != null && speeds.length >= 6 && reach.ms > Math.max(3 * usual, 3000);
  if (slowNow && state.slow[cfg.id]) app.problems.push({ level: 'warn', label: 'Lädt langsam', text: `Die App braucht gerade ${(reach.ms / 1000).toFixed(1).replace('.', ',')} Sekunden zum Laden – sonst etwa ${(usual / 1000).toFixed(1).replace('.', ',')} Sekunden.`, todo: 'Nichts tun – meist ist das nach einer Stunde vorbei.' });
  state.slow[cfg.id] = slowNow;
  if (reach.ok && reach.ms != null) { speeds.push(reach.ms); if (speeds.length > 48) speeds.shift(); }
  app.usualMs = usual;

  // Besucher
  if (cfg.visits && rum) Object.assign(app, { visits: visitStats(rum, cfg.visits) });

  if (cfg.cloudflare) {
    app.providers.push('Cloudflare');
    if (cf) {
      const mine = cfg.cloudflare.script ? (cf.byScript[cfg.cloudflare.script] || 0) : null;
      app.cfMine = mine;
      app.bars.push(bar('Cloudflare', 'Aufrufe heute', cf.total, LIMITS.cfRequests, { shared: true,
        sub: (mine !== null ? `davon diese App: ${fmt(mine)} · ` : '') + 'Limit gilt für alle Cloudflare-Apps zusammen',
        reset: resetText('UTC')
      }));
      if (cfg.cloudflare.script) {
        const errs = cf.errByScript[cfg.cloudflare.script] || 0;
        app.cfErrors = errs;
        if (errs >= 5 && mine && errs / mine > 0.1) app.problems.push({ level: 'warn', label: 'Fehler im Server-Baustein', text: `Heute sind ${fmt(errs)} von ${fmt(mine)} Aufrufen bei Cloudflare mit Fehler abgebrochen.`, todo: 'Melde dich bei Claude – dann schauen wir in die Cloudflare-Logs.' });
        app.facts.push({ provider: 'Cloudflare', text: `Fehler heute: ${fmt(errs)}` });
      }
      if (cfg.cloudflare.durableObjects && dob) {
        const reset = resetText('UTC');
        app.bars.push(bar('Cloudflare', 'Spielräume (alle Spiele): Anfragen heute', dob.requests, LIMITS.doRequests, { shared: true, reset }));
        if (dob.rowsWritten != null) app.bars.push(bar('Cloudflare', 'Spielräume (alle Spiele): gespeichert heute', dob.rowsWritten, LIMITS.doRowsWritten, { shared: true, reset }));
        if (dob.rowsRead != null) app.bars.push(bar('Cloudflare', 'Spielräume (alle Spiele): gelesen heute', dob.rowsRead, LIMITS.doRowsRead, { shared: true, reset }));
        if (dob.gbs != null) app.bars.push(bar('Cloudflare', 'Spielräume (alle Spiele): Rechenzeit heute', dob.gbs, LIMITS.doGbs, { shared: true, reset, text: `${fmt(dob.gbs)} / ${fmt(LIMITS.doGbs)} GB-s` }));
      }
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
    } catch (e) {
      const usage = `https://console.firebase.google.com/project/${cfg.firebase.project}/firestore/usage`;
      if (/billing/i.test(String(e.message))) app.facts.push({ provider: 'Firebase', text: 'Im Gratis-Tarif gibt Google den Verbrauch nicht automatisch heraus. Du kannst ihn in der Firebase-Konsole ansehen.', link: usage, linkText: 'Verbrauch in Firebase ansehen' });
      else { note(e); app.facts.push({ provider: 'Firebase', text: 'Verbrauch gerade nicht abrufbar.', link: usage, linkText: 'In Firebase ansehen' }); }
    }
  }

  if (cfg.github) {
    app.providers.push('GitHub');
    try {
      const { mb, pushed } = await githubRepo(cfg.github.repo);
      if (pushed && !app.updated) app.updated = pushed.toISOString();
      app.bars.push(bar('GitHub', 'Speicherplatz der Seite', mb, LIMITS.ghSiteMB, { text: `${mb < 10 ? mb.toFixed(1).replace('.', ',') : fmt(mb)} / ${fmt(LIMITS.ghSiteMB)} MB` }));
    } catch (e) { note(e); app.facts.push({ provider: 'GitHub', text: 'Verbrauch gerade nicht abrufbar.' }); }
  }

  if (cfg.versionUrl) { // z. B. {"v":"14.11.2026, 02:16 Uhr"}
    try {
      const vj = await (await get(cfg.versionUrl + '?t=' + Date.now())).json();
      const v = vj.v || '';
      const iso = String(vj.version || '').match(/^(\d{4})-(\d{2})-(\d{2})/);
      if (iso && !v) app.versionDay = `${+iso[3]}.${+iso[2]}.${iso[1]}`;
      const m = String(v).match(/(\d{1,2})\.(\d{1,2})\.(\d{4}),?\s*(\d{1,2}):(\d{2})/);
      if (m) {
        const guess = Date.UTC(+m[3], m[2] - 1, +m[1], +m[4], +m[5]);
        const off = (() => { const p = partsIn('Europe/Berlin', new Date(guess)); return Date.UTC(p.y, p.m - 1, p.d, p.h, p.min) - guess; })();
        app.updated = new Date(guess - off).toISOString();
      }
    } catch { /* ohne Versionsangabe */ }
  }

  if (cfg.pushCheck) {
    let ok = false;
    try { const r = await get(cfg.pushCheck); const pj = await r.json(); ok = r.ok && (pj.ok === true || !!pj.pub); } catch { /* bleibt false */ }
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
    if (b.level === 'ok' || b.shared) continue; // gemeinsame Kontingente meldet der Konto-Eintrag
    const full = b.pct >= 100;
    app.problems.push({
      level: b.level, label: full ? 'Voll' : b.level === 'crit' ? 'Fast voll' : 'Wird knapp',
      text: `${b.label.replace(/^Spielräume \(alle Spiele\): /, 'Spielräume aller Spiele – ')} (${b.provider}): ${b.pct} % vom Gratis-Kontingent. ${b.reset || ''}`.trim(),
      todo: full ? 'Die App hakt bis zum Neustart. Melde dich, dann mache ich sie sparsamer.' : 'Nichts tun – nur wenn es öfter passiert, melde dich.'
    });
  }

  app.updatedText = whenText(app.updated ? new Date(app.updated) : null);
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
const state = old.state || {};
for (const k of ['notified', 'warnDay', 'uptime', 'speed', 'slow']) state[k] ||= {};
const history = old.history || [];

let cf = null, cfError = null;
if (config.some(a => a.cloudflare)) { try { cf = await cloudflare(); } catch (e) { cfError = String(e.message || e); } }

let dob = null, dobError = null;
if (config.some(a => a.cloudflare?.durableObjects)) { try { dob = await durableObjects(); } catch (e) { dobError = String(e.message || e); } }
let rum = null, rumError = null;
if (config.some(a => a.visits)) { try { rum = await visitors(); } catch (e) { rumError = String(e.message || e); } }

const apps = [];
for (const cfg of config) {
  try {
    const a = await checkApp(cfg, cf, rum, state, dob);
    if (dobError && cfg.cloudflare?.durableObjects) a.notes.push(dobError);
    if (rumError && cfg.visits) a.notes.push(rumError);
    if (cfError && cfg.cloudflare) a.notes.push(cfError);
    apps.push(a);
  } catch (e) { apps.push({ id: cfg.id, name: cfg.name, level: 'off', label: 'Prüfung fehlgeschlagen', text: String(e.message || e), bars: [], facts: [], notes: [], providers: [] }); }
}

// Gemeinsame Gratis-Kontingente (gelten für alle Apps zusammen) als eigener Eintrag
{
  const shared = [];
  if (cf) shared.push(bar('Cloudflare', 'Aufrufe heute (alle Apps)', cf.total, LIMITS.cfRequests, { reset: resetText('UTC') }));
  if (dob) {
    shared.push(bar('Cloudflare', 'Spielräume: Anfragen heute', dob.requests, LIMITS.doRequests, { reset: resetText('UTC') }));
    if (dob.rowsWritten != null) shared.push(bar('Cloudflare', 'Spielräume: gespeichert heute', dob.rowsWritten, LIMITS.doRowsWritten, { reset: resetText('UTC') }));
    if (dob.rowsRead != null) shared.push(bar('Cloudflare', 'Spielräume: gelesen heute', dob.rowsRead, LIMITS.doRowsRead, { reset: resetText('UTC') }));
    if (dob.gbs != null) shared.push(bar('Cloudflare', 'Spielräume: Rechenzeit heute', dob.gbs, LIMITS.doGbs, { reset: resetText('UTC') }));
  }
  const top = shared.filter(b => b.level !== 'ok').sort((a, b) => b.pct - a.pct)[0];
  if (top) apps.push({ id: 'konto', name: 'Gratis-Kontingente', synthetic: true, level: top.level, label: top.pct >= 100 ? 'Voll' : top.level === 'crit' ? 'Fast voll' : 'Wird knapp',
    text: `${top.label} – ${top.pct} % vom Gratis-Kontingent (gilt für alle Apps zusammen). ${top.reset}`,
    todo: top.pct >= 100 ? 'Die betroffenen Apps haken bis zum Neustart. Melde dich bei Claude.' : 'Nichts tun – nur wenn es öfter passiert, melde dich.', bars: [], notes: [] });
}

const hour = partsIn('Europe/Berlin').h;
const quiet = hour >= QUIET_FROM || hour < QUIET_TO;
const today = berlinDay();

if (env.TEST_PUSH === 'true') await push('Test vom App-Monitor', 'Wenn du das liest, kommen die Warnungen auf deinem Handy an.', 3, ['white_check_mark']);

const muteOf = id => { const c = config.find(x => x.id === id) || {}; if (c.muted) return 'aus'; if (c.mutedUntil && c.mutedUntil >= today) return c.mutedUntil; return null; };
for (const a of apps) { const m = muteOf(a.id); if (m) a.muted = m; }
for (const a of apps) {
  if (a.muted) continue; // Meldungen für diese App stumm geschaltet
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

// ---------- Wochenbericht: sonntags ab 19 Uhr, einmal ----------
const bp = partsIn('Europe/Berlin');
const isSunday = new Date(Date.UTC(bp.y, bp.m - 1, bp.d)).getUTCDay() === 0;
if ((isSunday && bp.h >= 19 && state.weeklyDay !== today) || env.TEST_WEEKLY === 'true') {
  const lines = apps.map(a => {
    const parts = [];
    if (a.visits) parts.push(`${fmt(a.visits.week)} Aufrufe`);
    if (a.uptime != null) parts.push(`${String(a.uptime).replace('.', ',')} % erreichbar`);
    parts.push(a.level === 'ok' ? 'alles gut' : a.label);
    return `${a.name}: ${parts.join(', ')}`;
  });
  if (await push('Wochenbericht deiner Apps', lines.join('\n'), 2, ['bar_chart']) && env.TEST_WEEKLY !== 'true') state.weeklyDay = today;
}

// Neue, noch nicht eingetragene Cloudflare-Apps entdecken
const allCfg = JSON.parse(await readFile('apps.json', 'utf8'));
const known = new Set(allCfg.map(a => a.cloudflare?.script).filter(Boolean));
const discovered = cf ? Object.entries(cf.byScript).filter(([n, c]) => n && n !== '?' && !known.has(n) && c > 0).map(([n, c]) => ({ script: n, url: `https://${n}.kma-online.workers.dev/`, requests: c })) : [];
state.discoveredTold ||= {};
for (const d of discovered) {
  if (!state.discoveredTold[d.script] && await push('Neue App entdeckt', `${d.script} läuft bei Cloudflare, ist aber noch nicht im Monitor. Sag Claude Bescheid, dann wird sie aufgenommen.`, 3, ['sparkles'])) state.discoveredTold[d.script] = today;
}

const account = {
  discovered,
  cloudflare: cf ? { requests: cf.total, limit: LIMITS.cfRequests, reset: resetText('UTC') } : null,
  durableObjects: dob ? { requests: dob.requests, rowsWritten: dob.rowsWritten, rowsRead: dob.rowsRead, gbs: dob.gbs,
    limits: { requests: LIMITS.doRequests, rowsWritten: LIMITS.doRowsWritten, rowsRead: LIMITS.doRowsRead, gbs: LIMITS.doGbs } } : null,
  firebaseUsage: 'https://console.firebase.google.com/project/weed-online-kma/firestore/usage',
  hours: apps.reduce((h, a) => (a.visits?.hours || []).reduce((acc, n, i) => { acc[i] += n; return acc; }, h), Array(24).fill(0))
};
const out = { checkedAt: now.toISOString(), account, thresholds: { warn: WARN, crit: CRIT }, apps, state, history: history.slice(0, 15) };
await writeFile('status.json', JSON.stringify(out, null, 1) + '\n');
console.log(apps.map(a => `${a.name}: ${a.level} – ${a.text}${a.notes?.length ? ' [' + a.notes.join(' | ') + ']' : ''}`).join('\n'));
