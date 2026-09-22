'use strict';
/* LinkTest front end. Talks to the local Python server over a tiny JSON API
   and polls /api/events for live iperf3 data. No frameworks, no CDN. */

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];

const S = {
  status: null, settings: {}, history: [],
  mode: 'client', direction: 'upload', protocol: 'tcp',
  seq: 0, running: false,
  run: null,          // current/last run: {opts, cmd, intervals, log, start, summary, error, stopped}
  serverResults: [],  // finished tests received while in server mode (this session)
  viewing: null,      // history entry open in the dialog
};

/* ------------------------------------------------------------------------ */
/* Formatting                                                                */
/* ------------------------------------------------------------------------ */
function fmtBps(b) {
  if (b == null || isNaN(b)) return { n: '—', u: '' };
  const units = ['bps', 'Kbps', 'Mbps', 'Gbps', 'Tbps'];
  let i = 0; let v = Number(b);
  while (v >= 1000 && i < units.length - 1) { v /= 1000; i++; }
  const n = v >= 100 ? v.toFixed(0) : v >= 10 ? v.toFixed(1) : v.toFixed(2);
  return { n, u: units[i] };
}
const bpsStr = b => { const f = fmtBps(b); return f.u ? `${f.n} ${f.u}` : f.n; };
function fmtBytes(x) {
  if (x == null || isNaN(x)) return '—';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0; let v = Number(x);
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v >= 100 ? v.toFixed(0) : v >= 10 ? v.toFixed(1) : v.toFixed(2)} ${units[i]}`;
}
const fmtPct = p => (p == null || isNaN(p)) ? '—' : (p < 0.01 && p > 0 ? '<0.01' : (+p).toFixed(p < 1 ? 2 : 1)) + '%';
const fmtMs = ms => (ms == null || isNaN(ms)) ? '—' : `${(+ms).toFixed(ms < 10 ? 2 : 1)} ms`;
const fmtWhen = ts => new Date(ts * 1000).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const DIR_WORD = { upload: 'Send', download: 'Receive', both: 'Both directions' };

/* ------------------------------------------------------------------------ */
/* API                                                                       */
/* ------------------------------------------------------------------------ */
async function api(path, body) {
  let res;
  try {
    res = await fetch(path, body === undefined ? {} : {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}),
    });
  } catch (e) {
    return { error: 'LinkTest is not responding. If you closed it, reopen the app.', offline: true };
  }
  let data = {};
  try { data = await res.json(); } catch (e) { /* ignore */ }
  if (!res.ok && !data.error) data.error = `Server error (${res.status})`;
  return data;
}

/* ------------------------------------------------------------------------ */
/* Toast + clipboard                                                         */
/* ------------------------------------------------------------------------ */
let toastTimer;
function toast(msg) {
  const t = $('#toast'); t.textContent = msg; t.classList.remove('hidden');
  clearTimeout(toastTimer); toastTimer = setTimeout(() => t.classList.add('hidden'), 2200);
}
async function copyText(text, what = 'Copied') {
  try { await navigator.clipboard.writeText(text); toast(what); }
  catch (e) {
    const ta = document.createElement('textarea'); ta.value = text; document.body.appendChild(ta);
    ta.select(); try { document.execCommand('copy'); toast(what); } catch (e2) { toast('Could not copy'); }
    ta.remove();
  }
}
async function download(name, text, type = 'text/plain') {
  // Native window: ask the app for a real Save dialog. Browser mode: blob download.
  if (S.status && S.status.app.windowed) {
    const r = await api('/api/export', { name, text });
    if (r.ok) { toast('Saved to ' + r.path); return; }
    if (r.cancelled) return;
    if (r.error && r.error !== 'not-windowed') { toast('Could not save: ' + r.error); return; }
  }
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([text], { type }));
  a.download = name; document.body.appendChild(a); a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 500);
}

/* ------------------------------------------------------------------------ */
/* Form <-> options                                                          */
/* ------------------------------------------------------------------------ */
const V = id => $('#' + id).value.trim();
const C = id => $('#' + id).checked;
function collectOpts() {
  if (S.mode === 'server') {
    return {
      mode: 'server', port: V('sport') || '5201', interval: V('sinterval') || '1', bind: V('sbind'),
      ipver: V('sipver'), idleTimeout: V('idleTimeout'), serverBitrateLimit: V('serverBitrateLimit'),
      extraArgs: V('sextraArgs'), oneOff: C('oneOff'),
    };
  }
  return {
    mode: 'client', host: V('host'), port: V('port') || '5201', protocol: S.protocol, direction: S.direction,
    duration: V('duration') || '10', parallel: V('parallel') || '1',
    bitrate: S.protocol === 'udp' ? (V('bitrate') || '100M') : '',
    amount: ($('input[name=amount]:checked') || {}).value || 'time', bytes: V('bytes'), blocks: V('blocks'),
    interval: V('interval') || '1', omit: V('omit'), window: V('window'), length: V('length'), mss: V('mss'),
    bind: V('bind'), ipver: V('ipver'), cport: V('cport'), dscp: V('dscp'), tos: V('tos'),
    connectTimeout: V('connectTimeout'), nodelay: C('nodelay'), zerocopy: C('zerocopy'),
    getServerOutput: C('getServerOutput'), repeatingPayload: C('repeatingPayload'),
    dontFragment: C('dontFragment'), udp64: C('udp64'), congestion: V('congestion'), title: V('title'),
    extraArgs: V('extraArgs'),
  };
}
function setVal(id, v) { const el = $('#' + id); if (el && v !== undefined && v !== null) el.value = v; }
function setChk(id, v) { const el = $('#' + id); if (el) el.checked = !!v; }
function applyOpts(o) {
  if (!o) return;
  if (o.mode === 'server') {
    setMode('server');
    setVal('sport', o.port); setVal('sinterval', o.interval); setVal('sbind', o.bind); setVal('sipver', o.ipver || 'auto');
    setVal('idleTimeout', o.idleTimeout); setVal('serverBitrateLimit', o.serverBitrateLimit); setVal('sextraArgs', o.extraArgs);
    setChk('oneOff', o.oneOff);
    return;
  }
  setMode('client');
  setVal('host', o.host); setVal('port', o.port); setSeg('protocol', o.protocol || 'tcp'); setSeg('direction', o.direction || 'upload');
  setVal('duration', o.duration); setVal('parallel', o.parallel); if (o.bitrate) setVal('bitrate', o.bitrate);
  const am = $(`input[name=amount][value="${o.amount || 'time'}"]`); if (am) am.checked = true;
  ['bytes', 'blocks', 'interval', 'omit', 'window', 'length', 'mss', 'bind', 'cport', 'dscp', 'tos', 'connectTimeout',
   'congestion', 'title', 'extraArgs'].forEach(k => setVal(k, o[k] ?? ''));
  setVal('ipver', o.ipver || 'auto');
  ['nodelay', 'zerocopy', 'getServerOutput', 'repeatingPayload', 'dontFragment', 'udp64'].forEach(k => setChk(k, o[k]));
  refreshProtoUI();
}
function setSeg(id, v) {
  $$(`#${id} button`).forEach(b => b.classList.toggle('on', b.dataset.v === v));
  S[id] = v;
}
function refreshProtoUI() {
  $('#bitrateField').classList.toggle('hidden', S.protocol !== 'udp');
  const f = (S.status && S.status.iperf.features) || {};
  const both = $('#direction button[data-v=both]');
  both.disabled = f.bidir === false;
  both.title = both.disabled ? 'Needs iperf3 3.7 or newer' : 'Send and receive at the same time';
}
function setMode(m) {
  S.mode = m;
  $$('input[name=mode]').forEach(r => { r.checked = r.value === m; });
  $('#clientForm').classList.toggle('hidden', m !== 'client');
  $('#serverForm').classList.toggle('hidden', m !== 'server');
  $('#serverLog').classList.toggle('hidden', m !== 'server');
  if (m === 'server') $('#resultPanel').classList.add('hidden');
  $('#btnStart').textContent = S.running ? (m === 'server' ? 'Stop listening' : 'Stop test') : (m === 'server' ? 'Start listening' : 'Start test');
  schedulePreview();
}

const PRESETS = {
  quick: { protocol: 'tcp', direction: 'upload', duration: '10', parallel: '1', omit: '' },
  max:   { protocol: 'tcp', direction: 'upload', duration: '20', parallel: '8', omit: '2' },
  both:  { protocol: 'tcp', direction: 'both', duration: '10', parallel: '1', omit: '' },
  voice: { protocol: 'udp', direction: 'upload', duration: '15', parallel: '1', bitrate: '10M', omit: '' },
};
function applyPreset(name) {
  const p = PRESETS[name]; if (!p) return;
  setSeg('protocol', p.protocol); setSeg('direction', p.direction);
  setVal('duration', p.duration); setVal('parallel', p.parallel); setVal('omit', p.omit);
  if (p.bitrate) setVal('bitrate', p.bitrate);
  $$('#presets .chip').forEach(c => c.classList.toggle('on', c.dataset.preset === name));
  refreshProtoUI(); schedulePreview();
}

/* Command preview ----------------------------------------------------------*/
let previewTimer;
function schedulePreview() { clearTimeout(previewTimer); previewTimer = setTimeout(updatePreview, 250); }
async function updatePreview() {
  const r = await api('/api/preview', { opts: collectOpts() });
  $('#cmdLine').textContent = r.cmd || (r.error ? `(${r.error})` : '');
}

/* ------------------------------------------------------------------------ */
/* Status / setup                                                            */
/* ------------------------------------------------------------------------ */
async function refreshStatus() {
  const st = await api('/api/status');
  if (st.error) return;
  S.status = st;
  const ip = st.iperf;
  const pill = $('#enginePill');
  pill.classList.remove('pill-good', 'pill-bad', 'pill-muted');
  if (ip.found) { pill.textContent = `iperf3 ${ip.version}`; pill.classList.add('pill-good'); pill.title = ip.path; }
  else { pill.textContent = 'iperf3 problem'; pill.classList.add('pill-bad'); pill.title = 'See the setup box'; }
  if (typeof T !== 'undefined') pill.classList.toggle('hidden', T.tab !== 'speed');
  $('#setupCard').classList.toggle('hidden', ip.found);
  if (!ip.found) {
    const why = $('#setupWhy');
    why.textContent = ip.error ? ip.error : (ip.bundled ? 'The built-in copy would not start.' : 'No built-in copy was found in this build.');
    why.classList.remove('hidden');
    $('#iperfPathInput').placeholder = st.app.isWindows ? 'C:\\Tools\\iperf3\\iperf3.exe' : '/usr/bin/iperf3';
  }
  const fw = st.app.firewall;
  $('#fwField').classList.toggle('hidden', !fw);
  if (fw && !S.fwTouched) {
    $('#fwLabel').textContent = fw === 'windows' ? 'Windows Firewall' : fw === 'ufw' ? 'Firewall (ufw)' : 'Firewall (firewalld)';
    $('#fwStatus').textContent = fw === 'windows'
      ? 'Needed once so other computers can reach this one. Windows will ask for permission.'
      : 'Needed once so other computers can reach this one. Linux will ask for your password.';
  }
  $('#btnStart').disabled = !ip.found && !S.running;
  renderAddresses(st.net);
  $('#aboutVer').textContent = st.app.version;
  $('#aboutEngine').innerHTML = ip.found
    ? `Engine: <b>iperf3 ${esc(ip.version)}</b> at <code>${esc(ip.path)}</code>`
    : 'Engine: iperf3 could not be started.';
  $('#aboutState').textContent = `Settings and history are stored in ${st.app.stateDir}`;
  refreshProtoUI();
  // Reconnect to a test that is already running (page reload while testing).
  if (st.runner.running && !S.running) {
    S.running = true; S.mode = st.runner.mode || S.mode;
    S.run = S.run || newRun(st.runner.opts || {}, st.runner.cmd);
    setMode(S.mode); setRunningUI(true);
  }
}
function renderAddresses(net) {
  const box = $('#addrList');
  $('#hostName').textContent = net.hostname || '';
  const addrs = net.addresses || [];
  if (!addrs.length) { box.innerHTML = '<span class="hint">No network address found. Is this computer connected to a network?</span>'; return; }
  box.innerHTML = addrs.map((a, i) => `<button class="addr ${a === net.primary ? 'primary' : ''}" data-a="${esc(a)}">${esc(a)}${a === net.primary ? '<small>most likely</small>' : ''}</button>`).join('');
  $$('.addr', box).forEach(b => b.onclick = () => copyText(b.dataset.a, `Copied ${b.dataset.a}`));
}
/* ------------------------------------------------------------------------ */
/* Running a test                                                            */
/* ------------------------------------------------------------------------ */
function newRun(opts, cmd) {
  return { opts, cmd, intervals: [], log: [], start: null, summary: null, error: null, stopped: false, startedAt: Date.now(), ended: false };
}
// Well-known public iperf3 servers (built in; availability varies). ports = range the server accepts.
// Public iperf3 servers, USA only. Every entry was verified with the bundled iperf3 on 2026-09-11
// (re-check with `python tools/check_public_servers.py` before changing this list).
// ports = the range the server accepts; port = the one filled in.
const PUBLIC_SERVERS = [
  { region: 'USA (tested 2026-09-11)', name: 'Hurricane Electric (Fremont, CA)', host: 'iperf.he.net', port: 5201, ports: '5201', note: 'one test at a time; if it says busy, wait a moment or pick another server' },
  { region: 'USA (tested 2026-09-11)', name: 'Leaseweb (Seattle)', host: 'speedtest.sea11.us.leaseweb.net', port: 5201, ports: '5201–5210' },
  { region: 'USA (tested 2026-09-11)', name: 'Leaseweb (San Francisco)', host: 'speedtest.sfo12.us.leaseweb.net', port: 5201, ports: '5201–5210' },
  { region: 'USA (tested 2026-09-11)', name: 'Leaseweb (Los Angeles)', host: 'speedtest.lax12.us.leaseweb.net', port: 5201, ports: '5201–5210' },
  { region: 'USA (tested 2026-09-11)', name: 'Clouvider (Los Angeles)', host: 'la.speedtest.clouvider.net', port: 5201, ports: '5200–5209' },
  { region: 'USA (tested 2026-09-11)', name: 'Leaseweb (Phoenix)', host: 'speedtest.phx1.us.leaseweb.net', port: 5201, ports: '5201–5210' },
  { region: 'USA (tested 2026-09-11)', name: 'Leaseweb (Dallas)', host: 'speedtest.dal13.us.leaseweb.net', port: 5201, ports: '5201–5210' },
  { region: 'USA (tested 2026-09-11)', name: 'Clouvider (Dallas)', host: 'dal.speedtest.clouvider.net', port: 5201, ports: '5200–5209' },
  { region: 'USA (tested 2026-09-11)', name: 'Leaseweb (Chicago)', host: 'speedtest.chi11.us.leaseweb.net', port: 5201, ports: '5201–5210' },
  { region: 'USA (tested 2026-09-11)', name: 'Clouvider (Atlanta)', host: 'atl.speedtest.clouvider.net', port: 5201, ports: '5200–5209' },
  { region: 'USA (tested 2026-09-11)', name: 'Leaseweb (Miami)', host: 'speedtest.mia11.us.leaseweb.net', port: 5201, ports: '5201–5210' },
  { region: 'USA (tested 2026-09-11)', name: 'Leaseweb (Washington DC)', host: 'speedtest.wdc2.us.leaseweb.net', port: 5201, ports: '5201–5210' },
  { region: 'USA (tested 2026-09-11)', name: 'Leaseweb (New York)', host: 'speedtest.nyc1.us.leaseweb.net', port: 5201, ports: '5201–5210' },
];
function isPublicServer(host) { const h = (host || '').trim().toLowerCase(); return PUBLIC_SERVERS.some(s => s.host === h); }
function publicPorts(host) {
  // Every port the public server accepts, so a busy server can be retried on its other ports.
  const h = (host || '').trim().toLowerCase(); const s = PUBLIC_SERVERS.find(x => x.host === h); if (!s) return [];
  const m = /^(\d+)\D+(\d+)$/.exec(s.ports || ''); if (!m) return [s.port];
  const lo = +m[1], hi = +m[2]; const out = []; for (let p = lo; p <= hi && out.length < 64; p++) out.push(p); return out;
}
function renderPublicServers() {
  const sel = $('#publicServers'); if (!sel) return;
  const groups = {};
  PUBLIC_SERVERS.forEach((s, i) => (groups[s.region] = groups[s.region] || []).push(`<option value="${i}">${esc(s.name)} · ${esc(s.host)}</option>`));
  sel.innerHTML = '<option value="">Or pick a public test server (USA)…</option>' + Object.entries(groups).map(([g, opts]) => `<optgroup label="${esc(g)}">${opts.join('')}</optgroup>`).join('');
  sel.onchange = () => {
    const s = PUBLIC_SERVERS[+sel.value]; if (!s) return;
    $('#host').value = s.host; $('#port').value = s.port;
    $('#publicHint').textContent = (s.ports.includes('–') ? `${s.name} accepts ports ${s.ports}; port ${s.port} is filled in. If it says busy, try another port in that range.` : `${s.name}, port ${s.port}.`) + (s.note ? ` (${s.note})` : '') + ' Public servers are not added to Recent.';
    setMode('client'); schedulePreview(); sel.value = '';
  };
}
function renderRecentHosts(list) {
  S.recentHosts = list || [];
  const box = $('#recentHosts'); const dl = $('#hostList');
  box.classList.toggle('hidden', !S.recentHosts.length);
  box.innerHTML = S.recentHosts.length ? '<span class="hint" style="margin-right:4px">Recent:</span>' + S.recentHosts.map(h => `<button type="button" data-h="${esc(h)}" title="Use ${esc(h)}">${esc(h)}</button>`).join('') : '';
  dl.innerHTML = S.recentHosts.map(h => `<option value="${esc(h)}"></option>`).join('');
  $$('button', box).forEach(b => b.onclick = () => { $('#host').value = b.dataset.h; $('#host').focus(); schedulePreview(); });
}
async function startTest() {
  const opts = collectOpts();
  const errBox = $('#formError'); errBox.classList.add('hidden');
  const isPublic = opts.mode === 'client' && isPublicServer(opts.host);
  // Public servers are shared: keep trying every few seconds (rotating through the server's ports) until the test runs.
  const retry = isPublic ? { every: 3, maxSeconds: 120, ports: publicPorts(opts.host) } : null;
  const r = await api('/api/start', { opts, skipRecent: isPublic, retry });
  if (r.error) { errBox.textContent = r.error; errBox.classList.remove('hidden'); return; }
  if (opts.mode === 'client' && opts.host && !isPublic) renderRecentHosts([opts.host].concat((S.recentHosts || []).filter(h => h.toLowerCase() !== opts.host.toLowerCase())).slice(0, 5));
  S.run = newRun(opts, r.cmd); S.running = true; S.seq = 0;
  if (S.mode === 'server') { S.serverResults = []; renderServerResults(); }
  $('#cmdLine').textContent = r.cmd;
  setRunningUI(true);
  showLive(); renderLive();
  $('#resultPanel').classList.add('hidden');
}
async function stopTest() { await api('/api/stop', {}); }
function setRunningUI(on) {
  S.running = on;
  const b = $('#btnStart');
  b.classList.toggle('stop', on);
  b.textContent = on ? (S.mode === 'server' ? 'Stop listening' : 'Stop test') : (S.mode === 'server' ? 'Start listening' : 'Start test');
  b.disabled = !on && !(S.status && S.status.iperf.found);
  $('#modes').classList.toggle('locked', on);
  $$('#modes input').forEach(i => i.disabled = on);
}
function showLive() { $('#livePanel').classList.remove('hidden'); }

/* Event polling ------------------------------------------------------------*/
async function pollEvents() {
  const r = await api(`/api/events?since=${S.seq}`);
  if (r.error || !r.events) return;
  for (const e of r.events) { S.seq = e.seq; handleEvent(e); }
  if (S.running && r.running === false && S.run && !S.run.ended) {
    // process gone but no exit event seen yet; give the next poll a chance
  }
}
function handleEvent(e) {
  if (!S.run) S.run = newRun((S.status && S.status.runner.opts) || {}, null);
  const run = S.run;
  switch (e.type) {
    case 'state': if (e.cmd) run.cmd = e.cmd; if (e.opts) run.opts = e.opts; if (e.cmd) $('#cmdLine').textContent = e.cmd; break;
    case 'retry': run.error = null; run.retry = e; run.intervals = []; renderLive(); break;
    case 'log': run.log.push(e.line); if (run.log.length > 3000) run.log.splice(0, 500); break;
    case 'start':
      if (S.mode === 'server') { run.intervals = []; run.summary = null; run.error = null; run.log = run.log.slice(-50); }
      run.start = e.info || {}; run.startedAt = Date.now(); run.retry = null; run.error = null;
      showLive(); renderLive(); break;
    case 'interval': run.intervals.push(e); renderLive(); break;
    case 'end':
      run.summary = e.summary || {};
      if (S.mode === 'server') {
        S.serverResults.unshift({ ts: Date.now() / 1000, summary: run.summary, intervals: run.intervals.slice(), opts: run.opts });
        renderServerResults();
        refreshHistory();
      } else {
        showResult(run); refreshHistory();
      }
      renderLive(); break;
    case 'serverOutput': run.log.push('--- other side ---'); run.log.push(e.text); break;
    case 'error': run.error = e; renderLive(); break;
    case 'exit':
      run.ended = true; run.stopped = !!e.stopped;
      setRunningUI(false);
      if (S.mode === 'client' && !run.summary) {
        if (run.intervals.length && (run.stopped || !run.error)) showResult(run); // partial
        else showResult(run);
      }
      renderLive(); break;
  }
}

/* Live panel ---------------------------------------------------------------*/
function dirLabels(run) {
  const st = run.start || {}; const o = run.opts || {};
  if (S.mode === 'server' || o.mode === 'server') {
    const who = st.host ? `${st.host}` : 'the other computer';
    if (st.bidir) return { fwd: `Receiving from ${who}`, rev: `Sending to ${who}` };
    return st.reverse ? { fwd: `Sending to ${who}` } : { fwd: `Receiving from ${who}` };
  }
  if (o.direction === 'download') return { fwd: 'Receiving' };
  if (o.direction === 'both') return { fwd: 'Sending', rev: 'Receiving' };
  return { fwd: 'Sending' };
}
function renderLive() {
  const run = S.run; if (!run) return;
  const o = run.opts || {};
  const ivs = run.intervals.filter(i => !i.omitted);
  const last = run.intervals[run.intervals.length - 1];
  const status = $('#liveStatus');
  const server = (o.mode === 'server');
  let text, cls = 'status';
  if (S.running) {
    cls += ' running';
    if (server) text = run.start && !run.summary ? `Test in progress from ${run.start.host || '…'}` : `Listening on port ${o.port || 5201}… waiting for a computer to connect`;
    else if (run.retry && !run.start) text = run.retry.friendly;
    else if (!run.start && !run.intervals.length) text = `Connecting to ${o.host}…`;
    else text = `Testing against ${o.host}…`;
  } else {
    text = run.stopped ? 'Stopped' : run.error && !run.summary ? 'Failed' : run.summary ? 'Finished' : 'Ended';
  }
  status.textContent = text; status.className = cls;
  // timer
  let planned = null;
  if (!server && (o.amount || 'time') === 'time') planned = +o.duration || 10;
  const t = last ? last.t1 : 0;
  $('#liveTimer').textContent = last ? (planned ? `${Math.round(t)} of ${planned} s` : `${Math.round(t)} s`) : '';
  // big number
  const labels = dirLabels(run);
  if (last) {
    const f = fmtBps(last.bps);
    $('#liveSpeed').textContent = f.n; $('#liveSpeedUnit').textContent = f.u;
    let sub = labels.fwd + (last.omitted ? ' (warm-up, not counted)' : '');
    if (last.reverse) sub += ` · ${labels.rev}: ${bpsStr(last.reverse.bps)}`;
    if (last.perStream && last.perStream.length > 1) sub += ` · ${last.perStream.length} connections`;
    $('#liveSub').textContent = sub;
  } else {
    $('#liveSpeed').textContent = '—'; $('#liveSpeedUnit').textContent = '';
    $('#liveSub').textContent = run.error && !S.running ? run.error.friendly : '';
  }
  drawChart($('#chart'), run.intervals, { labels });
  // legend
  const hasRev = run.intervals.some(i => i.reverse);
  $('#legend').innerHTML = `<span><i style="background:var(--accent)"></i>${esc(labels.fwd)}</span>` +
    (hasRev ? `<span><i style="background:var(--reverse)"></i>${esc(labels.rev || 'Reverse')}</span>` : '') +
    (run.intervals.some(i => i.omitted) ? `<span><i style="background:var(--line)"></i>Warm-up (ignored)</span>` : '') +
    `<span><i style="background:transparent;border-top:2px dashed var(--muted);height:0;margin-top:5px"></i>Average</span>`;
  // tiles
  const tiles = [];
  if (ivs.length) {
    const avg = ivs.reduce((a, i) => a + (i.bps || 0), 0) / ivs.length;
    tiles.push(tile('Average so far', bpsStr(avg)));
    tiles.push(tile('Data moved', fmtBytes(ivs.reduce((a, i) => a + (i.bytes || 0), 0))));
    if (ivs.some(i => i.retransmits != null)) tiles.push(tile('Retransmits', ivs.reduce((a, i) => a + (i.retransmits || 0), 0)));
    if (ivs.some(i => i.lost_packets != null)) {
      const lost = ivs.reduce((a, i) => a + (i.lost_packets || 0), 0), pk = ivs.reduce((a, i) => a + (i.packets || 0), 0);
      tiles.push(tile('Lost packets', `${lost}<small>of ${pk}</small>`));
    }
    if (last && last.jitter_ms != null) tiles.push(tile('Jitter now', fmtMs(last.jitter_ms)));
  }
  if (run.error && S.running) tiles.push(`<div class="error" style="grid-column:1/-1">${esc(run.error.friendly)}</div>`);
  if (run.retry && S.running && !run.start) tiles.push(`<div class="hint" style="grid-column:1/-1">Public servers are shared. LinkTest keeps trying for up to 2 minutes; press Stop to give up.</div>`);
  $('#liveTiles').innerHTML = tiles.join('');
}
function tile(k, v, cls = '') { return `<div class="tile ${cls}"><div class="k">${esc(k)}</div><div class="v">${v}</div></div>`; }

/* Chart --------------------------------------------------------------------*/
function drawChart(canvas, intervals, opts = {}) {
  const dpr = window.devicePixelRatio || 1;
  // Setting canvas.height rewrites the height attribute, so remember the CSS height once.
  if (!canvas.dataset.h) canvas.dataset.h = canvas.getAttribute('height') || '220';
  const W = canvas.clientWidth || 600, H = parseInt(canvas.dataset.h) || 220;
  canvas.style.height = H + 'px';
  canvas.width = Math.round(W * dpr); canvas.height = Math.round(H * dpr);
  const ctx = canvas.getContext('2d'); ctx.scale(dpr, dpr);
  const css = getComputedStyle(document.documentElement);
  const col = n => css.getPropertyValue(n).trim();
  const padL = 62, padR = 12, padT = 12, padB = 24;
  const pw = W - padL - padR, ph = H - padT - padB;
  ctx.clearRect(0, 0, W, H);
  const fwd = intervals.map(i => i.bps || 0);
  const rev = intervals.map(i => i.reverse ? (i.reverse.bps || 0) : null);
  const hasRev = rev.some(v => v != null);
  const max = Math.max(1e3, ...fwd, ...rev.filter(v => v != null)) * 1.12;
  // grid
  ctx.font = '11px system-ui, sans-serif'; ctx.textBaseline = 'middle';
  for (let g = 0; g <= 4; g++) {
    const y = padT + ph - (ph * g / 4);
    ctx.strokeStyle = col('--line'); ctx.lineWidth = 1;
    ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(W - padR, y); ctx.stroke();
    ctx.fillStyle = col('--soft'); ctx.textAlign = 'right';
    ctx.fillText(bpsStr(max * g / 4), padL - 8, y);
  }
  const n = intervals.length;
  const slots = Math.max(n, opts.minSlots || 10);
  const slot = pw / slots;
  const barW = Math.max(2, slot * (hasRev ? 0.38 : 0.72));
  const y0 = padT + ph;
  intervals.forEach((iv, k) => {
    const cx = padL + slot * k + slot / 2;
    const hF = (iv.bps || 0) / max * ph;
    ctx.fillStyle = iv.omitted ? col('--line') : col('--accent');
    if (hasRev) roundRect(ctx, cx - barW - 1, y0 - hF, barW, hF, 3);
    else roundRect(ctx, cx - barW / 2, y0 - hF, barW, hF, 3);
    if (iv.reverse) {
      const hR = (iv.reverse.bps || 0) / max * ph;
      ctx.fillStyle = iv.omitted ? col('--line') : col('--reverse');
      roundRect(ctx, cx + 1, y0 - hR, barW, hR, 3);
    }
  });
  // average line (non-omitted forward)
  const good = intervals.filter(i => !i.omitted);
  if (good.length > 1) {
    const avg = good.reduce((a, i) => a + (i.bps || 0), 0) / good.length;
    const y = y0 - avg / max * ph;
    ctx.setLineDash([5, 4]); ctx.strokeStyle = col('--muted'); ctx.lineWidth = 1.5;
    ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(W - padR, y); ctx.stroke(); ctx.setLineDash([]);
  }
  // x labels
  ctx.fillStyle = col('--soft'); ctx.textAlign = 'center';
  const step = Math.max(1, Math.ceil(n / Math.max(4, Math.floor(pw / 60))));
  intervals.forEach((iv, k) => {
    if ((k + 1) % step === 0 || k === n - 1) ctx.fillText(`${Math.round(iv.t1)}s`, padL + slot * k + slot / 2, H - padB / 2);
  });
  if (!n) { ctx.fillStyle = col('--soft'); ctx.textAlign = 'center'; ctx.font = '13px system-ui, sans-serif'; ctx.fillText('Speed over time appears here', padL + pw / 2, padT + ph / 2); }
}
function roundRect(ctx, x, y, w, h, r) {
  if (h <= 0) return; r = Math.min(r, w / 2, h);
  ctx.beginPath(); ctx.moveTo(x, y + h); ctx.lineTo(x, y + r); ctx.quadraticCurveTo(x, y, x + r, y);
  ctx.lineTo(x + w - r, y); ctx.quadraticCurveTo(x + w, y, x + w, y + r); ctx.lineTo(x + w, y + h); ctx.closePath(); ctx.fill();
}

/* ------------------------------------------------------------------------ */
/* Analysis / verdict                                                        */
/* ------------------------------------------------------------------------ */
const TIERS = [[10e6, '10 Mbps'], [100e6, '100 Mbps'], [1e9, '1 Gbps'], [2.5e9, '2.5 Gbps'], [5e9, '5 Gbps'], [10e9, '10 Gbps'], [25e9, '25 Gbps'], [40e9, '40 Gbps'], [100e9, '100 Gbps']];
function rateNote(bps) {
  const t = TIERS.find(t => bps <= t[0] * 1.02);
  if (!t) return { level: 'good', text: `${bpsStr(bps)} is faster than common network links.` };
  const pct = Math.round(bps / t[0] * 100);
  if (pct >= 90) return { level: 'good', text: `That is about ${pct}% of a ${t[1]} link, which is as good as that kind of connection gets.` };
  if (pct >= 70) return { level: 'good', text: `That is about ${pct}% of a ${t[1]} link: good, with a little lost to Wi‑Fi, cabling or other traffic.` };
  if (pct >= 40) return { level: 'info', text: `That is about ${pct}% of a ${t[1]} link. Normal for Wi‑Fi, but low for a wired ${t[1]} connection.` };
  return { level: 'warn', text: `That is only ${pct}% of a ${t[1]} link. Something in between (Wi‑Fi, a slow switch port, a damaged cable, or a busy computer) is holding it back.` };
}
const LEVEL_RANK = { good: 0, info: 1, warn: 2, bad: 3 };
const worst = (a, b) => LEVEL_RANK[a] >= LEVEL_RANK[b] ? a : b;
function mainRate(block) { return block && (block.received && block.received.bps) || (block && block.sent && block.sent.bps) || null; }
function partialSummary(run) {
  const ivs = run.intervals.filter(i => !i.omitted);
  if (!ivs.length) return null;
  const avg = ivs.reduce((a, i) => a + (i.bps || 0), 0) / ivs.length;
  const bytes = ivs.reduce((a, i) => a + (i.bytes || 0), 0);
  const s = { partial: true, received: { bps: avg, bytes }, start: run.start };
  if (ivs.some(i => i.retransmits != null)) s.sent = { bps: avg, bytes, retransmits: ivs.reduce((a, i) => a + (i.retransmits || 0), 0) };
  if (ivs.some(i => i.lost_packets != null)) {
    const lost = ivs.reduce((a, i) => a + (i.lost_packets || 0), 0), pk = ivs.reduce((a, i) => a + (i.packets || 0), 0);
    s.udp = { lost, packets: pk, lostPct: pk ? lost / pk * 100 : 0, jitter_ms: ivs[ivs.length - 1].jitter_ms };
  }
  if (ivs.some(i => i.reverse)) {
    const ravg = ivs.reduce((a, i) => a + ((i.reverse || {}).bps || 0), 0) / ivs.length;
    s.reverse = { received: { bps: ravg } };
  }
  return s;
}
function analyse(run) {
  const o = run.opts || {}; const server = o.mode === 'server';
  let s = run.summary; let partial = false;
  if (!s) { s = partialSummary(run); partial = true; }
  const notes = []; let level = 'good';
  if (!s) {
    const why = run.error ? run.error.friendly : (run.stopped ? 'The test was stopped before any data was measured.' : 'iperf3 ended without producing a result.');
    return { level: run.stopped ? 'info' : 'bad', title: run.stopped ? 'Stopped' : 'The test could not run', text: why, notes: [], tiles: [], summary: null };
  }
  const proto = ((s.start && s.start.protocol) || o.protocol || 'tcp').toLowerCase();
  const labels = dirLabels(run);
  const rate = mainRate(s);
  const revRate = s.reverse ? mainRate(s.reverse) : null;
  let title;
  if (server) title = `${labels.fwd}: ${bpsStr(rate)}` + (revRate != null ? ` · ${labels.rev}: ${bpsStr(revRate)}` : '');
  else if (o.direction === 'both') title = `Send ${bpsStr(rate)} · Receive ${bpsStr(revRate)}`;
  else title = `${labels.fwd === 'Receiving' ? 'Receive' : 'Send'} speed: ${bpsStr(rate)}`;
  if (partial) title += ' (partial)';

  let text = '';
  const udpTarget = (proto === 'udp' && !server && o.bitrate) ? parseSize(o.bitrate) : null;
  if (udpTarget && rate != null) {
    // A UDP test runs at a fixed rate, so judge it against the target rather than link tiers.
    if (rate < udpTarget * 0.9) { level = worst(level, 'warn'); text = `You asked for ${bpsStr(udpTarget)} but only ${bpsStr(rate)} arrived, so the network could not sustain that rate.`; }
    else text = `The ${bpsStr(udpTarget)} target was delivered in full. Loss and jitter below tell you how cleanly it arrived.`;
    if (revRate != null) text += ` In the other direction ${bpsStr(revRate)} arrived.`;
  } else if (rate != null) {
    const rn = rateNote(rate); level = worst(level, rn.level); text = rn.text;
    if (revRate != null) { const r2 = rateNote(revRate); level = worst(level, r2.level); text += ` In the other direction: ${r2.text.charAt(0).toLowerCase()}${r2.text.slice(1)}`; }
  }
  if (partial) notes.push(run.stopped ? 'The test was stopped early, so these are averages of what was measured so far.' : `The test ended early${run.error ? ': ' + run.error.friendly : ''}. Figures are averages of what was measured.`);

  // TCP retransmits
  const sentBlock = s.sent || {};
  if (proto === 'tcp' && sentBlock.retransmits != null) {
    const retr = sentBlock.retransmits; const bytes = sentBlock.bytes || (s.received || {}).bytes || 0;
    const mss = (s.start && s.start.tcpMss) || 1448; const segs = Math.max(1, bytes / mss); const ratio = retr / segs;
    if (retr === 0) notes.push('No retransmissions: nothing had to be sent twice, which is what a clean connection looks like.');
    else if (ratio < 0.0005) notes.push(retr === 1 ? 'One retransmission, which is nothing to worry about.' : `${retr} retransmissions, a normal amount for this much data.`);
    else if (ratio < 0.005) { level = worst(level, 'warn'); notes.push(`${retr} retransmissions (about ${(ratio * 100).toFixed(2)}% of the data). That hints at mild congestion or a weak link.`); }
    else { level = worst(level, 'bad'); notes.push(`${retr} retransmissions (about ${(ratio * 100).toFixed(1)}% of the data). The link is dropping data; check cables, Wi‑Fi signal or an overloaded switch.`); }
  }
  // UDP quality
  const udpBlocks = [[s.udp, labels.fwd], [s.reverse && s.reverse.udp, labels.rev]].filter(x => x[0]);
  for (const [u, lbl] of udpBlocks) {
    const pfx = udpBlocks.length > 1 ? lbl + ': ' : '';
    const lp = u.lostPct != null ? +u.lostPct : (u.packets ? (u.lost || 0) / u.packets * 100 : null);
    if (lp != null) {
      if (lp === 0) notes.push(`${pfx}No packets were lost.`);
      else if (lp < 0.1) notes.push(`${pfx}Packet loss ${fmtPct(lp)}, negligible.`);
      else if (lp < 1) { level = worst(level, 'info'); notes.push(`${pfx}Packet loss ${fmtPct(lp)}. Acceptable for calls and video, but worth watching.`); }
      else if (lp < 5) { level = worst(level, 'warn'); notes.push(`${pfx}Packet loss ${fmtPct(lp)}. Calls and video will stutter at this rate.`); }
      else { level = worst(level, 'bad'); notes.push(`${pfx}Packet loss ${fmtPct(lp)}. The network cannot carry this much traffic reliably; try a lower target speed to find what it can.`); }
    }
    if (u.jitter_ms != null) {
      const j = +u.jitter_ms;
      if (j < 5) notes.push(`${pfx}Jitter ${fmtMs(j)}: very steady timing.`);
      else if (j < 30) notes.push(`${pfx}Jitter ${fmtMs(j)}: fine for voice and video.`);
      else if (j < 60) { level = worst(level, 'warn'); notes.push(`${pfx}Jitter ${fmtMs(j)}: calls may sound choppy.`); }
      else { level = worst(level, 'bad'); notes.push(`${pfx}Jitter ${fmtMs(j)}: too uneven for real-time audio or video.`); }
    }
  }
  // steadiness
  const ivs = run.intervals.filter(i => !i.omitted && i.bps != null);
  if (ivs.length >= 4) {
    const vals = ivs.map(i => i.bps); const mean = vals.reduce((a, b) => a + b, 0) / vals.length;
    const sd = Math.sqrt(vals.reduce((a, b) => a + (b - mean) ** 2, 0) / vals.length); const cv = mean ? sd / mean : 0;
    const mn = Math.min(...vals), mx = Math.max(...vals);
    if (cv > 0.35) { level = worst(level, 'warn'); notes.push(`Speed swung between ${bpsStr(mn)} and ${bpsStr(mx)} during the test, which usually points to Wi‑Fi interference or other traffic.`); }
    else if (cv > 0.15) notes.push(`Speed varied moderately (${bpsStr(mn)} to ${bpsStr(mx)}).`);
    else notes.push('Speed was steady throughout the test.');
  }
  if (s.cpu && (s.cpu.local > 85 || s.cpu.remote > 85)) { level = worst(level, 'info'); notes.push(`A computer was working hard (${s.cpu.local > 85 ? 'this one' : 'the other one'} at ${Math.round(Math.max(s.cpu.local || 0, s.cpu.remote || 0))}% CPU), which can cap the result below what the network allows.`); }

  // tiles
  const tiles = [];
  if (s.sent && s.sent.bps != null) tiles.push(tile(server ? 'Sent by this side' : 'Sent', bpsStr(s.sent.bps)));
  if (s.received && s.received.bps != null) tiles.push(tile(server ? 'Received by this side' : 'Arrived at the other end', bpsStr(s.received.bps)));
  if (s.reverse) {
    if (s.reverse.sent && s.reverse.sent.bps != null) tiles.push(tile('Reverse: sent', bpsStr(s.reverse.sent.bps)));
    if (s.reverse.received && s.reverse.received.bps != null) tiles.push(tile('Reverse: arrived', bpsStr(s.reverse.received.bps)));
  }
  const bytes = (s.received && s.received.bytes) || (s.sent && s.sent.bytes);
  if (bytes) tiles.push(tile('Data moved', fmtBytes(bytes)));
  if (sentBlock.retransmits != null) tiles.push(tile('Retransmits', sentBlock.retransmits, sentBlock.retransmits === 0 ? 'good' : ''));
  if (s.udp) {
    tiles.push(tile('Jitter', fmtMs(s.udp.jitter_ms)));
    const lp = s.udp.lostPct != null ? +s.udp.lostPct : (s.udp.packets ? (s.udp.lost || 0) / s.udp.packets * 100 : null);
    tiles.push(tile('Packet loss', `${fmtPct(lp)}<small>${s.udp.lost ?? 0} of ${s.udp.packets ?? '?'}</small>`, lp === 0 ? 'good' : lp > 1 ? 'bad' : ''));
  }
  if (s.cpu && s.cpu.local != null) tiles.push(tile('CPU here / there', `${Math.round(s.cpu.local)}%<small>/ ${s.cpu.remote != null ? Math.round(s.cpu.remote) + '%' : '?'}</small>`));
  const streams = (s.start && s.start.streams) || (o.parallel > 1 ? o.parallel : null);
  if (streams && streams > 1) tiles.push(tile('Connections', streams));
  return { level, title, text, notes, tiles, summary: s };
}
function parseSize(v) {
  const m = String(v || '').trim().match(/^(\d+(?:\.\d+)?)\s*([kKmMgGtT])?/);
  if (!m) return null;
  return parseFloat(m[1]) * ({ '': 1, K: 1e3, M: 1e6, G: 1e9, T: 1e12 }[(m[2] || '').toUpperCase()]);
}

function showResult(run) {
  const a = analyse(run);
  const icon = $('#verdictIcon');
  icon.textContent = a.level === 'good' ? '✓' : a.level === 'bad' ? '!' : a.level === 'warn' ? '!' : 'i';
  icon.className = 'verdict-icon ' + (a.level === 'good' ? '' : a.level);
  $('#verdictTitle').textContent = a.title;
  $('#verdictText').textContent = a.text;
  $('#resultTiles').innerHTML = a.tiles.join('');
  $('#resultNotes').innerHTML = a.notes.length ? '<ul>' + a.notes.map(n => `<li>${esc(n)}</li>`).join('') + '</ul>' : '';
  $('#rawLog').textContent = run.log.join('\n');
  $('#resultPanel').classList.remove('hidden');
  $('#btnCsv').disabled = !run.intervals.length;
  run.analysis = a;
}

/* Server-mode result list ---------------------------------------------------*/
function renderServerResults() {
  const box = $('#serverResults');
  if (!S.serverResults.length) { box.innerHTML = '<p class="hint">No tests yet. When another computer runs a test against this one, it shows up here.</p>'; return; }
  box.innerHTML = S.serverResults.map(r => {
    const fake = { opts: { mode: 'server' }, summary: r.summary, intervals: r.intervals, start: r.summary.start, log: [] };
    const a = analyse(fake);
    return `<div class="item"><div><div class="m">${esc(a.title)}</div><div class="t">${esc(fmtWhen(r.ts))} · ${esc(a.notes[0] || a.text)}</div></div><div class="r">${bpsStr(mainRate(r.summary))}</div></div>`;
  }).join('');
}

/* ------------------------------------------------------------------------ */
/* History                                                                   */
/* ------------------------------------------------------------------------ */
async function refreshHistory() {
  const r = await api('/api/history');
  if (r.history) { S.history = r.history; renderHistory(); }
}
function describe(h) {
  const o = h.opts || {};
  if (o.mode === 'server') {
    const from = (h.summary && h.summary.start && h.summary.start.host) || 'another computer';
    return `Received a test from ${from}`;
  }
  const proto = o.protocol === 'udp' ? 'Quality (UDP)' : 'Speed (TCP)';
  const dir = o.direction === 'download' ? 'Receive from' : o.direction === 'both' ? 'Both directions with' : 'Send to';
  return `${dir} ${o.host || '?'} · ${proto}${+o.parallel > 1 ? ` · ${o.parallel} connections` : ''}`;
}
function renderHistory() {
  const box = $('#historyList');
  if (!S.history.length) { box.innerHTML = '<p class="hint">Results are kept here so you can compare over time.</p>'; return; }
  box.innerHTML = S.history.slice(0, 50).map(h => {
    const s = h.summary || {}; const rate = mainRate(s); const rev = s.reverse ? mainRate(s.reverse) : null;
    const main = h.label ? esc(h.label) : esc(describe(h));
    const sub = esc(fmtWhen(h.ts)) + (h.label ? ' · ' + esc(describe(h)) : (h.opts && h.opts.title ? ' · ' + esc(h.opts.title) : ''));
    return `<div class="item" data-id="${esc(h.id)}"><div><div class="m">${main}</div><div class="t">${sub}</div></div>` +
      `<div class="r">${bpsStr(rate)}${rev != null ? `<small>↓ ${bpsStr(rev)}</small>` : ''}</div></div>`;
  }).join('');
  $$('.item', box).forEach(el => el.onclick = () => openHistory(el.dataset.id));
}
function openHistory(id) {
  const h = S.history.find(x => x.id === id); if (!h) return;
  S.viewing = h;
  const run = { opts: h.opts || {}, summary: h.summary, intervals: h.intervals || [], start: h.summary && h.summary.start, log: [], cmd: h.cmd };
  const a = analyse(run);
  $('#histTitle').textContent = h.label || describe(h);
  $('#histName').value = h.label || '';
  const kv = [['When', fmtWhen(h.ts)], ['Test', describe(h)], ['Result', a.title], ['Verdict', a.text], ['iperf3', h.iperfVersion || '?'], ['Command', h.cmd || '']];
  $('#histBody').innerHTML = `<div class="kv">${kv.map(([k, v]) => `<div class="k">${esc(k)}</div><div>${k === 'Command' ? '<code>' + esc(v) + '</code>' : esc(v)}</div>`).join('')}</div>` +
    `<canvas id="histChart" height="180"></canvas><div class="tiles">${a.tiles.join('')}</div>` +
    (a.notes.length ? `<div class="notes"><ul>${a.notes.map(n => `<li>${esc(n)}</li>`).join('')}</ul></div>` : '');
  const dlg = $('#histDialog'); dlg.showModal();
  drawChart($('#histChart'), run.intervals, { labels: dirLabels(run) });
}

/* Exports --------------------------------------------------------------------*/
function csvFor(intervals) {
  const cols = ['start_s', 'end_s', 'bits_per_second', 'bytes', 'retransmits', 'jitter_ms', 'lost_packets', 'packets', 'lost_percent', 'reverse_bits_per_second'];
  const rows = intervals.map(i => [i.t0, i.t1, i.bps, i.bytes, i.retransmits, i.jitter_ms, i.lost_packets, i.packets, i.lost_percent, i.reverse ? i.reverse.bps : ''].map(v => v == null ? '' : v).join(','));
  return cols.join(',') + '\n' + rows.join('\n') + '\n';
}
function stamp(ts) { const d = new Date(ts ? ts * 1000 : Date.now()); return d.toISOString().slice(0, 19).replace(/[:T]/g, '-'); }
function fileBase(h) { const slug = (h.label || '').replace(/[^A-Za-z0-9 _-]/g, '').trim().replace(/\s+/g, '-').slice(0, 40); return 'LinkTest-' + (slug ? slug + '-' : '') + stamp(h.ts); }
async function renameViewing() {
  if (!S.viewing) return;
  const label = $('#histName').value.trim();
  const r = await api('/api/history/rename', { id: S.viewing.id, label });
  if (r.error) { toast(r.error); return; }
  S.viewing.label = label || undefined;
  const h = S.history.find(x => x.id === S.viewing.id); if (h) { if (label) h.label = label; else delete h.label; }
  $('#histTitle').textContent = label || describe(S.viewing);
  renderHistory(); toast(label ? 'Name saved' : 'Name cleared');
}
function summaryText(run) {
  const a = run.analysis || analyse(run); const o = run.opts || {};
  const lines = [`LinkTest result - ${new Date().toLocaleString()}`, o.mode === 'server' ? 'Mode: test target' : `Test against ${o.host} (${DIR_WORD[o.direction] || 'Send'}, ${o.protocol === 'udp' ? 'UDP' : 'TCP'}, ${o.duration || '?'} s${+o.parallel > 1 ? ', ' + o.parallel + ' connections' : ''})`, '', a.title, a.text, ...a.notes.map(n => '- ' + n)];
  if (run.cmd) lines.push('', 'Command: ' + run.cmd);
  return lines.join('\n');
}
function fullReport(run) {
  return JSON.stringify({ app: 'LinkTest', version: S.status && S.status.app.version, when: new Date().toISOString(), opts: run.opts, cmd: run.cmd, summary: run.summary, intervals: run.intervals, analysis: run.analysis || analyse(run), log: run.log }, null, 1);
}

/* ------------------------------------------------------------------------ */
/* Wiring                                                                    */
/* ------------------------------------------------------------------------ */
function wire() {
  $$('input[name=mode]').forEach(r => r.onchange = () => { if (!S.running) setMode(r.value); });
  ['direction', 'protocol'].forEach(id => $$(`#${id} button`).forEach(b => b.onclick = () => {
    if (b.disabled) return; setSeg(id, b.dataset.v); refreshProtoUI(); clearPreset(); schedulePreview();
  }));
  $$('#presets .chip').forEach(c => c.onclick = () => applyPreset(c.dataset.preset));
  $$('.mini-chips button').forEach(b => b.onclick = () => { setVal('duration', b.dataset.d); clearPreset(); schedulePreview(); });
  $$('#clientForm input, #clientForm select, #serverForm input, #serverForm select').forEach(el => {
    el.addEventListener('input', () => { clearPreset(); schedulePreview(); });
    el.addEventListener('change', schedulePreview);
  });
  $('#host').addEventListener('keydown', e => { if (e.key === 'Enter' && !S.running) startTest(); });
  $('#btnStart').onclick = () => S.running ? stopTest() : startTest();
  $('#btnAgain').onclick = () => { if (!S.running) startTest(); };
  $('#btnCopyCmd').onclick = () => copyText($('#cmdLine').textContent, 'Command copied');
  $('#btnCopySummary').onclick = () => S.run && copyText(summaryText(S.run), 'Summary copied');
  $('#btnCsv').onclick = () => S.run && download(`LinkTest-${stamp()}.csv`, csvFor(S.run.intervals), 'text/csv');
  $('#btnJson').onclick = () => S.run && download(`LinkTest-${stamp()}.json`, fullReport(S.run), 'application/json');
  $('#btnClearHistory').onclick = async () => { if (S.history.length && confirm('Delete all past tests?')) { await api('/api/history/clear', {}); refreshHistory(); } };
  $('#histClose').onclick = () => $('#histDialog').close();
  $('#histDelete').onclick = async () => { if (S.viewing) { await api('/api/history/delete', { id: S.viewing.id }); $('#histDialog').close(); refreshHistory(); } };
  $('#histCsv').onclick = () => S.viewing && download(`${fileBase(S.viewing)}.csv`, csvFor(S.viewing.intervals || []), 'text/csv');
  $('#histJson').onclick = () => S.viewing && download(`${fileBase(S.viewing)}.json`, JSON.stringify(S.viewing, null, 1), 'application/json');
  $('#histSave').onclick = renameViewing;
  $('#histName').addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); renameViewing(); } });
  $('#histRerun').onclick = () => { if (S.viewing && !S.running) { applyOpts(S.viewing.opts); $('#histDialog').close(); window.scrollTo({ top: 0, behavior: 'smooth' }); startTest(); } };
  $('#btnAbout').onclick = () => $('#aboutDialog').showModal();
  $('#aboutClose').onclick = () => $('#aboutDialog').close();
  $$('dialog').forEach(d => d.addEventListener('click', e => { if (e.target === d) d.close(); }));
  $('#btnUsePath').onclick = async () => {
    const r = await api('/api/iperf/path', { path: V('iperfPathInput') });
    const err = $('#pathError');
    if (r.error) { err.textContent = r.error; err.classList.remove('hidden'); return; }
    err.classList.add('hidden'); toast('iperf3 is ready'); refreshStatus();
  };
  $('#btnFirewall').onclick = async () => {
    const st = $('#fwStatus'); const man = $('#fwManual'); const cp = $('#fwCopy');
    S.fwTouched = true;
    st.textContent = 'Waiting for permission…'; $('#btnFirewall').disabled = true;
    man.classList.add('hidden'); cp.classList.add('hidden');
    const r = await api('/api/firewall', { port: V('sport') || 5201 });
    $('#btnFirewall').disabled = false;
    if (r.error) { st.textContent = `Not done: ${r.error}`; return; }
    const res = r.result || {};
    st.textContent = res.message || (res.status === 'added' ? 'Done. Other computers can now reach this one.' : res.status);
    if (res.status === 'manual' && res.commands && res.commands.length) {
      man.textContent = res.commands.join('\n'); man.classList.remove('hidden');
      cp.classList.remove('hidden'); cp.onclick = () => copyText(res.commands.join('\n'), 'Commands copied');
    }
  };
  window.addEventListener('resize', () => S.run && drawChart($('#chart'), S.run.intervals, { labels: dirLabels(S.run) }));
}
function clearPreset() { $$('#presets .chip').forEach(c => c.classList.remove('on')); }

async function init() {
  wire();
  await refreshStatus();
  const st = await api('/api/settings');
  S.settings = st.settings || {};
  renderPublicServers();
  // Public servers picked before 0.7.1 may still sit in Recent; drop them once.
  const recentAll = S.settings.recentHosts || [];
  const recentOwn = recentAll.filter(h => !isPublicServer(h));
  if (recentOwn.length !== recentAll.length) { S.settings.recentHosts = recentOwn; api('/api/settings', { patch: { recentHosts: recentOwn } }); }
  renderRecentHosts(recentOwn);
  if (S.settings.lastOpts && !S.running) applyOpts(S.settings.lastOpts); else setMode(S.mode);
  refreshHistory();
  schedulePreview();
  setInterval(pollEvents, 400);
  setInterval(refreshStatus, 6000);
  setInterval(() => api('/api/heartbeat', {}), 2000);
  api('/api/heartbeat', {});
}
init();
