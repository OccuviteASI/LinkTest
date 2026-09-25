'use strict';
/* LinkTest network tools: tabs, Scan network, Ping monitor + traceroute, DNS lookup.
   Relies on helpers defined in app.js ($, $$, api, toast, copyText, download, esc, fmtMs, tile, roundRect). */

const T = { tab: 'speed', settings: {}, net: null };

/* ------------------------------------------------------------------------ */
/* Tabs                                                                     */
/* ------------------------------------------------------------------------ */
function showTab(name, persist = true) {
  if (!$(`#tab-${name}`)) name = 'speed';
  T.tab = name;
  $$('.tab').forEach(s => s.classList.toggle('hidden', s.id !== `tab-${name}`));
  $$('#tabs button').forEach(b => b.classList.toggle('on', b.dataset.tab === name));
  if (persist) api('/api/settings', { patch: { lastTab: name } });
  if (name === 'scan') { scanEnsureNet(); scanRehydrate(); if (!AR.loaded) arpLoad(); }
  if (name === 'dns') dnsEnsureServers();
  if (name === 'pings') pmRenderAll();
  if (name === 'capture') { pcEnsureInterfaces(); pcRehydrate(); }
  if (name === 'wifi') wfEnsure(); else if (T.prevTab === 'wifi') wfLeave();
  T.prevTab = name;
  $('#enginePill').classList.toggle('hidden', name !== 'speed');
}

/* ------------------------------------------------------------------------ */
/* Scan network                                                             */
/* ------------------------------------------------------------------------ */
const SC = { hosts: new Map(), seq: 0, running: false, intercepted: [], presets: {}, dupMacs: {}, sortKey: 'ip', sortAsc: true, portNames: {}, defaults: [],
  total: 0, done: 0, alive: 0, timer: null, netLoaded: false, estimate: 0 };

async function scanEnsureNet(force) {
  if (SC.netLoaded && !force) return;
  const r = await api('/api/net/info' + (force ? '?refresh=1' : ''));
  if (r.error) return;
  SC.netLoaded = true; T.net = r;
  SC.portNames = r.portNames || {}; SC.defaults = (r.defaultPorts || []).map(p => p.port); SC.presets = r.portPresets || {};
  const range = $('#scanRange');
  if (!range.value.trim()) range.value = T.settings.scanRange || r.default.range;
  const nets = (r.interfaces || []).filter(i => i.network);
  $('#scanNets').innerHTML = nets.map(i => `<option value="${esc(i.network)}" ${i.primary ? 'selected' : ''}>${esc(i.name)} – ${esc(i.network)}${i.narrowed ? ` (part of ${esc(i.fullNetwork)})` : ''}</option>`).join('') || '<option value="">No network found</option>';
  const iface = r.default.interface;
  $('#scanRangeHint').textContent = (r.default.note ? r.default.note + ' ' : '') +
    (iface ? `This computer is ${iface.ip} on ${iface.name}${iface.gateway ? `, gateway ${iface.gateway}` : ''}.` : '');
  const ports = $('#scanPorts');
  if (!ports.value.trim()) ports.value = (T.settings.scanPorts && T.settings.scanPorts.length ? T.settings.scanPorts : SC.defaults).join(', ');
  const o = T.settings.scanOpts || {};
  if (o.timeoutMs) $('#scanTimeout').value = o.timeoutMs;
  if (o.retries != null) $('#scanRetries').value = o.retries;
  if (o.resolveNames != null) $('#scanNames').checked = !!o.resolveNames;
  if (o.portsOnSilent != null) $('#scanSilent').checked = !!o.portsOnSilent;
  if (r.pinger === 'ping-cli') $('#scanRangeHint').textContent += ' Pings use the system ping tool on this computer, so scans are slower than usual.';
  scanPresetReflect();
}
/* Port presets ------------------------------------------------------------*/
function scanParsePortsText(t) {
  const out = new Set();
  for (const part of (t || '').split(/[\s,;]+/)) {
    if (!part) continue;
    const m = /^(\d+)-(\d+)$/.exec(part);
    if (m) { for (let p = +m[1]; p <= +m[2] && p <= 65535; p++) out.add(p); } else if (/^\d+$/.test(part)) out.add(+part);
  }
  return [...out].sort((a, b) => a - b);
}
function scanPresetReflect() {
  const cur = scanParsePortsText($('#scanPorts').value).join(',');
  let which = 'custom';
  for (const [k, p] of Object.entries(SC.presets || {})) if ((p.ports || []).join(',') === cur) which = k;
  $$('#portPresets button').forEach(b => b.classList.toggle('on', b.dataset.p === which));
  const n = cur ? cur.split(',').length : 0;
  $('#portPresetHint').textContent = which !== 'custom' ? `${n} ports` : n ? `custom list · ${n} port${n === 1 ? '' : 's'}` : 'type ports or ranges, e.g. 22, 80, 8000-8010';
  const warn = $('#portWarn');
  if (n > 200) {
    warn.textContent = `Checking ${n} ports on every device takes much longer: expect several minutes on a full network (the estimate appears when you press Scan). Basic or Standard is enough to see what a device is.`;
    warn.classList.remove('hidden');
  } else warn.classList.add('hidden');
  scanSettingsSum();
}
function scanApplyPreset(k) {
  if (k === 'custom') { $('#scanPorts').value = ''; scanPresetReflect(); $('#scanPorts').focus(); return; }
  const p = (SC.presets || {})[k]; if (!p) return;
  $('#scanPorts').value = p.text; scanPresetReflect();
}
function scanSettingsSum() {
  const el = $('#scanSettingsSum'); if (!el) return;
  const n = scanParsePortsText($('#scanPorts').value).length;
  el.textContent = `${$('#scanRange').value.trim() || 'no range'} · ${n} port${n === 1 ? '' : 's'}${SC.hosts.size ? ` · last scan: ${SC.alive} device${SC.alive === 1 ? '' : 's'}` : ''}`;
}
/* Collapsible cards -----------------------------------------------------------*/
function wireCollapsibles() {
  $$('[data-collapse]').forEach(card => {
    const head = card.querySelector(':scope > .row'); if (!head) return;
    const b = document.createElement('button'); b.className = 'chev'; b.title = 'Collapse or expand'; b.textContent = '▾';
    head.appendChild(b);
    const toggle = () => {
      const on = !card.classList.contains('collapsed');
      card.classList.toggle('collapsed', on); b.textContent = on ? '▸' : '▾';
      T.settings.collapsed = Object.assign({}, T.settings.collapsed, { [card.dataset.collapse]: on });
      api('/api/settings', { patch: { collapsed: T.settings.collapsed } });
    };
    b.onclick = ev => { ev.stopPropagation(); toggle(); };
    const h2 = head.querySelector('h2'); if (h2) { h2.style.cursor = 'pointer'; h2.onclick = toggle; }
  });
}
function applyCollapsed() {
  const c = T.settings.collapsed || {};
  $$('[data-collapse]').forEach(card => { const on = !!c[card.dataset.collapse]; card.classList.toggle('collapsed', on); const b = card.querySelector(':scope > .row > .chev'); if (b) b.textContent = on ? '▸' : '▾'; });
}

async function scanRehydrate() {
  const st = await api('/api/scan/state');
  if (st.error) return;
  SC.hosts.clear();
  (st.hosts || []).forEach(h => SC.hosts.set(h.ip, h));
  SC.seq = st.seq || 0; SC.total = st.total; SC.done = st.done; SC.alive = st.alive; SC.intercepted = st.intercepted || []; SC.dupMacs = st.dupMacs || {};
  scanSetRunning(!!st.running);
  if (st.running) scanStartPolling();
  scanRender(); scanProgress();
}

function scanSetRunning(on) {
  SC.running = on;
  const b = $('#scanStart');
  b.textContent = on ? 'Stop scan' : 'Scan'; b.classList.toggle('stop', on);
  $('#scanProgress').classList.toggle('hidden', !on && !SC.total);
}

async function scanStart() {
  const err = $('#scanError'); err.classList.add('hidden');
  const opts = { range: $('#scanRange').value.trim(), ports: $('#scanPorts').value.trim(), timeoutMs: +$('#scanTimeout').value || 1000,
    retries: +$('#scanRetries').value || 0, resolveNames: $('#scanNames').checked, portsOnSilent: $('#scanSilent').checked };
  const r = await api('/api/scan/start', opts);
  if (r.error) { err.textContent = r.error; err.classList.remove('hidden'); return; }
  SC.hosts.clear(); SC.seq = 0; SC.total = r.total; SC.done = 0; SC.alive = 0; SC.estimate = r.estimateS; SC.dupMacs = {};
  if (r.estimateS > 90) toast(`This scan will take about ${Math.round(r.estimateS / 60)} minutes`);
  scanSetRunning(true); scanRender(); scanProgress(); scanStartPolling();
}
async function scanStop() { await api('/api/scan/stop', {}); }

function scanStartPolling() {
  if (SC.timer) return;
  SC.timer = setInterval(scanPoll, 500); scanPoll();
}
async function scanPoll() {
  const r = await api(`/api/scan/events?since=${SC.seq}`);
  if (r.error || !r.events) return;
  if (r.events.some(e => e.type === 'done')) setTimeout(arpLoad, 500); // a scan fills the ARP table
  let changed = false;
  for (const e of r.events) {
    SC.seq = e.seq;
    switch (e.type) {
      case 'start': SC.total = e.total; SC.estimate = e.estimateS; SC.intercepted = []; scanNote(); break;
      case 'intercept': SC.intercepted = e.ports || []; scanNote(); changed = true; break;
      case 'host': SC.hosts.set(e.ip, Object.assign(SC.hosts.get(e.ip) || { ports: [] }, { ip: e.ip, n: e.n, alive: e.alive, rtt: e.rtt, status: e.status })); changed = true; break;
      case 'detail': Object.assign(SC.hosts.get(e.ip) || SC.hosts.set(e.ip, { ip: e.ip, n: 1e9 }).get(e.ip), { alive: e.alive, status: e.status, ports: e.ports, hostname: e.hostname, interceptedPorts: e.interceptedPorts || [], phantom: !!e.phantom, refused: !!e.refused }); changed = true; break;
      case 'progress': SC.done = e.done; SC.alive = e.alive; break;
      case 'arp': for (const [ip, m] of Object.entries(e.hosts || {})) { const h = SC.hosts.get(ip); if (h) { h.mac = m.mac; h.vendor = m.vendor; if (!h.alive) { h.alive = true; h.status = 'arp'; } changed = true; } } SC.dupMacs = e.dupMacs || {}; break;
      case 'done': SC.done = e.done; SC.alive = e.alive; scanSetRunning(false); clearInterval(SC.timer); SC.timer = null;
        SC.dupMacs = e.dupMacs || SC.dupMacs;
        { const nd = Object.keys(SC.dupMacs || {}).length;
          toast((e.cancelled ? `Scan stopped: ${e.alive} device${e.alive === 1 ? '' : 's'} found so far` : `Scan finished in ${e.elapsed}s: ${e.alive} device${e.alive === 1 ? '' : 's'} found`) + (nd ? ` · ${nd} duplicate MAC${nd === 1 ? '' : 's'}` : '')); }
        changed = true; break;
    }
  }
  if (!r.running && SC.running) { scanSetRunning(false); clearInterval(SC.timer); SC.timer = null; }
  if (changed) scanRender();
  scanProgress();
}
function scanDupWarn() {
  const el = $('#scanWarn'); const d = SC.dupMacs || {}; const macs = Object.keys(d);
  if (!macs.length) { el.classList.add('hidden'); el.innerHTML = ''; return; }
  el.innerHTML = '<b>Duplicate hardware addresses</b><ul>' + macs.map(m => {
    const ips = d[m]; const v = (SC.hosts.get(ips[0]) || {}).vendor;
    return `<li>⚠ <span class="mono">${esc(m)}</span>${v ? ` (${esc(v)})` : ''} answers for ${esc(ips.join(', '))}. Usually one device with several addresses (a router or a server); if that is unexpected it can be an IP conflict or a spoofed address.</li>`;
  }).join('') + '</ul>';
  el.classList.remove('hidden');
}
function scanNote() {
  const el = $('#scanNote'); const ps = SC.intercepted || [];
  if (!ps.length) { el.classList.add('hidden'); el.textContent = ''; return; }
  const names = ps.map(p => `${p}${SC.portNames[p] ? ' (' + SC.portNames[p] + ')' : ''}`).join(', ');
  el.textContent = `Port ${names} answers on every address in this range: the network (usually the gateway) intercepts it, so it is not proof that a device exists. Addresses that only answered there are treated as empty and hidden by "Only devices that answered"; on real devices that port is shown crossed out.`;
  el.classList.remove('hidden');
}
function scanProgress() {
  const p = $('#scanProgress');
  if (!SC.total) { p.classList.add('hidden'); return; }
  p.classList.remove('hidden');
  const pct = Math.round(SC.done / SC.total * 100);
  $('.bar', p).style.width = pct + '%';
  $('.msg', p).textContent = SC.running ? `Checked ${SC.done} of ${SC.total} addresses · ${SC.alive} answering${SC.estimate ? ` · about ${Math.round(SC.estimate)} s in total` : ''}` : `Checked ${SC.done} of ${SC.total} addresses · ${SC.alive} answering`;
}
const ipNum = ip => (ip || '').split('.').reduce((a, b) => a * 256 + (+b || 0), 0);
function scanRender() {
  const tb = $('#scanTable tbody'); const onlyAlive = $('#scanAliveOnly').checked;
  let rows = [...SC.hosts.values()];
  if (onlyAlive) rows = rows.filter(h => h.alive);
  const k = SC.sortKey, dir = SC.sortAsc ? 1 : -1;
  rows.sort((a, b) => {
    let va, vb;
    if (k === 'ip') { va = ipNum(a.ip); vb = ipNum(b.ip); }
    else if (k === 'rtt') { va = a.rtt ?? 1e9; vb = b.rtt ?? 1e9; }
    else if (k === 'ports') { va = (a.ports || []).length; vb = (b.ports || []).length; }
    else { va = (a[k] || '').toLowerCase(); vb = (b[k] || '').toLowerCase(); if (!va && vb) return 1; if (va && !vb) return -1; }
    return va < vb ? -dir : va > vb ? dir : ipNum(a.ip) - ipNum(b.ip);
  });
  $$('#scanTable th').forEach(th => { th.classList.toggle('sorted', th.dataset.k === k); th.classList.toggle('asc', th.dataset.k === k && SC.sortAsc); });
  tb.innerHTML = rows.map(h => {
    const ports = (h.ports || []).map(p => { const ic = (SC.intercepted || []).includes(p); return `<span class="chip port ${ic ? 'intercepted' : ''}" ${ic ? 'title="Answered by the network (intercepted), not necessarily by this device"' : ''}>${p}${SC.portNames[p] ? `<small>${esc(SC.portNames[p])}</small>` : ''}</span>`; }).join('');
    const ping = h.rtt != null ? fmtMs(h.rtt) : (h.status === 'tcp' ? 'ports only' : h.status === 'arp' ? 'seen (ARP)' : h.status === 'refused' ? 'no ping, but refused a connection' : h.status === 'intercepted' ? 'only intercepted port(s)' : h.alive ? '' : 'no answer');
    const dupIps = h.mac && SC.dupMacs[(h.mac || '').toUpperCase()] ? SC.dupMacs[h.mac.toUpperCase()].filter(x => x !== h.ip) : [];
    return `<tr class="${h.alive ? '' : 'dim'} ${dupIps.length ? 'dup' : ''}" data-ip="${esc(h.ip)}"><td class="mono">${esc(h.ip)}${h.ip === (T.net && T.net.default.interface && T.net.default.interface.ip) ? '<span class="sub">this computer</span>' : ''}</td>` +
      `<td>${esc(h.hostname || '')}</td><td>${esc(h.vendor || '')}${h.mac ? `<span class="sub mono">${esc(h.mac)}</span>` : ''}${dupIps.length ? `<span class="badge warn" title="The same hardware address answers for ${esc(dupIps.join(', '))}">⚠ also ${esc(dupIps.slice(0, 2).join(', '))}${dupIps.length > 2 ? ` +${dupIps.length - 2}` : ''}</span>` : ''}</td>` +
      `<td>${esc(ping)}</td><td>${ports || (h.alive ? '<span class="hint">none of the checked ports</span>' : '')}</td>` +
      `<td class="rowbtns"><button class="btn small" data-act="watch" title="Add to Ping monitor">Watch</button><button class="btn small" data-act="arp" title="Hardware address details">ARP</button><button class="btn small" data-act="dns" title="Reverse DNS lookup">DNS</button></td></tr>`;
  }).join('');
  $('#scanEmpty').classList.toggle('hidden', rows.length > 0 || SC.running);
  scanNote(); scanDupWarn(); scanSettingsSum();
  $('#scanTitle').textContent = SC.hosts.size ? `Devices (${SC.alive} answering of ${SC.total || SC.hosts.size} checked)` : 'Devices';
  $('#scanSummary').textContent = rows.length === 0 && SC.hosts.size && onlyAlive ? 'No device has answered yet. Untick "Only devices that answered" to see every address.' : '';
}

/* ARP / MAC tools ------------------------------------------------------------*/
const AR = { rows: [], conflicts: [], loaded: false, cmds: {}, isAdmin: false };
const MAC_KIND_WORDS = { global: 'factory', private: 'private / randomised', multicast: 'group', broadcast: 'everyone', invalid: '?' };
async function arpLoad() {
  const r = await api('/api/arp');
  if (r.error) { toast(r.error); return; }
  AR.rows = r.rows || []; AR.conflicts = r.conflicts || []; AR.loaded = true; AR.cmds = r.commands || AR.cmds; AR.isAdmin = !!r.isAdmin;
  arpRender(); arpRenderCmds();
}
function arpCmdText(action) {
  const t = AR.cmds[action] || ''; const ip = action === 'delete' ? $('#arpDelIp').value.trim() : $('#arpAddIp').value.trim();
  const mac = $('#arpAddMac').value.trim().replace(/[^0-9a-fA-F]/g, '').replace(/(..)(?=.)/g, '$1-').toLowerCase();
  return t.replace('{ip}', ip || '<ip>').replace('{mac}', mac.length === 17 ? mac : '<mac>').replace('{dev}', '<connection>');
}
function arpRenderCmds() {
  $$('#arpCard code[data-c]').forEach(c => c.textContent = arpCmdText(c.dataset.c));
  if (AR.isAdmin) $$('#arpCard [data-cmd] small').forEach(sm => sm.remove());
}
async function arpRunCmd(action) {
  const out = $('#arpOut'), hint = $('#arpOutHint');
  const ip = action === 'delete' ? $('#arpDelIp').value : $('#arpAddIp').value;
  const btn = $(`#arpCard [data-cmd="${action}"]`); btn.disabled = true;
  hint.textContent = ['flush', 'delete', 'add'].includes(action) && !AR.isAdmin ? 'Waiting for the administrator prompt…' : 'Running…';
  const r = await api('/api/arp/cmd', { action, ip, mac: $('#arpAddMac').value });
  btn.disabled = false;
  if (r.error) { hint.textContent = r.error; out.classList.add('hidden'); $('#arpOutCopy').classList.add('hidden'); toast(r.error); return; }
  hint.textContent = `$ ${r.cmd}` + (r.status === 'manual' ? ' (needs a terminal)' : '');
  out.textContent = r.output || '(no output)'; out.classList.remove('hidden'); $('#arpOutCopy').classList.remove('hidden');
  if (['flush', 'delete', 'add'].includes(action)) setTimeout(arpLoad, 400);
}
function arpRender() {
  const f = $('#arpFilter').value.trim().toLowerCase();
  const rows = AR.rows.filter(r => !f || [r.ip, r.mac, r.vendor, r.iface, r.hostname].some(v => (v || '').toLowerCase().includes(f)));
  // Which MACs / IPs are involved in a conflict (same MAC on several IPs, or one IP seen with two MACs)?
  const dupMac = {}, dupIp = new Set();
  for (const c of AR.conflicts) { if (c.kind === 'mac') dupMac[c.mac.toUpperCase()] = c.ips; else if (c.kind === 'ip') dupIp.add(c.ip); }
  $('#arpTable tbody').innerHTML = rows.map(r => {
    const others = (dupMac[(r.mac || '').toUpperCase()] || []).filter(ip => ip !== r.ip);
    const flag = others.length || dupIp.has(r.ip);
    const badge = others.length ? `<span class="badge warn" title="The same hardware address answers for ${esc(others.join(', '))}">⚠ also ${esc(others.slice(0, 2).join(', '))}${others.length > 2 ? ` +${others.length - 2}` : ''}</span>`
      : dupIp.has(r.ip) ? '<span class="badge warn" title="This address has been seen with two different hardware addresses">⚠ two MACs</span>' : '';
    return `<tr class="${flag ? 'dup' : ''}"><td class="mono">${esc(r.ip)}${r.hostname ? `<span class="sub">${esc(r.hostname)}</span>` : ''}</td><td class="mono">${esc(r.mac)}${badge}</td><td>${esc(r.vendor || '')}</td><td>${esc(MAC_KIND_WORDS[r.macKind] || r.macKind)}</td><td>${esc(r.kind)}</td><td>${esc(r.iface || '')}</td><td>${r.inScan ? 'yes' : ''}</td></tr>`;
  }).join('');
  $('#arpEmpty').classList.toggle('hidden', rows.length > 0);
  const box = $('#arpConflicts');
  if (AR.conflicts.length) {
    box.innerHTML = '<b>Duplicate hardware addresses</b><ul>' + AR.conflicts.map(c => `<li>⚠ ${esc(c.text)}</li>`).join('') + '</ul>';
    box.classList.remove('hidden');
  } else { box.innerHTML = ''; box.classList.add('hidden'); }
}
async function arpLookup() {
  const q = $('#arpQ').value.trim(); const box = $('#arpResult');
  if (!q) { $('#arpQ').focus(); return; }
  box.classList.remove('hidden'); box.innerHTML = '<span class="hint">Looking up…</span>';
  const r = await api('/api/arp/lookup', { q });
  if (r.error) { box.innerHTML = `<span class="error" style="display:block">${esc(r.error)}</span>`; return; }
  if (r.type === 'mac') {
    box.innerHTML = `<div><b class="mono">${esc(r.mac)}</b> · ${esc(r.vendor || 'maker unknown')} · <span class="hint">${esc(MAC_KIND_WORDS[r.kind] || r.kind)} address</span></div>` +
      `<div class="hint" style="margin-top:4px">${esc(r.text)}</div><div style="margin-top:6px">${esc(r.summary)}</div>` +
      (r.ips.length ? '<div class="row wrap" style="margin-top:6px">' + r.ips.map(x => `<button class="chip" data-ip="${esc(x.ip)}">${esc(x.ip)}${x.hostname ? ` · ${esc(x.hostname)}` : ''}</button>`).join('') + '</div>' : '');
    $$('#arpResult .chip').forEach(c => c.onclick = () => { $('#arpQ').value = c.dataset.ip; arpLookup(); });
  } else {
    box.innerHTML = `<div><b class="mono">${esc(r.ip)}</b>${r.hostname ? ` · ${esc(r.hostname)}` : ''}${r.own ? ' <span class="pill pill-good" style="font-size:11px">this computer</span>' : ''}</div>` +
      `<div style="margin-top:4px">${esc(r.summary)}</div>` +
      (r.mac ? `<div class="hint" style="margin-top:4px">Hardware address <span class="mono">${esc(r.mac)}</span> · ${esc(r.vendor || 'maker unknown')} · ${esc(MAC_KIND_WORDS[r.macKind] || '')}${r.iface ? ` · via ${esc(r.iface)}` : ''}${r.kind ? ` · ${esc(r.kind)} entry` : ''}</div>` : '') +
      `<div class="hint" style="margin-top:4px">${r.answersPing ? `Answers pings in ${r.rttMs} ms.` : 'Did not answer a ping.'}</div>`;
  }
  arpLoad();
}

/* ------------------------------------------------------------------------ */
/* Ping monitor (PingPlotter-style: route table + end-to-end timeline)      */
/* ------------------------------------------------------------------------ */
const PM = { t: {}, order: [], seq: 0, loaded: false, timer: null, audio: null, threshold: 3 };
const WINDOWS = [[300, '5 min'], [1800, '30 min'], [7200, '2 h'], [86400, '24 h']];
const cssVar = n => getComputedStyle(document.documentElement).getPropertyValue(n).trim();

function ensureAudio() {
  try {
    if (!PM.audio) PM.audio = new (window.AudioContext || window.webkitAudioContext)();
    if (PM.audio.state === 'suspended') PM.audio.resume();
  } catch (e) { /* no audio available */ }
}
function beep(kind) {
  try {
    ensureAudio(); const ctx = PM.audio; if (!ctx) return;
    const notes = kind === 'down' ? [[880, 0], [440, 0.2]] : [[523, 0], [784, 0.2]];
    for (const [f, at] of notes) {
      const o = ctx.createOscillator(), g = ctx.createGain();
      o.type = 'sine'; o.frequency.value = f; o.connect(g); g.connect(ctx.destination);
      const st = ctx.currentTime + at;
      g.gain.setValueAtTime(0.0001, st); g.gain.exponentialRampToValueAtTime(0.25, st + 0.02); g.gain.exponentialRampToValueAtTime(0.0001, st + 0.18);
      o.start(st); o.stop(st + 0.2);
    }
  } catch (e) { /* ignore */ }
}

function pmNewClient(stats) {
  const t = { stats, samples: [], win: 300, hist: null, histAt: 0, el: null, editing: false, hops: new Map(), routeVersion: -1, ymax: 5 };
  for (const h of stats.route || []) t.hops.set(h.n, { ring: (h.recent || []).map(s => ({ ts: s[0], rtt: s[1] })) });
  return t;
}

async function pmLoad() {
  const r = await api('/api/pings/targets');
  if (r.error) return;
  PM.threshold = r.outageThreshold || 3;
  $('#pingRetention').textContent = r.retentionDays || 30;
  PM.t = {}; PM.order = [];
  for (const s of r.targets) {
    const t = pmNewClient(s);
    t.samples = (s.recent || []).map(x => ({ ts: x[0], rtt: x[1], st: x[2] }));
    PM.t[s.id] = t; PM.order.push(s.id);
  }
  PM.seq = r.seq || 0; PM.loaded = true;
  pmRenderAll();
  if (!PM.timer) PM.timer = setInterval(pmPoll, 1000);
}

async function pmPoll() {
  if (!PM.loaded) return;
  const r = await api(`/api/pings/samples?since=${PM.seq}`);
  if (r.error || !r.events) return;
  const touched = new Set();
  for (const e of r.events) {
    PM.seq = e.seq;
    const t = PM.t[e.id];
    if (e.type === 'sample' && t) { t.samples.push({ ts: e.t, rtt: e.rtt, st: e.status }); if (t.samples.length > 20000) t.samples.splice(0, 2000); touched.add(e.id); }
    else if (e.type === 'hops' && t) {
      for (const [n, rtt] of e.hops) { let h = t.hops.get(n); if (!h) { h = { ring: [] }; t.hops.set(n, h); } h.ring.push({ ts: e.t, rtt }); if (h.ring.length > 120) h.ring.splice(0, h.ring.length - 120); }
      touched.add(e.id);
    }
    else if (e.type === 'route' && t) { if (e.reason === 'change') toast(`${e.label || e.host}: ${e.detail}`); }
    else if (e.type === 'outage') { if (!e.muted) beep('down'); toast(`${e.label || e.host} is down${e.detail ? ': ' + e.detail : ''}`); }
    else if (e.type === 'recovery') { if (!e.muted) beep('up'); toast(`${e.label || e.host} is answering again (down ${fmtDur(e.duration)})`); }
    else if (e.type === 'removed') { delete PM.t[e.id]; PM.order = PM.order.filter(x => x !== e.id); const el = $(`#pc-${e.id}`); if (el) el.remove(); }
  }
  for (const s of r.stats || []) {
    if (!PM.t[s.id]) { PM.t[s.id] = pmNewClient(s); PM.order.push(s.id); touched.add(s.id); }
    else PM.t[s.id].stats = s;
  }
  const visible = T.tab === 'pings';
  for (const id of PM.order) {
    const t = PM.t[id]; if (!t) continue;
    if (!t.el) pmCard(id);
    if (visible) pmUpdate(id, touched.has(id));
  }
  // the server's order is authoritative (another window may have rearranged things)
  const serverOrder = (r.stats || []).map(s => s.id).filter(id => PM.t[id]);
  if (!PM.dragging && serverOrder.length === PM.order.length && serverOrder.some((id, i) => id !== PM.order[i])) { PM.order = serverOrder; pmApplyOrder(); }
  pmBadge();
  $('#pingEmpty').classList.toggle('hidden', PM.order.length > 0);
}
function pmBadge() {
  const down = PM.order.filter(id => PM.t[id] && PM.t[id].stats.state === 'down').length;
  const b = $('#tabs button[data-tab=pings]');
  b.innerHTML = 'Ping monitor' + (down ? `<span class="badge">${down}</span>` : '');
}
function fmtDur(s) { s = Math.round(s || 0); if (s < 60) return `${s} s`; if (s < 3600) return `${Math.floor(s / 60)} min ${s % 60} s`; return `${Math.floor(s / 3600)} h ${Math.floor(s % 3600 / 60)} min`; }
const fmtClock = ts => new Date(ts * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

function pmRenderAll() {
  for (const id of PM.order) { const t = PM.t[id]; if (!t) continue; if (!t.el || !t.el.isConnected) pmCard(id); pmUpdate(id, true); }
  pmApplyOrder();
  $('#pingEmpty').classList.toggle('hidden', PM.order.length > 0);
  pmBadge();
}

function pmCard(id) {
  const t = PM.t[id];
  const el = document.createElement('section');
  el.className = 'card pcard'; el.id = `pc-${id}`;
  el.innerHTML = `
    <div class="phead">
      <span class="grip" draggable="true" title="Drag to reorder">⋮⋮</span>
      <button class="chev" data-a="toggle" title="Collapse or expand">▾</button>
      <div class="pname"><span class="dot"></span><span class="ptitle"></span><span class="hint phost"></span></div>
      <div class="psum hint"><span class="s-cur"></span><span class="s-loss"></span><span class="s-hops"></span></div>
      <div class="row wrap pbtns">
        <span class="arrows"><button class="btn small" data-a="top" title="Move to top">⤒</button><button class="btn small" data-a="up" title="Move up">▲</button><button class="btn small" data-a="down" title="Move down">▼</button><button class="btn small" data-a="bottom" title="Move to bottom">⤓</button></span>
        <button class="btn small" data-a="rename" title="Rename">Rename</button>
        <button class="btn small" data-a="pause">Pause</button>
        <button class="btn small" data-a="mute" title="Turn the outage sound on or off">Sound on</button>
        <button class="btn small" data-a="hops" title="Show or hide the route (hop by hop)">Route on</button>
        <button class="btn small" data-a="csv" title="Save the last 30 days as CSV">Save CSV</button>
        <button class="btn small" data-a="clear" title="Reset the statistics">Reset</button>
        <button class="btn small danger" data-a="remove">Remove</button>
      </div>
    </div>
    <div class="pbody">
      <div class="proute">
        <div class="table-wrap"><table class="table hops"><thead><tr><th>Hop</th><th>Address</th><th>Name</th><th>Avg</th><th>Min</th><th>Cur</th><th>Loss</th><th>Recent</th></tr></thead><tbody></tbody></table></div>
        <div class="hint proutenote"></div>
      </div>
      <div class="pnow"><span class="pv">—</span><small class="pu"></small></div>
      <canvas class="spark" height="130"></canvas>
      <div class="pfoot">
        <div class="legend"><span><i style="background:var(--accent)"></i>Reply time</span><span><i style="background:var(--bad)"></i>No reply</span><span><i style="background:transparent;border-top:2px dashed var(--muted);height:0;margin-top:5px"></i>Average</span></div>
        <span class="mini-chips pwin">${WINDOWS.map(([s, l]) => `<button data-w="${s}" class="${s === 300 ? 'on' : ''}">${l}</button>`).join('')}</span>
      </div>
      <div class="tiles ptiles"></div>
      <div class="poutages"></div>
    </div>`;
  t.el = el;
  $('#pingCards').appendChild(el);
  el.addEventListener('click', ev => {
    const b = ev.target.closest('button');
    if (b) {
      if (b.dataset.w) { t.win = +b.dataset.w; $$('.pwin button', el).forEach(x => x.classList.toggle('on', x === b)); t.hist = null; t.histAt = 0; pmUpdate(id, true); return; }
      if (b.dataset.a) { pmAction(id, b.dataset.a, b); return; }
    }
    if (ev.target.closest('.grip')) return;
    // clicking the header background toggles collapse
    if (ev.target.closest('.phead') && !ev.target.closest('input')) pmAction(id, 'toggle');
  });
  const grip = $('.grip', el);
  grip.addEventListener('dragstart', ev => {
    PM.dragging = id; el.classList.add('dragging');
    ev.dataTransfer.effectAllowed = 'move'; ev.dataTransfer.setData('text/plain', id);
    try { ev.dataTransfer.setDragImage(el, 20, 20); } catch (e) { /* ignore */ }
  });
  grip.addEventListener('dragend', () => { PM.dragging = null; el.classList.remove('dragging'); $$('.pcard').forEach(c => c.classList.remove('drop-before', 'drop-after')); });
  return el;
}

/* Reordering: arrows and drag & drop. The server order is authoritative after each change. */
function pmApplyOrder() {
  const box = $('#pingCards');
  PM.order.forEach(id => { const t = PM.t[id]; if (t && t.el) box.appendChild(t.el); });
  PM.order.forEach((id, i) => {
    const t = PM.t[id]; if (!t || !t.el) return;
    $('button[data-a=top]', t.el).disabled = $('button[data-a=up]', t.el).disabled = i === 0;
    $('button[data-a=down]', t.el).disabled = $('button[data-a=bottom]', t.el).disabled = i === PM.order.length - 1;
  });
}
async function pmMove(id, where) {
  const i = PM.order.indexOf(id); if (i < 0) return;
  let j = where === 'top' ? 0 : where === 'bottom' ? PM.order.length - 1 : where === 'up' ? i - 1 : where === 'down' ? i + 1 : (typeof where === 'number' ? where : i);
  j = Math.max(0, Math.min(PM.order.length - 1, j));
  if (j === i) return;
  PM.order.splice(i, 1); PM.order.splice(j, 0, id);
  pmApplyOrder();
  const r = await api('/api/pings/reorder', { ids: PM.order });
  if (r.error) toast(r.error);
}
function pmWireDragTarget() {
  const box = $('#pingCards');
  box.addEventListener('dragover', ev => {
    if (!PM.dragging) return;
    ev.preventDefault(); ev.dataTransfer.dropEffect = 'move';
    const card = ev.target.closest('.pcard');
    $$('.pcard', box).forEach(c => c.classList.remove('drop-before', 'drop-after'));
    if (!card || card.id === `pc-${PM.dragging}`) return;
    const rect = card.getBoundingClientRect();
    card.classList.add(ev.clientY < rect.top + rect.height / 2 ? 'drop-before' : 'drop-after');
  });
  box.addEventListener('drop', ev => {
    if (!PM.dragging) return;
    ev.preventDefault();
    const card = ev.target.closest('.pcard');
    const dragged = PM.dragging;
    $$('.pcard', box).forEach(c => c.classList.remove('drop-before', 'drop-after'));
    if (!card || card.id === `pc-${dragged}`) return;
    const targetId = card.id.slice(3);
    const rect = card.getBoundingClientRect();
    const before = ev.clientY < rect.top + rect.height / 2;
    const from = PM.order.indexOf(dragged);
    let to = PM.order.indexOf(targetId) + (before ? 0 : 1);
    if (from < to) to -= 1;
    pmMove(dragged, to);
  });
}

async function pmAction(id, act, btn) {
  const t = PM.t[id]; if (!t) return;
  const s = t.stats;
  if (act === 'toggle') { s.collapsed = !s.collapsed; pmUpdate(id, true); api('/api/pings/update', { id, collapsed: s.collapsed }); }
  else if (act === 'top' || act === 'up' || act === 'down' || act === 'bottom') { pmMove(id, act); }
  else if (act === 'pause') { const r = await api('/api/pings/pause', { id, paused: !s.paused }); if (!r.error) { t.stats = r.target; pmUpdate(id, true); } }
  else if (act === 'mute') { const r = await api('/api/pings/update', { id, muted: !s.muted }); if (!r.error) { t.stats = r.target; pmUpdate(id, true); toast(r.target.muted ? 'Outage sound off for this address' : 'Outage sound on'); } }
  else if (act === 'hops') { const r = await api('/api/pings/update', { id, hopsOn: !s.hopsOn }); if (!r.error) { t.stats = r.target; pmUpdate(id, true); } }
  else if (act === 'csv') { const r = await api(`/api/pings/csv?id=${id}&days=30`); if (r.error) toast(r.error); else download(r.name, r.text, 'text/csv'); }
  else if (act === 'clear') { const r = await api('/api/pings/clear', { id }); if (!r.error) { t.stats = r.target; t.samples = []; t.hops.forEach(h => h.ring = []); pmUpdate(id, true); } }
  else if (act === 'remove') { if (confirm(`Stop watching ${s.label || s.host} and delete its history?`)) { await api('/api/pings/remove', { id }); delete PM.t[id]; PM.order = PM.order.filter(x => x !== id); t.el.remove(); $('#pingEmpty').classList.toggle('hidden', PM.order.length > 0); pmBadge(); } }
  else if (act === 'rename') {
    const title = $('.ptitle', t.el);
    if (t.editing) return;
    t.editing = true;
    const inp = document.createElement('input'); inp.type = 'text'; inp.className = 'plabel'; inp.value = s.label || ''; inp.placeholder = s.host; inp.maxLength = 60;
    title.replaceWith(inp); inp.focus(); inp.select();
    const finish = async (save) => {
      if (!t.editing) return; t.editing = false;
      if (save) { const r = await api('/api/pings/update', { id, label: inp.value.trim() }); if (!r.error) t.stats = r.target; }
      const span = document.createElement('span'); span.className = 'ptitle'; inp.replaceWith(span); pmUpdate(id, true);
    };
    inp.addEventListener('keydown', e => { if (e.key === 'Enter') finish(true); if (e.key === 'Escape') finish(false); });
    inp.addEventListener('blur', () => finish(true));
  }
}

async function pmCollapseAll(collapsed) {
  const r = await api('/api/pings/collapse', { collapsed });
  if (r.error) { toast(r.error); return; }
  for (const s of r.targets || []) if (PM.t[s.id]) { PM.t[s.id].stats = s; pmUpdate(s.id, true); }
}

async function pmUpdate(id, redraw) {
  const t = PM.t[id]; if (!t || !t.el) return;
  const s = t.stats; const el = t.el;
  el.classList.toggle('down', s.state === 'down'); el.classList.toggle('paused', !!s.paused); el.classList.toggle('collapsed', !!s.collapsed);
  $('.chev', el).textContent = s.collapsed ? '▸' : '▾';
  $('.dot', el).className = 'dot ' + (s.paused ? 'paused' : s.state);
  const disp = s.display || s.host; const kindWord = s.kind === 'http' ? 'web page' : s.kind === 'tcp' ? `port ${s.port}` : '';
  const title = $('.ptitle', el); if (title) title.textContent = s.label || disp;
  $('.phost', el).textContent = (s.label ? disp : '') + (s.ip && s.ip !== s.host ? ` (${s.ip})` : '') + (kindWord ? ` · ${kindWord}` : '');
  // header summary
  const downWord = s.kind === 'ping' ? 'no reply' : 'down';
  const cur = s.paused ? 'paused' : s.state === 'down' ? downWord : s.state === 'unresolved' ? 'not found' : (s.last != null ? fmtMs(s.last) : '…');
  $('.s-cur', el).textContent = cur;
  $('.s-loss', el).textContent = s.sent ? (s.kind === 'ping' ? `${fmtPct(s.lossPct)} lost` : `${fmtPct(s.uptimePct)} up`) : '';
  const hopCount = (s.route || []).length;
  $('.s-hops', el).textContent = !s.hopsOn ? 'route off' : hopCount ? `${hopCount} hop${hopCount === 1 ? '' : 's'}${s.routeState === 'partial' ? ' (incomplete)' : ''}` : (s.routeState === 'discovering' ? 'finding route…' : '');
  $('button[data-a=pause]', el).textContent = s.paused ? 'Resume' : 'Pause';
  $('button[data-a=mute]', el).textContent = s.muted ? 'Sound off' : 'Sound on';
  $('button[data-a=mute]', el).classList.toggle('on', !s.muted);
  $('button[data-a=hops]', el).textContent = s.hopsOn ? 'Route on' : 'Route off';
  $('button[data-a=hops]', el).classList.toggle('on', !!s.hopsOn);
  if (s.collapsed) return;
  // big number
  const pv = $('.pv', el), pu = $('.pu', el);
  if (s.paused) { pv.textContent = 'Paused'; pu.textContent = ''; }
  else if (s.state === 'unresolved') { pv.textContent = 'Not found'; pu.textContent = s.resolveError || ''; }
  else if (s.state === 'down') { pv.textContent = s.kind === 'ping' ? 'No reply' : 'Down'; pu.textContent = `${s.consecutiveFail} in a row${s.lastDetail && s.kind !== 'ping' ? ' · ' + s.lastDetail : ''}`; }
  else if (s.last != null && s.lastStatus === 'ok') { const f = fmtMs(s.last).split(' '); pv.textContent = f[0]; pu.textContent = s.kind === 'http' ? `ms · ${s.lastDetail || 'page answered'}` : s.kind === 'tcp' ? 'ms · port answered' : 'ms · last reply'; }
  else if (['timeout', 'refused', 'http_error', 'error'].includes(s.lastStatus)) { pv.textContent = s.kind === 'ping' ? 'No reply' : 'Down'; pu.textContent = s.lastDetail && s.kind !== 'ping' ? s.lastDetail : 'waiting for the next one'; }
  else { pv.textContent = '—'; pu.textContent = s.state === 'starting' ? 'starting…' : ''; }
  const lossCls = s.lossPct === 0 ? 'good' : s.lossPct > 5 ? 'bad' : s.lossPct > 1 ? 'warn' : '';
  $('.ptiles', el).innerHTML = [
    tile('Average', s.avg != null ? fmtMs(s.avg) : '—'), tile('Best', s.min != null ? fmtMs(s.min) : '—'), tile('Worst', s.max != null ? fmtMs(s.max) : '—'),
    tile('Jitter', s.received > 1 ? fmtMs(s.jitter) : '—'),
    s.kind === 'ping' ? tile('Lost', `${fmtPct(s.lossPct)}<small>${s.sent - s.received} of ${s.sent}</small>`, lossCls) : tile('Uptime', `${s.uptimePct != null ? fmtPct(s.uptimePct) : '—'}<small>${s.received} of ${s.sent} checks</small>`, lossCls),
    tile('Outages', `${s.outages.length}`, s.outages.length ? 'warn' : ''), tile('Route changes', `${s.routeChanges || 0}`, s.routeChanges ? 'warn' : ''),
  ].join('');
  const out = s.outages.slice(-3).reverse().map(o => o.end ? `<b>Down ${fmtDur(o.duration)}</b> at ${fmtClock(o.start)} (${o.count} misses)` : `<b>Down since ${fmtClock(o.start)}</b> (${o.count} misses so far)`);
  $('.poutages', el).innerHTML = out.length ? 'Recent outages: ' + out.join(' · ') : '';
  // timeline
  if (t.win > 1800 && (!t.hist || Date.now() - t.histAt > 60000)) {
    t.histAt = Date.now();
    const h = await api(`/api/pings/history?id=${id}&hours=${t.win / 3600}`);
    if (!h.error) t.hist = h;
  }
  t.ymax = drawLatencyChart($('canvas.spark', el), t);
  // route table
  const pr = $('.proute', el);
  pr.classList.toggle('hidden', !s.hopsOn && !(s.route || []).length);
  pr.classList.toggle('off', !s.hopsOn);
  if (s.routeVersion !== t.routeVersion) { pmBuildRoute(t); t.routeVersion = s.routeVersion; }
  pmPatchRoute(t);
}

function pmBuildRoute(t) {
  const tb = $('.hops tbody', t.el);
  const route = t.stats.route || [];
  tb.innerHTML = route.map(h => `<tr data-n="${h.n}" class="${h.dest ? 'dest' : ''} ${h.ip ? '' : 'dim'}"><td>${h.n}</td><td class="mono h-ip"></td><td class="h-name"></td><td class="h-avg"></td><td class="h-min"></td><td class="h-cur"></td><td class="h-loss"></td><td><canvas class="hspark" width="110" height="22"></canvas></td></tr>`).join('');
  const note = $('.proutenote', t.el);
  if (!route.length) note.textContent = t.stats.routeState === 'discovering' ? 'Finding the route…' : t.stats.hopsOn ? 'The route will appear once the first replies arrive.' : '';
  else note.textContent = (t.stats.routeState === 'partial' ? 'The last routers before the destination do not answer, so the route is shown as far as it can be seen. ' : '') +
    'Loss at a middle hop that does not continue to later hops is that router limiting its replies, not a real problem.';
}
function pmPatchRoute(t) {
  const s = t.stats; const el = t.el;
  for (const h of s.route || []) {
    const tr = $(`.hops tr[data-n="${h.n}"]`, el); if (!tr) continue;
    tr.classList.toggle('dim', !h.ip); tr.classList.toggle('stale', !!h.stale); tr.classList.toggle('dest', !!h.dest);
    $('.h-ip', tr).textContent = h.ip || (h.dest ? s.ip || '' : '—');
    $('.h-name', tr).innerHTML = (h.dest ? `<span class="pill pill-good" style="font-size:11px;margin-right:6px">destination</span>` : '') + esc(h.name || (h.ip ? '' : 'no reply from this hop')) +
      (h.flapping ? ` <span class="pill pill-muted" style="font-size:11px" title="This hop answers from more than one address (load balancing)">${h.addresses} addresses</span>` : '') +
      (h.changes ? ` <span class="pill pill-muted" style="font-size:11px" title="Times this hop's address changed">${h.changes} change${h.changes === 1 ? '' : 's'}</span>` : '');
    $('.h-avg', tr).textContent = h.avg != null ? fmtMs(h.avg) : '—';
    $('.h-min', tr).textContent = h.min != null ? fmtMs(h.min) : '—';
    $('.h-cur', tr).textContent = h.cur != null ? fmtMs(h.cur) : '—';
    const lossEl = $('.h-loss', tr); lossEl.textContent = h.sent ? fmtPct(h.lossPct) : '—';
    lossEl.className = 'h-loss ' + (h.lossPct > 5 ? 'bad' : h.lossPct > 1 ? 'warn' : '');
    const ring = h.dest ? t.samples.slice(-120).filter(x => x.st !== 'gap' && x.st !== 'unresolved').map(x => ({ ts: x.ts, rtt: x.rtt })) : ((t.hops.get(h.n) || {}).ring || []);
    drawHopSpark($('canvas.hspark', tr), ring, t.ymax || 5);
  }
}
function drawHopSpark(canvas, ring, ymax) {
  const dpr = window.devicePixelRatio || 1, W = 110, H = 22;
  if (canvas.width !== Math.round(W * dpr)) { canvas.width = Math.round(W * dpr); canvas.height = Math.round(H * dpr); canvas.style.width = W + 'px'; canvas.style.height = H + 'px'; }
  const ctx = canvas.getContext('2d'); ctx.setTransform(dpr, 0, 0, dpr, 0, 0); ctx.clearRect(0, 0, W, H);
  ctx.fillStyle = cssVar('--line'); ctx.fillRect(0, H - 1, W, 1);
  const n = Math.min(ring.length, W), off = ring.length - n, ok = cssVar('--accent'), bad = cssVar('--bad');
  for (let i = 0; i < n; i++) {
    const smp = ring[off + i], x = W - n + i;
    if (smp.rtt == null) { ctx.fillStyle = bad; ctx.fillRect(x, 0, 1, H); }
    else { const h = Math.max(1, Math.min(smp.rtt, ymax) / ymax * (H - 2)); ctx.fillStyle = ok; ctx.fillRect(x, H - 1 - h, 1, h); }
  }
}

function drawLatencyChart(canvas, t) {
  if (!canvas.dataset.h) canvas.dataset.h = canvas.getAttribute('height') || '130';
  const dpr = window.devicePixelRatio || 1;
  const W = canvas.clientWidth || 600, H = parseInt(canvas.dataset.h) || 130;
  canvas.style.height = H + 'px'; canvas.width = Math.round(W * dpr); canvas.height = Math.round(H * dpr);
  const ctx = canvas.getContext('2d'); ctx.scale(dpr, dpr);
  const col = cssVar;
  const padL = 52, padR = 10, padT = 8, padB = 18; const pw = W - padL - padR, ph = H - padT - padB;
  ctx.clearRect(0, 0, W, H);
  const now = Date.now() / 1000; const start = now - t.win;
  let pts;
  if (t.win > 1800 && t.hist) {
    pts = t.hist.raw ? t.hist.points.map(p => ({ x: p[0], y: p[1], st: p[2] })) : t.hist.points.map(p => ({ x: p[0], y: p[1], st: p[2], lo: p[3], hi: p[4], lost: p[5] }));
    const lastX = pts.length ? pts[pts.length - 1].x : 0;
    pts = pts.concat(t.samples.filter(s => s.ts > lastX).map(s => ({ x: s.ts, y: s.rtt, st: s.st })));
  } else {
    pts = t.samples.filter(s => s.ts >= start).map(s => ({ x: s.ts, y: s.rtt, st: s.st }));
  }
  const ys = pts.map(p => p.y).filter(v => v != null).sort((a, b) => a - b);
  let ymax = 5;
  if (ys.length) { const p95 = ys[Math.min(ys.length - 1, Math.floor(ys.length * 0.95))]; ymax = Math.max(5, p95 * 1.3); }
  const xOf = x => padL + (x - start) / t.win * pw; const yOf = y => padT + ph - Math.min(y, ymax) / ymax * ph;
  ctx.font = '11px system-ui, sans-serif'; ctx.textBaseline = 'middle';
  for (let g = 0; g <= 3; g++) {
    const y = padT + ph - ph * g / 3;
    ctx.strokeStyle = col('--line'); ctx.lineWidth = 1; ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(W - padR, y); ctx.stroke();
    ctx.fillStyle = col('--soft'); ctx.textAlign = 'right'; ctx.fillText(g === 0 ? '0' : fmtMs(ymax * g / 3), padL - 6, y);
  }
  if (pts.some(p => p.lo != null)) {
    ctx.fillStyle = col('--accent-soft'); ctx.beginPath(); let started = false;
    const good = pts.filter(p => p.lo != null);
    good.forEach(p => { const x = xOf(p.x); if (!started) { ctx.moveTo(x, yOf(p.hi)); started = true; } else ctx.lineTo(x, yOf(p.hi)); });
    good.slice().reverse().forEach(p => ctx.lineTo(xOf(p.x), yOf(p.lo)));
    ctx.closePath(); ctx.fill();
  }
  ctx.strokeStyle = col('--accent'); ctx.lineWidth = 1.6; ctx.lineJoin = 'round'; ctx.beginPath(); let pen = false;
  for (const p of pts) {
    if (p.y == null || p.st === 'gap') { pen = false; continue; }
    const x = xOf(p.x), y = yOf(p.y);
    if (!pen) { ctx.moveTo(x, y); pen = true; } else ctx.lineTo(x, y);
  }
  ctx.stroke();
  for (const p of pts) {
    const x = xOf(p.x);
    if (p.y != null && p.y > ymax) { ctx.fillStyle = col('--warn'); ctx.beginPath(); ctx.moveTo(x, padT); ctx.lineTo(x - 3, padT + 6); ctx.lineTo(x + 3, padT + 6); ctx.closePath(); ctx.fill(); }
    if ((p.y == null && p.st !== 'gap') || p.lost) { ctx.fillStyle = col('--bad'); ctx.fillRect(x - 1, padT + ph - 8, 2, 8); }
  }
  if (ys.length > 1) { const avg = ys.reduce((a, b) => a + b, 0) / ys.length; const y = yOf(avg); ctx.setLineDash([5, 4]); ctx.strokeStyle = col('--muted'); ctx.lineWidth = 1; ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(W - padR, y); ctx.stroke(); ctx.setLineDash([]); }
  ctx.fillStyle = col('--soft'); ctx.textAlign = 'center';
  const n = Math.max(2, Math.floor(pw / 90));
  for (let i = 0; i <= n; i++) { const x = start + t.win * i / n; ctx.fillText(i === n ? 'now' : fmtClock(x), xOf(x), H - padB / 2); }
  if (!pts.length) { ctx.fillStyle = col('--soft'); ctx.font = '12.5px system-ui, sans-serif'; ctx.fillText('Reply times appear here', padL + pw / 2, padT + ph / 2); }
  return ymax;
}

async function pmAdd() {
  const err = $('#pingError'); err.classList.add('hidden');
  ensureAudio();
  const host = $('#pingHost').value.trim(); if (!host) { $('#pingHost').focus(); return; }
  const kind = $('#pingKind').value; const port = $('#pingPort').value.trim();
  if (kind === 'tcp' && !port && !/:\d+$/.test(host)) { err.textContent = 'Enter the port to check.'; err.classList.remove('hidden'); $('#pingPort').focus(); return; }
  const r = await api('/api/pings/add', { host, kind, port: port || null, label: $('#pingLabel').value.trim(), interval: +$('#pingInterval').value || 1 });
  if (r.error) { err.textContent = r.error; err.classList.remove('hidden'); return; }
  $('#pingHost').value = ''; $('#pingLabel').value = ''; $('#pingPort').value = '';
  const s = r.target; PM.t[s.id] = pmNewClient(s); PM.order.push(s.id);
  pmCard(s.id); pmUpdate(s.id, true); pmApplyOrder(); $('#pingEmpty').classList.add('hidden');
  toast(`Watching ${s.label || s.display || s.host}`);
}
function pmKindUI() {
  const k = $('#pingKind').value; const host = $('#pingHost').value.trim();
  const auto = k === 'auto' ? (/^https?:\/\//i.test(host) ? 'http' : /:\d+$/.test(host) ? 'tcp' : 'ping') : k;
  $('#pingPort').classList.toggle('hidden', k !== 'tcp');
  const iv = $('#pingInterval');
  if (auto !== 'ping' && +iv.value < 10 && !iv.dataset.userSet) iv.value = '30';
  if (auto === 'ping' && +iv.value >= 30 && !iv.dataset.userSet) iv.value = '1';
  $('#pingHost').placeholder = auto === 'http' ? 'Web address, e.g. https://intranet.example.com/login' : auto === 'tcp' ? 'Host or address, e.g. fileserver (port at right) or fileserver:445' : 'Address, name, URL or host:port, e.g. 8.8.8.8, https://intranet, fileserver:445';
}

/* ------------------------------------------------------------------------ */
/* DNS lookup                                                               */
/* ------------------------------------------------------------------------ */
const DN = { system: [], presets: [], custom: [], selected: new Set(['system']), loaded: false };
async function dnsEnsureServers(force) {
  if (DN.loaded && !force) return;
  const r = await api('/api/dns/servers');
  if (r.error) return;
  DN.system = r.system || []; DN.presets = r.presets || []; DN.custom = r.custom || []; DN.loaded = true;
  if (T.settings.dnsLastType) $('#dnsType').value = T.settings.dnsLastType;
  dnsRenderChips();
}
function dnsRenderChips() {
  const box = $('#dnsServers');
  const chips = [{ key: 'system', label: `This computer's (${DN.system.join(', ') || 'none found'})`, on: DN.selected.has('system'), disabled: !DN.system.length }]
    .concat(DN.presets.map(p => ({ key: p.ip, label: `${p.name} ${p.ip}`, on: DN.selected.has(p.ip) })))
    .concat(DN.custom.map(ip => ({ key: ip, label: ip, on: DN.selected.has(ip), custom: true })));
  box.innerHTML = chips.map(c => `<button class="chip srv ${c.on ? 'on' : ''}" data-key="${esc(c.key)}" ${c.disabled ? 'disabled' : ''}>${esc(c.label)}${c.custom ? '<span class="x" data-x="1" title="Remove">✕</span>' : ''}</button>`).join('');
  $$('.chip', box).forEach(b => b.onclick = ev => {
    const key = b.dataset.key;
    if (ev.target.dataset.x) { DN.custom = DN.custom.filter(x => x !== key); DN.selected.delete(key); dnsRenderChips(); return; }
    if (DN.selected.has(key)) { if (DN.selected.size > 1) DN.selected.delete(key); } else DN.selected.add(key);
    dnsRenderChips();
  });
}
function dnsServersToQuery() {
  const out = [];
  for (const k of DN.selected) { if (k === 'system') out.push(...DN.system); else out.push(k); }
  return [...new Set(out)];
}
async function dnsLookup() {
  const err = $('#dnsError'); err.classList.add('hidden');
  const name = $('#dnsName').value.trim(); if (!name) { $('#dnsName').focus(); return; }
  const servers = dnsServersToQuery();
  const btn = $('#dnsGo'); btn.disabled = true; btn.textContent = 'Looking up…';
  const r = await api('/api/dns/lookup', { name, type: $('#dnsType').value, servers, custom: DN.custom });
  btn.disabled = false; btn.textContent = 'Look up';
  if (r.error) { err.textContent = r.error; err.classList.remove('hidden'); return; }
  dnsRender(r);
}
function dnsRender(r) {
  const box = $('#dnsResults');
  const servers = r.servers;
  // Which (type,data) pairs appear on every server? Others get highlighted.
  const sets = servers.map(s => new Set((r.results[s] || []).flatMap(q => (q.answers || []).map(a => `${a.type}|${a.data}`))));
  const common = new Set([...sets[0] || []].filter(k => sets.every(s => s.has(k))));
  box.innerHTML = servers.map((srv, i) => {
    const qs = r.results[srv] || [];
    const label = srv === DN.system[0] || DN.system.includes(srv) ? `This computer's server · ${srv}` : (DN.presets.find(p => p.ip === srv) || {}).name ? `${DN.presets.find(p => p.ip === srv).name} · ${srv}` : srv;
    const errs = qs.filter(q => q.error);
    const ok = qs.filter(q => !q.error);
    const worst = ok.some(q => q.rcode === 3) ? 'NXDOMAIN' : ok.some(q => q.rcode && q.rcode !== 0) ? ok.find(q => q.rcode && q.rcode !== 0).rcodeText : ok.length ? 'OK' : 'no answer';
    const pillCls = worst === 'OK' ? 'pill-good' : worst === 'NXDOMAIN' ? 'pill-bad' : 'pill-muted';
    const ms = ok.length ? Math.max(...ok.map(q => q.ms || 0)) : null;
    const tcp = ok.some(q => q.transport === 'tcp');
    let rows = '';
    for (const q of ok) {
      for (const a of q.answers || []) rows += `<tr class="${common.has(`${a.type}|${a.data}`) || servers.length < 2 ? '' : 'diff'}"><td>${esc(a.type)}</td><td class="mono">${esc(a.name)}</td><td>${esc(fmtTtl(a.ttl))}</td><td class="data">${esc(a.data)}</td></tr>`;
      if (!(q.answers || []).length && q.rcode === 3) rows += `<tr><td>${esc(q.type)}</td><td colspan="3" class="hint">No such name (NXDOMAIN)${(q.authority || []).length ? ` · zone ${esc(q.authority[0].name)}` : ''}</td></tr>`;
      else if (!(q.answers || []).length && r.types.length === 1) rows += `<tr><td>${esc(q.type)}</td><td colspan="3" class="hint">No ${esc(q.type)} record${(q.authority || []).some(a => a.type === 'SOA') ? ' (the name exists, but has no record of this type)' : ''}</td></tr>`;
    }
    for (const q of errs) rows += `<tr><td>${esc(q.type)}</td><td colspan="3" class="hint">${esc(q.error)}</td></tr>`;
    return `<section class="card"><div class="dhead"><h3>${esc(label)}</h3><div class="row"><span class="pill ${pillCls}">${esc(worst)}</span>${ms != null ? `<span class="hint">${ms} ms${tcp ? ' · used TCP' : ''}</span>` : ''}</div></div>` +
      `<div class="table-wrap"><table class="table"><thead><tr><th>Type</th><th>Name</th><th>Cached for</th><th>Answer</th></tr></thead><tbody>${rows || '<tr><td colspan="4" class="hint">Nothing came back.</td></tr>'}</tbody></table></div>` +
      `${i === 0 && r.note ? `<div class="dnote">${esc(r.note)}</div>` : ''}</section>`;
  }).join('');
  if (servers.length > 1 && [...sets].some(s => [...s].some(k => !common.has(k)))) {
    box.insertAdjacentHTML('afterbegin', `<div class="hint" style="grid-column:1/-1">Highlighted rows are answers that not every server gave. Different addresses can be normal for big sites (they hand out nearby servers); different mail or name servers usually mean a stale or wrong record somewhere.</div>`);
  }
}
function fmtTtl(s) { if (s == null) return ''; if (s < 60) return `${s} s`; if (s < 3600) return `${Math.round(s / 60)} min`; if (s < 86400) return `${Math.round(s / 3600)} h`; return `${Math.round(s / 86400)} d`; }

/* ------------------------------------------------------------------------ */
/* Packet capture                                                           */
/* ------------------------------------------------------------------------ */
const PC = { ifaces: [], engines: null, loaded: false, seq: 0, running: false, id: null, timer: null, recent: [], counters: null,
  proto: 'any', duration: 60, viewId: null, view: null, filter: { proto: '', host: '', port: '', q: '' }, offset: 0, total: 0, sel: null, wireshark: false };
const PROTO_COLORS = { DNS: '#0b6ef5', mDNS: '#4d8ff7', LLMNR: '#4d8ff7', HTTP: '#1a9e5c', TLS: '#3cc47c', QUIC: '#7bd7a3', TCP: '#8a93a6', UDP: '#c7a300', ICMP: '#d7860a',
  ICMPv6: '#f0a52e', ARP: '#9b59b6', DHCP: '#e67e22', NTP: '#b8b8b8', SSDP: '#95a5a6', NBNS: '#7f8c8d', iperf3: '#ef8a1c', IPv4: '#6f788c', IPv6: '#6f788c', Other: '#5d667a' };
const fmtBytesShort = b => fmtBytes(b);
const pcTime = (ts, t0) => (ts - t0).toFixed(3) + ' s';
const fmtDurS = s => s == null ? '—' : s < 60 ? `${Math.round(s)} s` : s < 3600 ? `${Math.floor(s / 60)} min ${Math.round(s % 60)} s` : `${Math.floor(s / 3600)} h ${Math.floor(s % 3600 / 60)} min`;

async function pcEnsureInterfaces(force) {
  if (PC.loaded && !force) return;
  const r = await api('/api/pcap/interfaces');
  if (r.error) { $('#pcIfaceHint').textContent = r.error; return; }
  PC.ifaces = r.interfaces || []; PC.engines = r.engines || {}; PC.loaded = true;
  const sel = $('#pcIface');
  sel.innerHTML = PC.ifaces.map(i => `<option value="${esc(i.id)}">${esc(i.label)}</option>`).join('');
  const last = r.last || {};
  if (last.iface && PC.ifaces.some(i => i.id === last.iface)) sel.value = last.iface;
  if (last.filter) { pcSetProto(last.filter.proto || 'any'); $('#pcHost').value = last.filter.host || ''; $('#pcPort').value = last.filter.port || ''; }
  if (last.duration != null) pcSetDuration(String(last.duration));
  if (last.maxMB) $('#pcMaxMB').value = String(last.maxMB);
  if (!PC.ifaces.length) $('#pcIfaceHint').textContent = 'No network connection was found to record on.';
  pcIfaceChanged(); pcFilterText();
  if (!$('#pcName').value) $('#pcName').placeholder = 'Capture ' + new Date().toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });
}
function pcIfaceChanged() {
  const i = PC.ifaces.find(x => x.id === $('#pcIface').value); const e = PC.engines || {};
  if (!i) { $('#pcPermission').textContent = ''; return; }
  $('#pcIfaceHint').textContent = i.detail || '';
  let msg = '';
  if (i.engine === 'npcap') msg = `Recording uses Npcap (${(e.npcap && e.npcap.version || '').split(',')[0]}). No extra permission is needed.`;
  else if (i.engine === 'rawsock') msg = i.needsElevation ? 'Windows will ask for administrator permission when you press Start (one prompt per recording). Without Npcap only IPv4 traffic on this connection is recorded; installing Wireshark or Npcap gives full detail.' : 'Built-in recording: IPv4 traffic on this connection only.';
  else if (i.engine === 'afpacket') msg = i.needsElevation ? (e.pkexec ? 'Linux will ask for your password when you press Start.' : 'Recording needs administrator rights and no password prompt is available here; LinkTest will show the command to run instead.') : 'Recording as administrator.';
  $('#pcPermission').textContent = msg;
}
function pcSetProto(v) { PC.proto = v; $$('#pcProto button').forEach(b => b.classList.toggle('on', b.dataset.v === v)); pcFilterText(); }
function pcSetDuration(v) { PC.duration = +v; $$('#pcDuration button').forEach(b => b.classList.toggle('on', b.dataset.v === String(v))); }
function pcFilterText() {
  const names = { any: 'Everything', web: 'Web traffic (HTTP and HTTPS)', dns: 'DNS lookups', icmp: 'Pings', tcp: 'TCP connections', udp: 'UDP messages', arp: 'ARP (who-has questions on the local network)' };
  let t = names[PC.proto] || 'Everything';
  const h = $('#pcHost').value.trim(), p = $('#pcPort').value.trim();
  if (h) t += ` to or from ${h}`;
  if (p) t += ` on port ${p}`;
  $('#pcFilterText').textContent = t + ' will be recorded.';
}

async function pcStart() {
  const err = $('#pcError'); err.classList.add('hidden');
  const opts = { iface: $('#pcIface').value, filter: { host: $('#pcHost').value.trim(), port: $('#pcPort').value.trim() || null, proto: PC.proto },
    duration: PC.duration, maxMB: +$('#pcMaxMB').value || 100, name: $('#pcName').value.trim() };
  $('#pcStart').disabled = true;
  const r = await api('/api/pcap/start', opts);
  $('#pcStart').disabled = false;
  if (r.error) { err.textContent = r.error; err.classList.remove('hidden'); return; }
  PC.id = r.id; PC.seq = 0; PC.recent = []; PC.counters = null; PC.running = true;
  $('#pcName').value = '';
  $('#pcLiveStatus').textContent = r.elevated ? r.message : 'Recording…';
  $('#pcLiveCard').classList.remove('hidden'); $('#pcViewCard').classList.add('hidden');
  $('#pcLiveTable tbody').innerHTML = ''; $('#pcLiveTiles').innerHTML = ''; $('#pcLiveProtos').innerHTML = '';
  pcStartPolling();
}
async function pcStop() { $('#pcStop').disabled = true; await api('/api/pcap/stop', {}); setTimeout(() => $('#pcStop').disabled = false, 1500); }
function pcStartPolling() { if (PC.timer) return; PC.timer = setInterval(pcPoll, 500); pcPoll(); }
async function pcRehydrate() {
  const r = await api('/api/pcap/status?since=0');
  if (r.error || !r.state) return;
  if (r.state.running) {
    PC.id = r.state.id; PC.seq = 0; PC.running = true; PC.recent = r.state.recent || []; PC.counters = r.state.counters;
    $('#pcLiveCard').classList.remove('hidden'); pcRenderLive(); pcStartPolling();
  }
  pcList();
}
async function pcPoll() {
  const r = await api(`/api/pcap/status?since=${PC.seq}`);
  if (r.error || !r.events) return;
  let done = null;
  for (const e of r.events) {
    PC.seq = e.seq;
    if (e.type === 'packets') { PC.recent = PC.recent.concat(e.rows).slice(-200); }
    else if (e.type === 'progress') PC.counters = e;
    else if (e.type === 'done') done = e;
  }
  if (r.state && r.state.counters) PC.counters = Object.assign(PC.counters || {}, r.state.counters);
  if (r.state && r.state.running) $('#pcLiveStatus').textContent = (PC.counters && PC.counters.helperState === 'starting') ? 'Waiting for permission…' : 'Recording…';
  pcRenderLive();
  if (done || (r.state && !r.state.running && PC.running)) {
    PC.running = false; clearInterval(PC.timer); PC.timer = null;
    const e = done || {};
    $('#pcLiveStatus').className = 'status'; $('#pcLiveStatus').textContent = e.error ? 'Stopped: ' + e.error : `Finished (${e.reason === 'time' ? 'time was up' : e.reason === 'size' ? 'file size limit reached' : 'stopped'})`;
    if (e.error) { const err = $('#pcError'); err.textContent = e.error; err.classList.remove('hidden'); }
    else toast(`Recording saved: ${e.packets} packets`);
    setTimeout(() => { $('#pcLiveCard').classList.add('hidden'); $('#pcLiveStatus').className = 'status running'; }, 1500);
    pcList();
    if (!e.error && PC.id) pcOpen(PC.id);
  }
}
function pcRenderLive() {
  const c = PC.counters;
  if (c) {
    const pctT = c.remaining != null ? Math.min(100, Math.round(c.elapsed / (c.elapsed + c.remaining) * 100)) : 0;
    const pctS = Math.min(100, Math.round(c.sizeBytes / c.maxBytes * 100));
    const pct = Math.max(pctT, pctS);
    $('#pcProgress .bar').style.width = pct + '%';
    $('#pcProgress .msg').textContent = c.remaining != null ? `${fmtDurS(c.elapsed)} recorded · ${fmtDurS(c.remaining)} left` : `${fmtDurS(c.elapsed)} recorded · until you stop it`;
    $('#pcLiveTimer').textContent = `${fmtBytes(c.sizeBytes)} of ${fmtBytes(c.maxBytes)} file limit`;
    const rate = c.elapsed ? c.packets / c.elapsed : 0;
    $('#pcLiveTiles').innerHTML = [tile('Packets', c.packets.toLocaleString()), tile('Data', fmtBytes(c.bytes)), tile('Rate', `${rate.toFixed(rate < 10 ? 1 : 0)}<small>packets/s</small>`), tile('Dropped', String(c.dropped || 0), c.dropped ? 'warn' : '')].join('');
    $('#pcLiveProtos').innerHTML = pcProtoBar(c.protos, c.packets);
  }
  const t0 = PC.recent.length ? PC.recent[0].ts : 0;
  $('#pcLiveTable tbody').innerHTML = PC.recent.slice(-60).reverse().map(s => pcRow(s, t0, false)).join('');
}
function pcProtoBar(protos, total) {
  if (!protos || !protos.length || !total) return '';
  const bar = protos.map(p => `<span style="width:${Math.max(0.5, p.packets / total * 100)}%;background:${PROTO_COLORS[p.proto] || PROTO_COLORS.Other}" title="${esc(p.proto)}: ${p.packets}"></span>`).join('');
  const leg = protos.slice(0, 8).map(p => `<span><i style="background:${PROTO_COLORS[p.proto] || PROTO_COLORS.Other}"></i>${esc(p.proto)} ${Math.round(p.packets / total * 100)}%</span>`).join('');
  return `<div class="protobar">${bar}</div><div class="protolegend">${leg}</div>`;
}
function pcRow(s, t0, withNo) {
  return `<tr data-n="${s.n}" class="${PC.sel === s.n ? 'sel' : ''}">${withNo ? `<td class="mono">${s.n}</td>` : ''}<td class="mono">${pcTime(s.ts, t0)}</td><td class="mono">${esc(s.src)}${s.sport != null ? `<span class="sub">:${s.sport}</span>` : ''}</td><td class="mono">${esc(s.dst)}${s.dport != null ? `<span class="sub">:${s.dport}</span>` : ''}</td><td><span class="chip port" style="background:${PROTO_COLORS[s.proto] || PROTO_COLORS.Other}22;color:${PROTO_COLORS[s.proto] || PROTO_COLORS.Other}">${esc(s.proto)}</span></td><td>${s.len}</td><td class="info">${esc(s.info)}</td></tr>`;
}

/* viewer */
async function pcOpen(id) {
  const r = await api('/api/pcap/stats?id=' + encodeURIComponent(id));
  if (r.error) { toast(r.error); return; }
  PC.viewId = id; PC.view = r; PC.offset = 0; PC.sel = null; PC.filter = { proto: '', host: '', port: '', q: '', conn: '' };
  $$('#pcFilterProto .chip').forEach(c => c.classList.toggle('on', c.dataset.b === ''));
  $('#pcFHost').value = ''; $('#pcFPort').value = ''; $('#pcFQ').value = '';
  $('#pcDetail').classList.add('hidden');
  pcRenderViewer(); await pcPage();
  $('#pcViewCard').classList.remove('hidden');
  $('#pcViewCard').scrollIntoView({ behavior: 'smooth', block: 'start' });
  zkOpen(id);
}
function pcRenderViewer() {
  const v = PC.view; const st = v.stats || {};
  $('#pcViewTitle').textContent = v.name || 'Capture';
  const when = v.started ? new Date(v.started * 1000).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }) : '';
  $('#pcViewMeta').textContent = [when, v.ifaceLabel, v.filterText, v.error ? 'Ended with a problem: ' + v.error : '', v.truncated ? 'Showing the first 200,000 packets' : ''].filter(Boolean).join(' · ');
  const rate = st.duration ? st.packets / st.duration : 0;
  $('#pcViewTiles').innerHTML = [tile('Packets', (st.packets || 0).toLocaleString()), tile('Data', fmtBytes(st.bytes || 0)), tile('Length', fmtDurS(st.duration)),
    tile('Rate', `${rate.toFixed(rate < 10 ? 1 : 0)}<small>packets/s</small>`), tile('Devices', String(st.hosts || 0)), tile('Conversations', String(st.convCount || 0))].join('');
  $('#pcViewProtos').innerHTML = pcProtoBar(st.protos, st.packets);
  $('#pcTalkers').innerHTML = (st.talkers || []).length ? '<span class="presets-label">Busiest addresses</span>' + st.talkers.slice(0, 8).map(t => `<button class="chip talker" data-ip="${esc(t.ip)}" title="Show only this address">${esc(t.ip)}<small>${fmtBytes(t.bytes)}</small></button>`).join('') : '';
  $$('#pcTalkers .chip').forEach(b => b.onclick = () => { $('#pcFHost').value = b.dataset.ip; PC.filter.host = b.dataset.ip; PC.offset = 0; pcPage(); });
  $('#pcViewWireshark').classList.toggle('hidden', !v.wireshark);
}
async function pcPage() {
  const f = PC.filter; const qs = new URLSearchParams({ id: PC.viewId, proto: f.proto, host: f.host, port: f.port, q: f.q, conn: f.conn || '', offset: PC.offset, limit: 500 });
  const r = await api('/api/pcap/packets?' + qs.toString());
  if (r.error) { toast(r.error); return; }
  PC.total = r.total;
  const t0 = (PC.view.stats && PC.view.stats.first) || (r.rows[0] && r.rows[0].ts) || 0;
  $('#pcViewTable tbody').innerHTML = r.rows.map(s => pcRow(s, t0, true)).join('') || '<tr><td colspan="7" class="hint">No packets match this filter.</td></tr>';
  const from = r.total ? PC.offset + 1 : 0, to = Math.min(PC.offset + 500, r.total);
  $('#pcPageInfo').textContent = (r.total ? `Showing ${from.toLocaleString()}–${to.toLocaleString()} of ${r.total.toLocaleString()} packets` : 'No packets') +
    (f.conn ? ` of one connection (${(c => c[1] ? `${c[0]}:${c[1]} ↔ ${c[2]}:${c[3]}` : `${c[0]} ↔ ${c[2]}`)(f.conn.split('|'))}) · Clear to show all` : '');
  $('#pcPrev').disabled = PC.offset === 0; $('#pcNext').disabled = to >= r.total;
}
async function pcDetail(n) {
  PC.sel = n;
  $$('#pcViewTable tbody tr').forEach(tr => tr.classList.toggle('sel', +tr.dataset.n === n));
  const r = await api(`/api/pcap/packet?id=${encodeURIComponent(PC.viewId)}&n=${n}`);
  if (r.error) { toast(r.error); return; }
  const s = r.summary || {};
  $('#pcDetailTitle').textContent = `Packet ${n}: ${s.info || ''}`;
  $('#pcDetailBody').innerHTML = r.sections.map(sec => `<h4>${esc(sec.title)}</h4><div class="kv">${sec.rows.map(row => `<div class="k">${esc(row[0])}</div><div>${esc(row[1])}</div><div class="note">${esc(row[2] || '')}</div>`).join('')}</div>`).join('') +
    `<h4>Raw bytes</h4><pre class="mono">${esc(r.hex)}</pre>`;
  PC.selSummary = s;
  $('#pcDetail').classList.remove('hidden');
}
function pcFollow() {
  const s = PC.selSummary; if (!s) return;
  const ports = s.sport != null && s.dport != null;
  PC.filter = { proto: '', host: '', port: '', q: '', conn: [s.src, ports ? s.sport : '', s.dst, ports ? s.dport : '', '', ''].join('|') };
  $('#pcFHost').value = ''; $('#pcFPort').value = ''; $('#pcFQ').value = '';
  $$('#pcFilterProto .chip').forEach(c => c.classList.toggle('on', c.dataset.b === ''));
  PC.offset = 0; pcPage();
}
async function pcList() {
  const r = await api('/api/pcap/list');
  if (r.error) return;
  PC.wireshark = !!r.wireshark;
  const box = $('#pcList');
  if (!r.captures.length) { box.innerHTML = '<p class="hint">Recordings you make are kept here.</p>'; return; }
  box.innerHTML = r.captures.map(c => {
    const when = c.started ? new Date(c.started * 1000).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }) : '';
    const sub = [when, c.ifaceLabel, c.filterText, c.external ? 'opened file' : '', c.error ? 'problem: ' + c.error : ''].filter(Boolean).join(' · ');
    return `<div class="item" data-id="${esc(c.id)}"><div><div class="m">${esc(c.name)}${!c.exists ? ' <span class="pill pill-bad" style="font-size:11px">file missing</span>' : ''}</div><div class="t">${esc(sub)}</div></div>` +
      `<div class="r">${c.packets != null ? c.packets.toLocaleString() + '<small>packets</small>' : ''}<small>${fmtBytes(c.sizeBytes || 0)}</small></div>` +
      `<div class="rowbtns" style="grid-column:1/-1;text-align:right"><button class="btn small" data-act="open">Open</button><button class="btn small" data-act="rename">Rename</button>${PC.wireshark ? '<button class="btn small" data-act="ws">Wireshark</button>' : ''}<button class="btn small danger" data-act="del">Delete</button></div></div>`;
  }).join('');
  $$('.item', box).forEach(el => el.querySelectorAll('button[data-act]').forEach(b => b.onclick = async ev => {
    ev.stopPropagation(); const id = el.dataset.id;
    if (b.dataset.act === 'open') pcOpen(id);
    else if (b.dataset.act === 'ws') { const r2 = await api('/api/pcap/wireshark', { id }); if (r2.error) toast(r2.error); }
    else if (b.dataset.act === 'del') { if (confirm('Delete this recording?')) { const r2 = await api('/api/pcap/delete', { id }); if (r2.error) toast(r2.error); if (PC.viewId === id) $('#pcViewCard').classList.add('hidden'); if (ZK.id === id) { $('#zkCard').classList.add('hidden'); ZK.id = null; } pcList(); } }
    else if (b.dataset.act === 'rename') pcRenameInline(el, id);
  }));
}
function pcRenameInline(el, id) {
  const m = $('.m', el); const old = m.textContent.trim();
  const inp = document.createElement('input'); inp.type = 'text'; inp.value = old; inp.maxLength = 80; inp.style.width = '20em';
  m.replaceWith(inp); inp.focus(); inp.select();
  let done = false;
  const finish = async save => { if (done) return; done = true; if (save && inp.value.trim() && inp.value.trim() !== old) { const r = await api('/api/pcap/rename', { id, name: inp.value.trim() }); if (r.error) toast(r.error); if (PC.viewId === id && PC.view) { PC.view.name = inp.value.trim(); $('#pcViewTitle').textContent = PC.view.name; } } pcList(); };
  inp.addEventListener('keydown', e => { if (e.key === 'Enter') finish(true); if (e.key === 'Escape') finish(false); });
  inp.addEventListener('blur', () => finish(true));
}

/* ------------------------------------------------------------------------ */
/* Connections & findings (Zeek-style logs)                                 */
/* ------------------------------------------------------------------------ */
const ZK = { id: null, state: null, summary: null, log: 'conn', q: '', uid: '', offset: 0, total: 0, all: false, timer: null,
  data: null, sel: null, t0: 0, sort: '', desc: false, findings: [] };
const ZK_LOGS = [['notice', 'Findings'], ['conn', 'Connections'], ['dns', 'DNS'], ['http', 'Web (HTTP)'], ['ssl', 'Secure (TLS)'],
  ['quic', 'QUIC'], ['x509', 'Certificates'], ['files', 'Files'], ['ssh', 'SSH'], ['dhcp', 'DHCP'], ['ftp', 'FTP'], ['ntp', 'Time (NTP)'],
  ['software', 'Software'], ['known_hosts', 'Known hosts'], ['known_services', 'Known services'], ['weird', 'Oddities']];
// [field, header, secondary field shown underneath]
const ZK_COLS = {
  conn: [['ts', 'When'], ['id.orig_h', 'From', 'id.orig_p'], ['id.resp_h', 'To', 'id.resp_p'], ['service', 'Service', 'proto'], ['duration', 'Lasted'],
    ['orig_bytes', 'Sent'], ['resp_bytes', 'Received'], ['conn_state', 'Outcome'], ['history', 'History']],
  dns: [['ts', 'When'], ['id.orig_h', 'Asked by'], ['id.resp_h', 'DNS server'], ['query', 'Name'], ['qtype_name', 'Type'], ['rcode_name', 'Result'],
    ['answers', 'Answers'], ['rtt', 'Reply time']],
  http: [['ts', 'When'], ['id.orig_h', 'From'], ['host', 'Site', 'id.resp_h'], ['method', 'Method'], ['uri', 'Address (URI)'], ['status_code', 'Result', 'status_msg'],
    ['response_body_len', 'Size'], ['resp_mime_types', 'Type'], ['user_agent', 'Program']],
  ssl: [['ts', 'When'], ['id.orig_h', 'From'], ['server_name', 'Site', 'id.resp_h'], ['version', 'Version'], ['cipher', 'Cipher'], ['established', 'Completed'],
    ['sni_matches_cert', 'Certificate matches'], ['ja4', 'JA4 fingerprint']],
  quic: [['ts', 'When'], ['id.orig_h', 'From'], ['server_name', 'Site', 'id.resp_h'], ['version', 'Version'], ['client_protocol', 'Protocol'], ['history', 'History']],
  x509: [['ts', 'When'], ['certificate.subject', 'Issued to'], ['certificate.issuer', 'Issued by'], ['certificate.not_valid_after', 'Expires'],
    ['certificate.key_type', 'Key', 'certificate.key_length'], ['san.dns', 'Names it covers']],
  files: [['ts', 'When'], ['source', 'Carried by'], ['mime_type', 'Type'], ['filename', 'Name'], ['seen_bytes', 'Size'], ['id.resp_h', 'Server'], ['sha256', 'SHA-256']],
  ssh: [['ts', 'When'], ['id.orig_h', 'From'], ['id.resp_h', 'To', 'id.resp_p'], ['client', 'Client'], ['server', 'Server'], ['auth_success', 'Logged in'],
    ['auth_attempts', 'Attempts'], ['kex_alg', 'Key exchange']],
  dhcp: [['ts', 'When'], ['mac', 'Device'], ['host_name', 'Name'], ['assigned_addr', 'Address given'], ['server_addr', 'DHCP server'], ['msg_types', 'Messages'],
    ['lease_time', 'Lease']],
  ftp: [['ts', 'When'], ['id.orig_h', 'From'], ['id.resp_h', 'Server'], ['user', 'User'], ['command', 'Command'], ['arg', 'Argument'], ['reply_code', 'Reply', 'reply_msg']],
  ntp: [['ts', 'When'], ['id.orig_h', 'From'], ['id.resp_h', 'To'], ['mode', 'Mode'], ['stratum', 'Stratum'], ['ref_id', 'Reference'], ['xmt_time', 'Their clock']],
  software: [['ts', 'When'], ['host', 'Host', 'host_p'], ['software_type', 'Kind'], ['name', 'Software'], ['unparsed_version', 'Version string']],
  known_hosts: [['ts', 'First seen'], ['host', 'Host']],
  known_services: [['ts', 'First seen'], ['host', 'Host'], ['port_num', 'Port', 'port_proto'], ['service', 'Service']],
  notice: [['ts', 'When'], ['note', 'Finding'], ['msg', 'Details'], ['src', 'Source'], ['dst', 'Destination', 'p']],
  weird: [['ts', 'When'], ['name', 'Oddity'], ['addl', 'Detail'], ['id.orig_h', 'From', 'id.orig_p'], ['id.resp_h', 'To', 'id.resp_p']],
};
const ZK_STATE = { S0: ['No answer', 'warn'], S1: ['Open', 'good'], SF: ['Normal', 'good'], REJ: ['Refused', 'bad'], S2: ['Closed by starter', 'good'],
  S3: ['Closed by answerer', 'good'], RSTO: ['Aborted by starter', 'warn'], RSTR: ['Aborted by answerer', 'warn'], RSTOS0: ['Gave up', 'warn'],
  RSTRH: ['Reset (no SYN)', 'warn'], SH: ['No answer', 'warn'], SHR: ['Answer only', ''], OTH: ['Mid-stream', ''] };
const ZK_STATE_TEXT = { S0: 'Connection attempt seen, no reply.', S1: 'Connection established, not closed.', SF: 'Normal: established and closed.',
  REJ: 'Connection attempt rejected (refused).', S2: 'Established; the starting side closed it, no reply to that.',
  S3: 'Established; the answering side closed it, no reply to that.', RSTO: 'Established, then the starting side aborted it (reset).',
  RSTR: 'The answering side aborted it (reset).', RSTOS0: 'The starting side sent a SYN then reset; never answered.',
  RSTRH: 'The answering side sent SYN-ACK then reset; no SYN seen.', SH: 'The starting side sent a SYN then a FIN; never answered.',
  SHR: 'Only the answering side was seen.', OTH: 'No handshake seen (caught mid-way, or not TCP).' };
const ZK_HIST = { s: 'sent a SYN (start)', h: 'answered with SYN-ACK', a: 'sent a bare acknowledgement', d: 'sent data', f: 'closed (FIN)',
  r: 'aborted (RST)', c: 'sent a packet with a bad checksum', g: 'had data missing from the capture', t: 'resent data (retransmission)',
  w: 'said its receive buffer was full (zero window)', i: 'sent FIN and RST together', q: 'sent an unusual flag combination' };
const ZK_HELP = {
  uid: 'Connection ID: every log line from the same conversation carries it.', conn_state: 'How the connection went (see Outcome).',
  history: 'The conversation step by step: capitals are the side that started it, small letters the side that answered.',
  service: 'The protocol recognised inside the connection (from its content, not just the port).', duration: 'From first to last packet.',
  orig_bytes: 'Data bytes sent by the side that started the connection.', resp_bytes: 'Data bytes sent back by the other side.',
  missed_bytes: 'Bytes the capture did not see (packets lost by the capture, not by the network).', local_orig: 'Is the starting side on a private (local) network?',
  local_resp: 'Is the answering side on a private (local) network?', orig_ip_bytes: 'Everything the starting side sent, headers included.',
  resp_ip_bytes: 'Everything the answering side sent, headers included.', community_id: 'Community ID: the same flow hash Suricata, Wireshark and Elastic use.',
  orig_l2_addr: 'Hardware (MAC) address of the starting side.', resp_l2_addr: 'Hardware (MAC) address of the answering side.',
  rtt: 'Time between the question and the answer.', rcode_name: 'NOERROR = fine, NXDOMAIN = the name does not exist, SERVFAIL = the server failed.',
  AA: 'The answer came from the server responsible for the name.', RA: 'The server does lookups on your behalf.', rejected: 'The server refused to answer.',
  server_name: 'The site name the client asked for (SNI).', established: 'The secure connection completed its handshake.',
  sni_matches_cert: 'The certificate covers the name that was asked for.', ja3: 'JA3 client fingerprint (MD5).', ja3s: 'JA3S server fingerprint (MD5).',
  ja4: 'JA4 client fingerprint: identifies the program making the connection.', resumed: 'An earlier secure session was reused.',
  cert_chain_fps: 'SHA-256 fingerprints of the certificates the server sent (see Certificates).', next_protocol: 'Protocol agreed inside the secure connection (h2 = HTTP/2).',
  auth_success: 'Guessed from packet sizes: SSH hides the login itself.', host_key_fingerprint: 'The server key, as ssh-keygen -l shows it.',
  'certificate.not_valid_after': 'Expiry date.', 'certificate.not_valid_before': 'Start of validity.', md5: 'MD5 of the file (for looking it up).',
  sha1: 'SHA-1 of the file.', sha256: 'SHA-256 of the file (for looking it up, e.g. on VirusTotal).', mime_type: 'File type, from its content.',
};
const zkDash = v => v === '-' || v === '(empty)' || v == null;
const zkUnesc = v => String(v).replace(/\\x([0-9a-fA-F]{2})/g, (m, h) => String.fromCharCode(parseInt(h, 16)));

function zkFmt(v, t, f) {
  if (zkDash(v)) return '';
  if (t === 'time') {
    const x = +v;
    if (!x) return '';
    if (f === 'ts' && ZK.t0 && ZK.span < 86400) return '+' + fmtDurS(Math.max(0, x - ZK.t0));
    return new Date(x * 1000).toLocaleString([], { dateStyle: 'medium', timeStyle: 'medium' });
  }
  if (t === 'interval') { const x = +v; return x < 1 ? `${(x * 1000).toFixed(x < 0.01 ? 2 : 1)} ms` : fmtDurS(x); }
  if (t === 'bool') return v === 'T' ? 'yes' : 'no';
  if (t === 'count' && /(bytes|_len|seen_bytes|file_size)$/.test(f)) return +v ? fmtBytes(+v) : '0';
  if (t.startsWith('set[') || t.startsWith('vector[')) return v.split(',').map(zkUnesc).join(', ');
  return zkUnesc(v);
}
function zkTitleTs(v) { return zkDash(v) ? '' : new Date(+v * 1000).toLocaleString([], { dateStyle: 'medium', timeStyle: 'medium' }); }
function zkHistory(h) {
  if (zkDash(h)) return '';
  const out = [];
  for (const ch of h) {
    if (ch === '^') { out.push('The direction was guessed: the start of the connection was not captured.'); continue; }
    const m = ZK_HIST[ch.toLowerCase()];
    if (m) out.push(`${ch}: the ${ch === ch.toLowerCase() ? 'answering' : 'starting'} side ${m}`);
  }
  return out.join('\n');
}

async function zkOpen(id) {
  ZK.id = id; ZK.summary = null; ZK.sel = null; ZK.uid = ''; ZK.q = ''; ZK.offset = 0; ZK.sort = ''; ZK.desc = false;
  $('#zkQ').value = ''; $('#zkCard').classList.remove('hidden'); $('#zkBody').classList.add('hidden'); $('#zkError').classList.add('hidden');
  $('#zkDetail').classList.add('hidden');
  const r = await api('/api/pcap/analysis?id=' + encodeURIComponent(id));
  if (r.error) { zkErr(r.error); return; }
  if (r.state === 'none' || r.state === 'cancelled') { const s = await api('/api/pcap/analyze', { id }); if (s.error) { zkErr(s.error); return; } zkApply(s); }
  else zkApply(r);
}
function zkErr(msg) { const e = $('#zkError'); e.textContent = msg; e.classList.remove('hidden'); $('#zkProgress').classList.add('hidden'); }
function zkApply(r) {
  ZK.state = r.state;
  const prog = $('#zkProgress');
  if (r.state === 'running') {
    prog.classList.remove('hidden');
    $('.bar', prog).style.width = Math.round((r.progress || 0) * 100) + '%';
    $('.msg', prog).textContent = `Analysing… ${(r.packets || 0).toLocaleString()} packets read`;
    if (!ZK.timer) ZK.timer = setInterval(zkPoll, 700);
    return;
  }
  clearInterval(ZK.timer); ZK.timer = null; prog.classList.add('hidden');
  if (r.state === 'error') { zkErr(r.error || 'The analysis failed.'); return; }
  if (r.state === 'done') { ZK.summary = r.summary; zkRender(); }
}
async function zkPoll() {
  if (!ZK.id) { clearInterval(ZK.timer); ZK.timer = null; return; }
  const id = ZK.id;
  const r = await api('/api/pcap/analysis?id=' + encodeURIComponent(id));
  if (id !== ZK.id || r.error) return;
  zkApply(r);
}
async function zkRender() {
  const s = ZK.summary; if (!s) return;
  ZK.t0 = (s.meta && s.meta.first) || 0;
  ZK.span = s.meta && s.meta.last && s.meta.first ? s.meta.last - s.meta.first : 0;
  $('#zkBody').classList.remove('hidden');
  const f = s.findings || {}; const nf = (f.bad || 0) + (f.warn || 0);
  $('#zkTiles').innerHTML = [
    tile('Connections', (s.counts.conn || 0).toLocaleString()),
    tile('Completed normally', s.tcpTotal ? `${s.tcpOk.toLocaleString()}<small>of ${s.tcpTotal.toLocaleString()} TCP</small>` : '—'),
    tile('Failed attempts', (s.tcpFailed || 0).toLocaleString(), s.tcpFailed ? 'warn' : 'good'),
    tile('Devices', String(s.hosts || 0)), tile('Sites', String((s.sites || []).length)),
    tile('Findings', nf ? String(nf) : 'none', f.bad ? 'bad' : nf ? 'warn' : 'good'),
    tile('Analysis took', `${s.meta.seconds}<small>s</small>`)].join('');
  // outcome bar
  const st = s.states || []; const tot = st.reduce((a, x) => a + x.count, 0);
  const col = k => ({ good: 'var(--good)', warn: 'var(--warn)', bad: 'var(--bad)' }[(ZK_STATE[k] || [])[1]] || 'var(--soft)');
  $('#zkStates').innerHTML = tot ? `<div class="protobar" title="Connection outcomes">${st.map(x => `<span style="width:${Math.max(0.5, x.count / tot * 100)}%;background:${col(x.state)}" title="${esc(x.state)}: ${x.count} (${esc(x.text)})"></span>`).join('')}</div>` +
    `<div class="protolegend">${st.map(x => `<span class="zk-state" data-s="${esc(x.state)}" title="${esc(x.text)}"><i style="background:${col(x.state)}"></i>${esc((ZK_STATE[x.state] || [x.state])[0])} <span class="soft">${esc(x.state)}</span> ${x.count.toLocaleString()}</span>`).join('')}</div>` : '';
  $$('#zkStates .zk-state').forEach(el => el.onclick = () => zkShow('conn', { q: el.dataset.s }));
  // findings
  const nr = await api(`/api/pcap/log?id=${encodeURIComponent(ZK.id)}&log=notice&limit=200`);
  ZK.findings = [];
  if (!nr.error) {
    const fi = nr.fields.indexOf('note'), mi = nr.fields.indexOf('msg'), ti = nr.fields.indexOf('ts');
    ZK.findings = nr.rows.map((row, i) => ({ note: row[fi], msg: zkUnesc(row[mi]), ts: row[ti], ...(nr.extra[i] || {}) }));
  }
  const order = { bad: 0, warn: 1, info: 2 };
  ZK.findings.sort((a, b) => (order[a._severity] ?? 1) - (order[b._severity] ?? 1));
  const LIM = 6; const many = ZK.findings.length > LIM + 1;
  $('#zkFindings').innerHTML = ZK.findings.length ? ZK.findings.map((x, i) =>
    `<div class="zk-find ${esc(x._severity || 'warn')}"><div class="zk-ico">${x._severity === 'bad' ? '!' : x._severity === 'info' ? 'i' : '▲'}</div>` +
    `<div><div class="m">${esc(x.msg)}</div><div class="t">${esc(x._plain || '')}</div><div class="soft zk-note">${esc(x.note)} · ${esc(zkFmt(x.ts, 'time', 'ts'))}</div></div>` +
    `<div>${x._filter ? `<button class="btn small" data-i="${i}">Show</button>` : ''}</div></div>`.replace('<div class="zk-find', `<div${many && i >= LIM ? ' hidden' : ''} class="zk-find`)).join('') +
    (many ? `<button class="btn small" id="zkMoreFind">Show ${ZK.findings.length - LIM} more</button>` : '')
    : '<p class="hint" style="margin:4px 0">Nothing unusual: no failing connections, weak encryption, cleartext passwords, scans or address conflicts were found.</p>';
  const mf = $('#zkMoreFind'); if (mf) mf.onclick = () => { $$('#zkFindings .zk-find[hidden]').forEach(el => el.hidden = false); mf.remove(); };
  $$('#zkFindings button[data-i]').forEach(b => b.onclick = () => { const flt = ZK.findings[+b.dataset.i]._filter || {}; flt.uid ? zkShow('conn', { uid: flt.uid }) : zkShow(flt.log || 'conn', { q: flt.q || '' }); });
  // lists
  $('#zkSites').innerHTML = (s.sites || []).length ? `<table class="table zk-mini"><tbody>${s.sites.map(x => `<tr data-q="${esc(x.name)}" data-log="${x.how.includes('HTTPS') ? 'ssl' : x.how.includes('QUIC') ? 'quic' : 'http'}"><td>${esc(x.name)}<span class="sub">${esc(x.how.join(', '))} · ${x.conns} connection${x.conns === 1 ? '' : 's'}</span></td><td class="num">${fmtBytes(x.bytes)}</td></tr>`).join('')}</tbody></table>` : '<p class="hint">No web or secure connections.</p>';
  $('#zkQueries').innerHTML = (s.queries || []).length ? `<table class="table zk-mini"><tbody>${s.queries.map(x => `<tr data-q="${esc(x.name)}" data-log="dns"><td>${esc(x.name)}${x.nx ? ' <span class="pill pill-bad" style="font-size:11px">does not exist</span>' : ''}</td><td class="num">${x.count}×</td></tr>`).join('')}</tbody></table>` : '<p class="hint">No DNS lookups.</p>';
  $('#zkFails').innerHTML = (s.failures || []).length ? `<table class="table zk-mini"><tbody>${s.failures.map(x => `<tr data-q="${esc(x.host)}" data-log="conn"><td class="mono">${esc(x.host)}:${x.port}<span class="sub">${x.state === 'REJ' ? 'refused' : 'no answer'}</span></td><td class="num">${x.count}×</td></tr>`).join('')}</tbody></table>` : '<p class="hint">Every TCP connection got an answer.</p>';
  $$('#zkBody .zk-mini tr[data-q]').forEach(tr => tr.onclick = () => zkShow(tr.dataset.log, { q: tr.dataset.q }));
  // log chips
  const c = s.counts || {};
  $('#zkLogs').innerHTML = '<span class="presets-label">Show</span>' + ZK_LOGS.filter(([k]) => c[k] || k === 'conn').map(([k, label]) =>
    `<button class="chip${k === ZK.log ? ' on' : ''}" data-log="${k}" title="${k}.log">${esc(label)} <small>${(c[k] || 0).toLocaleString()}</small></button>`).join('');
  $$('#zkLogs .chip').forEach(b => b.onclick = () => zkShow(b.dataset.log, { q: ZK.q, uid: ZK.uid, keep: true }));
  if (!c[ZK.log]) ZK.log = 'conn';
  zkPage();
}
function zkShow(log, o = {}) {
  ZK.log = log; ZK.offset = 0; ZK.sort = ''; ZK.desc = false;
  if (!o.keep) { ZK.q = o.q || ''; ZK.uid = o.uid || ''; $('#zkQ').value = ZK.q; }
  $$('#zkLogs .chip').forEach(b => b.classList.toggle('on', b.dataset.log === log));
  $('#zkDetail').classList.add('hidden');
  zkPage();
  $('#zkLogs').scrollIntoView({ behavior: 'smooth', block: 'start' });
}
async function zkPage() {
  if (!ZK.id || !ZK.summary) return;
  const qs = new URLSearchParams({ id: ZK.id, log: ZK.log, q: ZK.q, uid: ZK.uid, offset: ZK.offset, limit: 200, sort: ZK.sort, desc: ZK.desc ? '1' : '0' });
  const r = await api('/api/pcap/log?' + qs);
  if (r.error) { toast(r.error); return; }
  ZK.data = r;
  const idx = {}; r.fields.forEach((f, i) => idx[f] = i);
  const cols = ZK.all ? r.fields.map(f => [f, f]) : (ZK_COLS[ZK.log] || r.fields.map(f => [f, f]));
  const th = cols.map(([f, h]) => `<th class="sortable${ZK.sort === f ? ' sorted' + (ZK.desc ? '' : ' asc') : ''}" data-f="${esc(f)}" title="${esc(f)}${ZK_HELP[f] ? ': ' + esc(ZK_HELP[f]) : ''}">${esc(h)}</th>`).join('');
  $('#zkTable thead').innerHTML = `<tr>${th}</tr>`;
  $$('#zkTable th.sortable').forEach(el => el.onclick = () => { const f = el.dataset.f; if (ZK.sort === f) ZK.desc = !ZK.desc; else { ZK.sort = f; ZK.desc = f === 'ts' ? false : true; } ZK.offset = 0; zkPage(); });
  const cell = (row, f, f2) => {
    const i = idx[f]; if (i === undefined) return '<td></td>';
    const t = r.types[i]; const v = row[i];
    let html;
    if (f === 'conn_state' && !zkDash(v)) { const [label, cls] = ZK_STATE[v] || [v, '']; html = `<span class="zk-st ${cls}" title="${esc(ZK_STATE_TEXT[v] || '')}">${esc(label)}</span><span class="sub">${esc(v)}</span>`; }
    else if (f === 'history' && !zkDash(v)) html = `<span class="mono" title="${esc(zkHistory(v))}">${esc(v)}</span>`;
    else if (f === 'ts') html = `<span title="${esc(zkTitleTs(v))}">${esc(zkFmt(v, t, f))}</span>`;
    else { const s = zkFmt(v, t, f); html = esc(s.length > 140 ? s.slice(0, 140) + '…' : s); }
    if (f2 && idx[f2] !== undefined && !zkDash(row[idx[f2]])) html += `<span class="sub">${esc(zkFmt(row[idx[f2]], r.types[idx[f2]], f2))}</span>`;
    const mono = /(^id\.|_h$|addr$|^host$|^src$|^dst$|mac$|sha|md5|ja[34]|fingerprint)/.test(f) ? ' class="mono"' : '';
    return `<td${mono}>${html}</td>`;
  };
  $('#zkTable tbody').innerHTML = r.rows.map((row, n) => `<tr data-n="${n}" class="${ZK.sel === n ? 'sel' : ''}">${cols.map(([f, , f2]) => cell(row, f, ZK.all ? null : f2)).join('')}</tr>`).join('') ||
    `<tr><td colspan="${cols.length}" class="hint">Nothing in this log${ZK.q || ZK.uid ? ' matches' : ''}.</td></tr>`;
  const from = r.total ? ZK.offset + 1 : 0, to = Math.min(ZK.offset + 200, r.total);
  $('#zkPageInfo').textContent = r.total ? `${from.toLocaleString()}–${to.toLocaleString()} of ${r.total.toLocaleString()} lines in ${ZK.log}.log` : `${ZK.log}.log`;
  $('#zkPrev').disabled = ZK.offset === 0; $('#zkNext').disabled = to >= r.total;
  const up = $('#zkUid');
  if (ZK.uid) { up.innerHTML = `Only connection ${esc(ZK.uid)} <button class="linkbtn" title="Show all">✕</button>`; up.classList.remove('hidden'); $('button', up).onclick = () => { ZK.uid = ''; ZK.offset = 0; zkPage(); $('#zkPivotChips').innerHTML = ''; }; }
  else up.classList.add('hidden');
}
function zkRowObj(n) {
  const r = ZK.data; if (!r || !r.rows[n]) return null;
  const o = {}; r.fields.forEach((f, i) => o[f] = r.rows[n][i]); return o;
}
async function zkDetail(n) {
  ZK.sel = n;
  $$('#zkTable tbody tr').forEach(tr => tr.classList.toggle('sel', +tr.dataset.n === n));
  const r = ZK.data; const o = zkRowObj(n); if (!o) return;
  const title = { conn: `${o['id.orig_h']} → ${o['id.resp_h']}:${o['id.resp_p']}`, dns: o.query, http: `${o.method || ''} ${o.host || ''}${o.uri || ''}`,
    ssl: o.server_name !== '-' ? o.server_name : o['id.resp_h'], x509: o['certificate.subject'], files: o.filename !== '-' ? o.filename : o.mime_type,
    notice: o.note, weird: o.name }[ZK.log] || `${ZK.log}.log line`;
  $('#zkDetailTitle').textContent = zkUnesc(title || '');
  $('#zkDetailBody').innerHTML = `<div class="kv">${r.fields.map((f, i) => {
    const v = o[f]; if (zkDash(v)) return '';
    let shown = zkFmt(v, r.types[i], f); if (f === 'ts' || r.types[i] === 'time') shown = zkTitleTs(v);
    let note = ZK_HELP[f] || '';
    if (f === 'conn_state') note = ZK_STATE_TEXT[v] || note;
    if (f === 'history') note = zkHistory(v).split('\n').join(' · ');
    return `<div class="k mono">${esc(f)}</div><div class="mono zk-val">${esc(shown)}${shown !== zkUnesc(v) && !['time', 'bool'].includes(r.types[i]) ? ` <span class="soft">(${esc(zkUnesc(v))})</span>` : ''}</div><div class="note">${esc(note)}</div>`;
  }).join('')}</div>`;
  const uid = o.uid && !zkDash(o.uid) ? o.uid : null;
  $('#zkPivot').classList.toggle('hidden', !uid);
  $('#zkPackets').classList.toggle('hidden', !(o['id.orig_h'] && !zkDash(o['id.orig_h'])));
  $('#zkPivotChips').innerHTML = '';
  $('#zkDetail').classList.remove('hidden');
}
async function zkPivot() {
  const o = zkRowObj(ZK.sel); if (!o || zkDash(o.uid)) return;
  const uid = o.uid; const box = $('#zkPivotChips');
  box.innerHTML = '<span class="hint">Looking…</span>';
  const logs = ZK_LOGS.map(([k]) => k).filter(k => !['software', 'known_hosts', 'known_services'].includes(k) && (ZK.summary.counts[k] || 0));
  const res = await Promise.all(logs.map(k => api(`/api/pcap/log?${new URLSearchParams({ id: ZK.id, log: k, uid, limit: 1 })}`)));
  const hits = logs.map((k, i) => [k, res[i].total || 0]).filter(([, n]) => n);
  box.innerHTML = '<span class="presets-label">Connection ' + esc(uid) + ' appears in</span>' + hits.map(([k, n]) =>
    `<button class="chip" data-log="${k}">${esc((ZK_LOGS.find(x => x[0] === k) || [k, k])[1])} <small>${n}</small></button>`).join('');
  $$('.chip', box).forEach(b => b.onclick = () => zkShow(b.dataset.log, { uid }));
}
function zkPackets() {
  const o = zkRowObj(ZK.sel); if (!o) return;
  const proto = o.proto || '';
  const ports = ZK.log === 'conn' ? (proto === 'tcp' || proto === 'udp') : !zkDash(o['id.resp_p']) && ZK.log !== 'weird';
  const t0 = +o.ts || 0; const dur = zkDash(o.duration) ? 0 : +o.duration;
  const spec = [o['id.orig_h'], ports ? o['id.orig_p'] : '', o['id.resp_h'], ports ? o['id.resp_p'] : '', ZK.log === 'conn' ? t0 : '', ZK.log === 'conn' ? t0 + dur : ''].join('|');
  PC.filter = { proto: '', host: '', port: '', q: '', conn: spec };
  $('#pcFHost').value = ''; $('#pcFPort').value = ''; $('#pcFQ').value = '';
  $$('#pcFilterProto .chip').forEach(c => c.classList.toggle('on', c.dataset.b === ''));
  PC.offset = 0; pcPage();
  $('#pcViewCard').scrollIntoView({ behavior: 'smooth', block: 'start' });
}
async function zkSaveZip(format) {
  if (!ZK.id) return;
  const r = await api('/api/pcap/logs-export', { id: ZK.id, format });
  if (r.error) { toast(r.error); return; }
  if (r.cancelled) return;
  if (r.b64) {
    const bin = atob(r.b64); const buf = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
    const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([buf], { type: 'application/zip' })); a.download = r.name;
    document.body.appendChild(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 500);
  } else if (r.path) toast('Saved to ' + r.path);
}
function wireZeek() {
  $('#zkRerun').onclick = async () => { if (!ZK.id) return; $('#zkBody').classList.add('hidden'); const r = await api('/api/pcap/analyze', { id: ZK.id, force: true }); if (r.error) zkErr(r.error); else zkApply(r); };
  $('#zkSaveZeek').onclick = () => zkSaveZip('zeek');
  $('#zkSaveJson').onclick = () => zkSaveZip('json');
  $('#zkSaveLog').onclick = async () => { const r = await api(`/api/pcap/log-text?${new URLSearchParams({ id: ZK.id, log: ZK.log })}`); if (r.error) toast(r.error); else download(r.name, r.text, 'text/plain'); };
  let t;
  $('#zkQ').addEventListener('input', () => { clearTimeout(t); t = setTimeout(() => { ZK.q = $('#zkQ').value.trim(); ZK.offset = 0; zkPage(); }, 250); });
  $('#zkAll').onchange = () => { ZK.all = $('#zkAll').checked; zkPage(); };
  $('#zkPrev').onclick = () => { ZK.offset = Math.max(0, ZK.offset - 200); zkPage(); };
  $('#zkNext').onclick = () => { ZK.offset += 200; zkPage(); };
  $('#zkTable').addEventListener('click', ev => { const tr = ev.target.closest('tr[data-n]'); if (tr) zkDetail(+tr.dataset.n); });
  $('#zkDetailClose').onclick = () => { $('#zkDetail').classList.add('hidden'); ZK.sel = null; $$('#zkTable tr.sel').forEach(x => x.classList.remove('sel')); };
  $('#zkPivot').onclick = zkPivot;
  $('#zkPackets').onclick = zkPackets;
}

/* release notes */
function mdToHtml(md) {
  const lines = md.split('\n'); let html = ''; let inList = false;
  const inline = s => esc(s).replace(/`([^`]+)`/g, '<code>$1</code>').replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>');
  for (const raw of lines) {
    const l = raw.trimEnd();
    if (/^\s*[-*] /.test(l)) { if (!inList) { html += '<ul>'; inList = true; } html += `<li>${inline(l.replace(/^\s*[-*] /, ''))}</li>`; continue; }
    if (inList && /^\s{2,}\S/.test(l)) { html = html.replace(/<\/li>$/, ' ' + inline(l.trim()) + '</li>'); continue; }
    if (inList) { html += '</ul>'; inList = false; }
    if (/^# /.test(l)) html += `<h1>${inline(l.slice(2))}</h1>`;
    else if (/^## /.test(l)) html += `<h2>${inline(l.slice(3))}</h2>`;
    else if (/^### /.test(l)) html += `<h3>${inline(l.slice(4))}</h3>`;
    else if (l.trim()) html += `<p>${inline(l)}</p>`;
  }
  if (inList) html += '</ul>';
  return html;
}
async function showNotes() {
  const r = await api('/api/changelog');
  $('#notesBody').innerHTML = r.error ? `<p class="hint">${esc(r.error)}</p>` : mdToHtml(r.markdown || '');
  $('#notesDialog').showModal();
}

function wireCapture() {
  $('#pcIface').onchange = pcIfaceChanged;
  $$('#pcProto button').forEach(b => b.onclick = () => pcSetProto(b.dataset.v));
  $$('#pcDuration button').forEach(b => b.onclick = () => pcSetDuration(b.dataset.v));
  ['pcHost', 'pcPort'].forEach(id => $('#' + id).addEventListener('input', pcFilterText));
  $('#pcStart').onclick = pcStart;
  $('#pcStop').onclick = pcStop;
  $('#pcViewClose').onclick = () => { $('#pcViewCard').classList.add('hidden'); $('#zkCard').classList.add('hidden'); ZK.id = null; };
  $('#pcViewRename').onclick = async () => { const name = prompt('Name for this recording', PC.view ? PC.view.name : ''); if (name != null && PC.viewId) { const r = await api('/api/pcap/rename', { id: PC.viewId, name }); if (!r.error) { PC.view.name = r.capture.name; $('#pcViewTitle').textContent = r.capture.name; pcList(); } } };
  $('#pcViewCsv').onclick = async () => { const f = PC.filter; const qs = new URLSearchParams({ id: PC.viewId, proto: f.proto, host: f.host, port: f.port, q: f.q, conn: f.conn || '' }); const r = await api('/api/pcap/csv?' + qs); if (r.error) toast(r.error); else download(r.name, r.text, 'text/csv'); };
  $('#pcViewSave').onclick = async () => { const r = await api('/api/pcap/export', { id: PC.viewId }); if (r.ok) toast('Saved to ' + r.path); else if (r.error === 'not-windowed') toast('The file is at ' + r.path); else if (r.error) toast(r.error); };
  $('#pcViewWireshark').onclick = async () => { const r = await api('/api/pcap/wireshark', { id: PC.viewId }); if (r.error) toast(r.error); };
  $$('#pcFilterProto .chip').forEach(c => c.onclick = () => { $$('#pcFilterProto .chip').forEach(x => x.classList.toggle('on', x === c)); PC.filter.proto = c.dataset.b; PC.filter.conn = ''; PC.offset = 0; pcPage(); });
  let ft;
  const applyF = () => { clearTimeout(ft); ft = setTimeout(() => { PC.filter.host = $('#pcFHost').value.trim(); PC.filter.port = $('#pcFPort').value.trim(); PC.filter.q = $('#pcFQ').value.trim(); PC.filter.conn = ''; PC.offset = 0; pcPage(); }, 250); };
  ['pcFHost', 'pcFPort', 'pcFQ'].forEach(id => $('#' + id).addEventListener('input', applyF));
  $('#pcFClear').onclick = () => { $('#pcFHost').value = ''; $('#pcFPort').value = ''; $('#pcFQ').value = ''; $$('#pcFilterProto .chip').forEach(x => x.classList.toggle('on', x.dataset.b === '')); PC.filter = { proto: '', host: '', port: '', q: '', conn: '' }; PC.offset = 0; pcPage(); };
  $('#pcPrev').onclick = () => { PC.offset = Math.max(0, PC.offset - 500); pcPage(); };
  $('#pcNext').onclick = () => { PC.offset += 500; pcPage(); };
  $('#pcViewTable').addEventListener('click', ev => { const tr = ev.target.closest('tr[data-n]'); if (tr) pcDetail(+tr.dataset.n); });
  $('#pcDetailClose').onclick = () => { $('#pcDetail').classList.add('hidden'); PC.sel = null; $$('#pcViewTable tr.sel').forEach(t => t.classList.remove('sel')); };
  $('#pcFollow').onclick = pcFollow;
  $('#pcImport').onclick = async () => { const r = await api('/api/pcap/import', {}); if (r.error === 'not-windowed') { const p = prompt('Path of the .pcap or .pcapng file'); if (p) { const r2 = await api('/api/pcap/open', { path: p }); if (r2.error) toast(r2.error); else { pcList(); pcOpen(r2.capture.id); } } } else if (r.error) toast(r.error); else if (r.ok) { pcList(); pcOpen(r.capture.id); } };
  wireZeek();
  $('#verPill').onclick = showNotes;
  $('#notesClose').onclick = () => $('#notesDialog').close();
}

/* ------------------------------------------------------------------------ */
/* Wi-Fi scanner                                                            */
/* ------------------------------------------------------------------------ */
const WF = { rows: [], sel: new Set(), band: 'all', sortKey: 'rssi', sortAsc: false, timer: null, hist: {}, win: 300, showStale: false, connected: null, hint: {}, autoSel: true, paused: false, focus: null, lastScan: 0, colors: new Map(), hover: null, filter: { text: '', minRssi: null, hideHidden: false, overlapMine: false } };
const BAND_RANGES = { '2.4': [2400, 2495], '5': [5150, 5895], '6': [5925, 7135] };
// One colour per network for the whole session (charts, table swatch, legend, history lines).
function wfColor(r) {
  const b = typeof r === 'string' ? r : (r && r.bssid) || '';
  if (r && typeof r === 'object' && r.connected) return cssVar('--accent');
  if (!WF.colors.has(b)) WF.colors.set(b, WF_COLORS[WF.colors.size % WF_COLORS.length]);
  return WF.colors.get(b);
}
const WF_COLORS = ['#0b6ef5', '#1a9e5c', '#ef8a1c', '#9b59b6', '#d63b3b', '#00a6a6', '#c7a300', '#e67e22', '#3cc47c', '#4d8ff7', '#f06060', '#7f8c8d'];

function wfEnsure() {
  if (WF.timer || WF.paused) { wfRenderToggle(); return; }
  api('/api/wifi/start', {}).then(r => { if (r.error) { $('#wfError').textContent = r.error; $('#wfError').classList.remove('hidden'); } });
  WF.timer = setInterval(wfPoll, 1000); wfPoll(); wfRenderToggle();
}
function wfLeave() {
  if (WF.timer) { clearInterval(WF.timer); WF.timer = null; }
  api('/api/wifi/stop', {});
}
function wfRenderToggle() {
  const b = $('#wfToggle');
  b.textContent = WF.paused ? 'Start scanning' : 'Stop scanning';
  b.classList.toggle('stop', !WF.paused); b.classList.toggle('primary', WF.paused);
  b.style.color = WF.paused ? '' : '#fff';
}
function wfToggle() {
  WF.paused = !WF.paused;
  if (WF.paused) { wfLeave(); $('#wfIface').textContent = `Scanning stopped${WF.lastScan ? ` · last scan ${fmtClock(WF.lastScan)}` : ''}. The results below stay as they were.`; }
  else wfEnsure();
  wfRenderToggle();
}
async function wfPoll() {
  const r = await api('/api/wifi/state');
  if (r.error && !r.rows) return;
  WF.rows = r.rows || []; WF.connected = r.connected; WF.hint = r.hint || {}; WF.lastScan = r.lastScan || WF.lastScan;
  const err = $('#wfError');
  if (r.error) { err.textContent = r.error; err.classList.remove('hidden'); } else err.classList.add('hidden');
  if (!WF.paused) $('#wfIface').textContent = r.iface && r.iface.desc ? `Adapter: ${r.iface.desc}${r.iface.radioOn === false ? ' (radio off)' : ''} · ${r.scans ? `scan ${r.scans}, ` : ''}every ${r.interval || 5} s` : (r.backend ? '' : 'Looking for a Wi‑Fi adapter…');
  if (WF.autoSel && WF.connected && WF.connected.bssid) { WF.sel.add(WF.connected.bssid); WF.autoSel = false; }
  wfRenderConnected(); wfRenderTable(); wfRenderCharts(); wfRenderDetail();
  await wfRenderHistory();
}
function wfShowDetail(bssid) {
  WF.focus = bssid;
  wfRenderDetail(); wfRenderTable(); wfRenderCharts();
  const card = $('#wfDetail'); card.classList.remove('hidden'); card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  const tr = $(`#wfTable tr[data-b="${bssid}"]`); if (tr) tr.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}
function wfRenderDetail() {
  const card = $('#wfDetail');
  if (!WF.focus) { card.classList.add('hidden'); return; }
  const r = WF.rows.find(x => x.bssid === WF.focus);
  if (!r) { card.classList.add('hidden'); return; }
  $('#wfDetailTitle').innerHTML = `<i class="sw" style="background:${wfColor(r)}"></i>${esc(wfName(r))}`;
  $('#wfDetailBadges').innerHTML = (r.connected ? '<span class="pill pill-good">connected</span> ' : '') + (r.stale ? '<span class="pill pill-muted">not heard recently</span>' : '');
  $('#wfDetailSub').textContent = `${r.bssid}${r.vendor ? ` · ${r.vendor}` : (parseInt(r.bssid.slice(0, 2), 16) & 2 ? ' · private (randomised) address' : '')}`;
  const half = (r.widthMHz || 20) / 2;
  const now = Date.now() / 1000, ago = Math.max(0, now - (r.seenAt || now));
  $('#wfDetailTiles').innerHTML = [
    tile('Signal', `${r.rssi != null ? Math.round(r.rssi) + ' dBm' : '—'}<small>${esc(r.signalWord || '')}${r.quality != null ? ` · ${r.quality}%` : ''}</small>`, r.rssi == null ? '' : r.rssi >= -60 ? 'good' : r.rssi >= -75 ? 'warn' : 'bad'),
    tile('Channel', `${r.channel != null ? r.channel : '—'}<small>${r.band ? r.band + ' GHz' : ''}${r.freqMHz ? ` · ${r.freqMHz} MHz` : ''}</small>`),
    tile('Width', `${r.widthMHz || 20} MHz<small>${r.centerMHz ? `${r.centerMHz - half}–${r.centerMHz + half} MHz` : ''}</small>`),
    tile('Security', esc(r.security || '—'), r.security === 'Open' || r.security === 'WEP' ? 'warn' : ''),
    tile('Standard', r.phy ? `802.11${esc(r.phy)}<small>${esc(r.phyWord || '')}</small>` : '—'),
    tile('Busy', r.utilization != null ? `${r.utilization}%<small>reported by the access point</small>` : '—<small>not reported</small>'),
    tile('Last heard', ago < 8 ? 'now' : ago < 60 ? `${Math.round(ago)} s ago` : `${Math.round(ago / 60)} min ago`),
    tile('Top speed', r.maxRate ? `${Math.round(r.maxRate)}<small>Mbps (advertised basic rates)</small>` : '—'),
  ].join('');
  const overl = WF.rows.filter(x => x.bssid !== r.bssid && !x.stale && x.band === r.band && x.centerMHz && r.centerMHz &&
    Math.abs(x.centerMHz - r.centerMHz) < ((x.widthMHz || 20) + (r.widthMHz || 20)) / 2);
  const strong = overl.filter(x => x.rssi != null && x.rssi >= -65).length;
  let reading;
  if (!overl.length) reading = 'Nothing else overlaps this network’s channel: it has the air to itself here.';
  else if (strong) reading = `${overl.length} network${overl.length === 1 ? '' : 's'} share this air time, ${strong} of them strong; they take turns talking, which slows everyone down.`;
  else reading = `${overl.length} network${overl.length === 1 ? '' : 's'} overlap this channel but all are weak here, so the effect is small.`;
  $('#wfDetailOverlap').innerHTML = `<p>${esc(reading)}</p>` + (overl.length ? '<ul>' + overl.sort((a, b) => (b.rssi || -100) - (a.rssi || -100)).slice(0, 10).map(x =>
    `<li><a href="#" data-b="${esc(x.bssid)}">${esc(wfName(x))}</a> · channel ${x.channel} · ${x.widthMHz} MHz · ${x.rssi != null ? Math.round(x.rssi) + ' dBm' : '—'}${x.connected ? ' · yours' : ''}</li>`).join('') + '</ul>' : '');
  $$('#wfDetailOverlap a').forEach(a => a.onclick = ev => { ev.preventDefault(); wfShowDetail(a.dataset.b); });
  $('#wfDetailPlot').textContent = WF.sel.has(r.bssid) ? 'Stop plotting' : 'Plot signal';
  card.classList.remove('hidden');
}
function sigBars(rssi) {
  const n = rssi == null ? 0 : rssi >= -55 ? 4 : rssi >= -65 ? 3 : rssi >= -75 ? 2 : 1;
  return `<span class="sigbars s${n} ${n <= 2 ? 'weak' : ''}"><i></i><i></i><i></i><i></i></span>`;
}
function wfName(r) { return r.hidden || !r.ssid ? '(hidden network)' : r.ssid; }
function wfRenderConnected() {
  const c = WF.connected; const box = $('#wfConnected');
  if (!c || !c.bssid) { box.classList.add('hidden'); return; }
  box.classList.remove('hidden');
  box.innerHTML = `<span>Connected to <b>${esc(c.ssid || c.profile || c.bssid)}</b></span>` +
    (c.rssi != null ? `<span>${sigBars(c.rssi)}<span class="sig">${Math.round(c.rssi)} dBm</span> ${esc(c.signalWord || '')}</span>` : '') +
    (c.band ? `<span>${esc(c.band)} GHz · channel ${c.channel} · ${c.widthMHz} MHz wide</span>` : '') +
    (c.security ? `<span>${esc(c.security)}</span>` : '') + (c.phy ? `<span>802.11${esc(c.phy)}${c.phyWord ? ` (${esc(c.phyWord)})` : ''}</span>` : '') +
    (c.rxMbps ? `<span>link ${Math.round(c.rxMbps)} Mbps</span>` : '') + `<span class="mono hint">${esc(c.bssid)}</span>`;
}
function wfOverlapsMine(r) {
  const m = WF.connected; if (!m || !m.bssid) return true;
  if (r.bssid === m.bssid) return true;
  if (!m.centerMHz || !r.centerMHz || r.band !== m.band) return false;
  return Math.abs(r.centerMHz - m.centerMHz) < ((r.widthMHz || 20) + (m.widthMHz || 20)) / 2;
}
function wfVisible() {
  // The one place that decides what the table, the channel charts and the legend chips show.
  const f = WF.filter; const q = (f.text || '').trim().toLowerCase();
  return WF.rows.filter(r => (WF.band === 'all' || r.band === WF.band) && (WF.showStale || !r.stale)
    && (!q || wfName(r).toLowerCase().includes(q) || (r.bssid || '').toLowerCase().includes(q) || (r.vendor || '').toLowerCase().includes(q))
    && (f.minRssi == null || r.connected || (r.rssi != null && r.rssi >= f.minRssi))
    && (!f.hideHidden || !(r.hidden || !r.ssid))
    && (!f.overlapMine || wfOverlapsMine(r)));
}
function wfFiltersActive() { const f = WF.filter; return !!((f.text || '').trim() || f.minRssi != null || f.hideHidden || f.overlapMine); }
let wfFilterSaveTimer = null;
function wfApplyFilters(save = true) {
  wfRenderTable(); wfRenderCharts();
  $('#wfFClear').classList.toggle('on', wfFiltersActive());
  if (save) { clearTimeout(wfFilterSaveTimer); wfFilterSaveTimer = setTimeout(() => api('/api/settings', { patch: { wifiFilters: WF.filter, wifiShowStale: WF.showStale } }), 400); }
}
function wfLoadFilters() {
  const f = T.settings.wifiFilters || {};
  WF.filter = { text: f.text || '', minRssi: f.minRssi == null ? null : +f.minRssi, hideHidden: !!f.hideHidden, overlapMine: !!f.overlapMine };
  WF.showStale = !!T.settings.wifiShowStale;
  $('#wfFText').value = WF.filter.text; $('#wfFMin').value = WF.filter.minRssi == null ? '' : String(WF.filter.minRssi);
  $('#wfFHidden').checked = WF.filter.hideHidden; $('#wfFOverlap').checked = WF.filter.overlapMine; $('#wfShowStale').checked = WF.showStale;
  $('#wfFClear').classList.toggle('on', wfFiltersActive());
}
function wfRenderTable() {
  const rows = wfVisible().slice();
  const k = WF.sortKey, dir = WF.sortAsc ? 1 : -1;
  rows.sort((a, b) => {
    let va = a[k], vb = b[k];
    if (k === 'ssid') { va = wfName(a).toLowerCase(); vb = wfName(b).toLowerCase(); }
    if (va == null && vb == null) return 0; if (va == null) return 1; if (vb == null) return -1;
    if (typeof va === 'string') { va = va.toLowerCase(); vb = String(vb).toLowerCase(); }
    return va < vb ? -dir : va > vb ? dir : 0;
  });
  $$('#wfTable th.sortable').forEach(th => { th.classList.toggle('sorted', th.dataset.k === k); th.classList.toggle('asc', th.dataset.k === k && WF.sortAsc); });
  const now = Date.now() / 1000;
  $('#wfTable tbody').innerHTML = rows.map(r => {
    const ago = Math.max(0, now - (r.seenAt || now));
    return `<tr data-b="${esc(r.bssid)}" class="${r.connected ? 'conn' : ''} ${r.stale ? 'stale' : ''} ${WF.focus === r.bssid ? 'sel' : ''} ${WF.hover === r.bssid ? 'hl' : ''}">` +
      `<td><input type="checkbox" data-b="${esc(r.bssid)}" ${WF.sel.has(r.bssid) ? 'checked' : ''}></td>` +
      `<td class="ssid"><i class="sw" style="background:${wfColor(r)}"></i>${esc(wfName(r))}${r.connected ? ' <span class="pill pill-good" style="font-size:11px">connected</span>' : ''}<span class="sub mono">${esc(r.bssid)}</span></td>` +
      `<td>${sigBars(r.rssi)}${r.rssi != null ? Math.round(r.rssi) + ' dBm' : '—'}<span class="sub">${esc(r.signalWord || '')}${r.utilization != null ? ` · ${r.utilization}% busy` : ''}</span></td>` +
      `<td>${r.channel != null ? r.channel : '—'}<span class="sub">${r.band ? r.band + ' GHz' : ''}${r.freqMHz ? ` · ${r.freqMHz} MHz` : ''}</span></td>` +
      `<td>${r.widthMHz ? r.widthMHz + ' MHz' : '—'}</td><td>${esc(r.security || '')}</td>` +
      `<td>${r.phy ? '802.11' + esc(r.phy) : ''}${r.phyWord ? `<span class="sub">${esc(r.phyWord)}</span>` : ''}</td>` +
      `<td>${esc(r.vendor || (r.bssid && (parseInt(r.bssid.slice(0, 2), 16) & 2) ? 'private address' : ''))}</td>` +
      `<td>${ago < 8 ? 'now' : ago < 60 ? `${Math.round(ago)} s ago` : `${Math.round(ago / 60)} min ago`}</td></tr>`;
  }).join('');
  $$('#wfTable input[type=checkbox]').forEach(cb => cb.onchange = () => { if (cb.checked) WF.sel.add(cb.dataset.b); else WF.sel.delete(cb.dataset.b); wfRenderHistory(); });
  const live = WF.rows.filter(r => !r.stale).length;
  { const total = WF.rows.filter(r => WF.showStale || !r.stale).length; $('#wfCount').textContent = rows.length === total ? `Networks (${total})` : `Networks · ${rows.length} of ${total} shown`; }
  $('#wfEmpty').textContent = WF.rows.length && !rows.length ? 'No networks match the filters. Press Clear filters to see everything again.' : 'Scanning… networks appear within a few seconds.'; $('#wfEmpty').classList.toggle('hidden', rows.length > 0);
  if (!rows.length && WF.rows.length) $('#wfEmpty').textContent = 'No networks on this band.';
}
function wfRenderCharts() {
  const box = $('#wfCharts');
  const bands = WF.band === 'all' ? ['2.4', '5', '6'] : [WF.band];
  const live = wfVisible().filter(r => !r.stale && r.centerMHz && r.band);
  const want = bands.filter(b => live.some(r => r.band === b) || (WF.band !== 'all'));
  // create/remove canvases as needed
  const have = [...box.querySelectorAll('.wfchart')].map(d => d.dataset.band);
  if (have.join() !== want.join()) {
    box.innerHTML = want.map(b => `<div class="wfchart" data-band="${b}"><div class="lbl">${b} GHz</div><canvas height="210"></canvas><div class="wflegend"></div></div>`).join('');
  }
  for (const b of want) {
    const div = box.querySelector(`.wfchart[data-band="${b}"]`); if (!div) continue;
    const rows = live.filter(r => r.band === b);
    drawChannelChart(div.querySelector('canvas'), b, rows);
    // legend chips (strongest first): hover = highlight the shape, click = details
    div.querySelector('.wflegend').innerHTML = rows.slice().sort((a, c) => (c.rssi || -100) - (a.rssi || -100)).map(r =>
      `<button type="button" class="wfchip ${WF.hover === r.bssid ? 'hl' : ''} ${WF.focus === r.bssid ? 'sel' : ''}" data-b="${esc(r.bssid)}" style="--c:${wfColor(r)}" title="${esc(r.bssid)}"><i></i>${esc(wfName(r))} · ch ${r.channel != null ? r.channel : '?'}${r.rssi != null ? ` · ${Math.round(r.rssi)} dBm` : ''}</button>`).join('');
  }
  const hints = [];
  for (const b of bands) {
    const h = WF.hint[b]; if (!h) continue;
    const mine = WF.connected && WF.connected.band === b ? WF.connected : null;
    let t = `${b} GHz: the quietest channel is ${h.channel}` + (h.networks ? ` (${h.networks} network${h.networks === 1 ? '' : 's'} overlap it)` : ' (nothing else on it)');
    if (mine && mine.channel != null) {
      const sharing = live.filter(r => r.band === b && !r.connected && Math.abs(r.centerMHz - mine.centerMHz) < (r.widthMHz + mine.widthMHz) / 2).length;
      t += `. Your network uses channel ${mine.channel}${sharing ? ` and overlaps ${sharing} other${sharing === 1 ? '' : 's'}` : ' with nothing overlapping it'}.`;
    }
    hints.push(t);
  }
  $('#wfHint').textContent = hints.join(' ');
  if (!live.length) $('#wfHint').textContent = '';
}
function drawChannelChart(canvas, band, rows) {
  if (!canvas.dataset.h) canvas.dataset.h = canvas.getAttribute('height') || '170';
  const dpr = window.devicePixelRatio || 1; const W = canvas.clientWidth || 800, H = parseInt(canvas.dataset.h) || 170;
  canvas.style.height = H + 'px'; canvas.width = Math.round(W * dpr); canvas.height = Math.round(H * dpr);
  const ctx = canvas.getContext('2d'); ctx.scale(dpr, dpr);
  const padL = 48, padR = 10, padT = 22, padB = 22; const pw = W - padL - padR, ph = H - padT - padB;
  ctx.clearRect(0, 0, W, H);
  const [f0, f1] = BAND_RANGES[band]; const xOf = f => padL + (f - f0) / (f1 - f0) * pw;
  const yMin = -100, yMax = -30; const yOf = r => padT + ph - (Math.max(yMin, Math.min(yMax, r)) - yMin) / (yMax - yMin) * ph;
  ctx.font = '11px system-ui, sans-serif'; ctx.textBaseline = 'middle';
  for (const g of [-90, -70, -50]) { const y = yOf(g); ctx.strokeStyle = cssVar('--line'); ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(W - padR, y); ctx.stroke(); ctx.fillStyle = cssVar('--soft'); ctx.textAlign = 'right'; ctx.fillText(`${g} dBm`, padL - 6, y); }
  // channel ticks
  ctx.textAlign = 'center'; ctx.fillStyle = cssVar('--soft');
  const ticks = band === '2.4' ? [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13] : band === '5' ? [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165, 169, 173, 177] : [1, 17, 33, 49, 65, 81, 97, 113, 129, 145, 161, 177, 193, 209, 225];
  const base = band === '2.4' ? 2407 : band === '5' ? 5000 : 5950;
  const every = Math.max(1, Math.ceil(ticks.length / Math.floor(pw / 34)));
  ticks.forEach((ch, i) => { const f = ch === 14 ? 2484 : base + 5 * ch; const x = xOf(f); ctx.strokeStyle = cssVar('--line'); ctx.beginPath(); ctx.moveTo(x, padT + ph); ctx.lineTo(x, padT + ph + 3); ctx.stroke(); if (i % every === 0) ctx.fillText(String(ch), x, H - padB / 2); });
  canvas._band = band; canvas._rows = rows;
  const hovered = WF.hover && rows.some(r => r.bssid === WF.hover) ? WF.hover : null;
  const dim = !!hovered; // fade everything except the network under the mouse
  let sorted = rows.slice().sort((a, b) => (a.rssi || -100) - (b.rssi || -100)); // weakest first so strong ones draw on top
  if (hovered) sorted = sorted.filter(r => r.bssid !== hovered).concat(sorted.filter(r => r.bssid === hovered)); // hovered last = on top
  const placed = []; // label boxes already drawn, to stagger overlapping names
  canvas._shapes = [];
  let tip = null;
  sorted.forEach(r => {
    const color = wfColor(r);
    const isHover = r.bssid === hovered;
    const half = (r.widthMHz || 20) / 2; const lo = r.centerMHz - half, hi = r.centerMHz + half;
    const yTop = yOf(r.rssi == null ? -95 : r.rssi), yBase = padT + ph;
    const inset = Math.min(8, (xOf(hi) - xOf(lo)) * 0.15);
    const focused = WF.focus === r.bssid;
    canvas._shapes.push({ bssid: r.bssid, x0: xOf(lo), x1: xOf(hi), yTop, yBase, inset });
    ctx.beginPath(); ctx.moveTo(xOf(lo), yBase); ctx.lineTo(xOf(lo) + inset, yTop); ctx.lineTo(xOf(hi) - inset, yTop); ctx.lineTo(xOf(hi), yBase); ctx.closePath();
    const fillA = isHover ? '73' : dim ? '14' : focused ? '66' : r.connected ? '55' : '22';
    ctx.fillStyle = color + fillA; ctx.fill();
    ctx.strokeStyle = focused ? cssVar('--text') : color + (dim && !isHover ? '66' : '');
    ctx.lineWidth = focused || isHover ? 2.5 : r.connected ? 2 : 1.5; ctx.stroke();
    const label = wfName(r); const cx = (xOf(lo) + xOf(hi)) / 2;
    const narrow = (xOf(hi) - xOf(lo)) < 28 && !isHover && !focused && !r.connected;
    if (!narrow) {
      const text = label.length > 18 ? label.slice(0, 17) + '…' : label;
      ctx.font = (r.connected || focused || isHover ? 'bold ' : '') + '11px system-ui, sans-serif'; ctx.textAlign = 'center';
      const tw = ctx.measureText(text).width;
      let ly = yTop - 9, clash = true;
      for (let guard = 0; guard < 8 && ly >= 6; guard++) {
        clash = placed.some(p => Math.abs(p.y - ly) < 11 && Math.abs(p.x - cx) < (p.w + tw) / 2 + 6);
        if (!clash) break;
        ly -= 11;
      }
      // No free spot: leave the label off rather than print over another one (hover/chips still name it).
      if (!clash || isHover || focused || r.connected) {
        placed.push({ x: cx, y: ly, w: tw });
        ctx.fillStyle = dim && !isHover ? cssVar('--soft') : r.connected ? cssVar('--accent') : cssVar('--text');
        ctx.fillText(text, cx, Math.max(6, ly));
      }
    }
    if (isHover) tip = { r, color, x: canvas._hoverPt ? canvas._hoverPt.x : cx, y: canvas._hoverPt ? canvas._hoverPt.y : yTop };
  });
  if (tip) {
    // tooltip near the cursor (or above the shape when the hover came from the table/legend)
    const r = tip.r;
    const lines = [wfName(r), `channel ${r.channel != null ? r.channel : '?'} · ${r.widthMHz || 20} MHz · ${r.rssi != null ? Math.round(r.rssi) + ' dBm' : '—'}${r.signalWord ? ` (${r.signalWord})` : ''}`];
    const extra = [r.security, r.vendor || (r.bssid && (parseInt(r.bssid.slice(0, 2), 16) & 2) ? 'private address' : '')].filter(Boolean).join(' · ');
    if (extra) lines.push(extra);
    ctx.font = '11.5px system-ui, sans-serif'; ctx.textAlign = 'left'; ctx.textBaseline = 'top';
    const tw = Math.max(...lines.map((l, i) => { ctx.font = (i ? '' : 'bold ') + '11.5px system-ui, sans-serif'; return ctx.measureText(l).width; }));
    const bw = tw + 16, bh = lines.length * 15 + 10;
    let bx = tip.x + 14, by = tip.y - bh - 10;
    if (bx + bw > W - 4) bx = tip.x - bw - 14; if (bx < 4) bx = 4;
    if (by < 2) by = Math.min(H - bh - 2, tip.y + 18);
    ctx.fillStyle = cssVar('--card'); ctx.strokeStyle = tip.color; ctx.lineWidth = 1.5;
    roundRect(ctx, bx, by, bw, bh, 6); ctx.fill(); ctx.stroke();
    lines.forEach((l, i) => { ctx.font = (i ? '' : 'bold ') + '11.5px system-ui, sans-serif'; ctx.fillStyle = i ? cssVar('--muted') : cssVar('--text'); ctx.fillText(l, bx + 8, by + 5 + i * 15); });
    ctx.textBaseline = 'middle';
  }
  if (!rows.length) { ctx.fillStyle = cssVar('--soft'); ctx.textAlign = 'center'; ctx.font = '12.5px system-ui, sans-serif'; ctx.fillText('No networks heard on this band', padL + pw / 2, padT + ph / 2); }
}
async function wfRenderHistory() {
  const canvas = $('#wfHistory'); const ids = [...WF.sel];
  const legend = $('#wfLegend');
  if (!ids.length) { legend.innerHTML = ''; drawSignalHistory(canvas, {}, []); return; }
  const r = await api('/api/wifi/history?bssid=' + encodeURIComponent(ids.join(',')));
  if (r.error) return;
  WF.hist = r.history || {};
  const byId = Object.fromEntries(WF.rows.map(x => [x.bssid, x]));
  legend.innerHTML = ids.map(b => `<span class="lg" data-b="${esc(b)}" title="Click to stop plotting"><i style="background:${wfColor(byId[b] || b)}"></i>${esc(byId[b] ? wfName(byId[b]) : b)}${byId[b] && byId[b].rssi != null ? ` ${Math.round(byId[b].rssi)} dBm` : ''}</span>`).join('');
  drawSignalHistory(canvas, WF.hist, ids);
}
function drawSignalHistory(canvas, hist, ids) {
  if (!canvas.dataset.h) canvas.dataset.h = canvas.getAttribute('height') || '180';
  const dpr = window.devicePixelRatio || 1; const W = canvas.clientWidth || 800, H = parseInt(canvas.dataset.h) || 180;
  canvas.style.height = H + 'px'; canvas.width = Math.round(W * dpr); canvas.height = Math.round(H * dpr);
  const ctx = canvas.getContext('2d'); ctx.scale(dpr, dpr);
  const padL = 52, padR = 10, padT = 8, padB = 18; const pw = W - padL - padR, ph = H - padT - padB;
  ctx.clearRect(0, 0, W, H);
  const now = Date.now() / 1000, start = now - WF.win;
  const yMin = -100, yMax = -30; const yOf = r => padT + ph - (Math.max(yMin, Math.min(yMax, r)) - yMin) / (yMax - yMin) * ph; const xOf = t => padL + (t - start) / WF.win * pw;
  ctx.font = '11px system-ui, sans-serif'; ctx.textBaseline = 'middle';
  for (const g of [-100, -90, -80, -70, -60, -50, -40, -30]) { const y = yOf(g); ctx.strokeStyle = cssVar('--line'); ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(W - padR, y); ctx.stroke(); ctx.fillStyle = cssVar('--soft'); ctx.textAlign = 'right'; ctx.fillText(`${g} dBm`, padL - 6, y); }
  ids.forEach((b, i) => {
    const pts = (hist[b] || []).filter(p => p[0] >= start); if (!pts.length) return;
    ctx.strokeStyle = wfColor(WF.rows.find(x => x.bssid === b) || b); ctx.lineWidth = 1.8; ctx.lineJoin = 'round'; ctx.beginPath();
    pts.forEach((p, k) => { const x = xOf(p[0]), y = yOf(p[1]); if (k === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y); });
    ctx.stroke();
  });
  ctx.fillStyle = cssVar('--soft'); ctx.textAlign = 'center';
  const n = Math.max(2, Math.floor(pw / 90));
  for (let i = 0; i <= n; i++) { const t = start + WF.win * i / n; ctx.fillText(i === n ? 'now' : fmtClock(t), xOf(t), H - padB / 2); }
  if (!ids.length) { ctx.font = '12.5px system-ui, sans-serif'; ctx.fillText('Tick a network above to plot its signal', padL + pw / 2, padT + ph / 2); }
}
function wfRedrawChart(c) { if (c && c._band) drawChannelChart(c, c._band, c._rows || []); }
function wfSetHover(b) {
  // Highlight one network everywhere: its chart shape (others fade), its legend chip and its table row.
  if (b === WF.hover) return;
  WF.hover = b || null;
  $$('#wfCharts canvas').forEach(c => { if (!WF.hover) c._hoverPt = null; wfRedrawChart(c); });
  $$('#wfCharts .wfchip').forEach(ch => ch.classList.toggle('hl', ch.dataset.b === WF.hover));
  $$('#wfTable tr[data-b]').forEach(tr => tr.classList.toggle('hl', tr.dataset.b === WF.hover));
}
function wfShapeAt(canvas, ev) {
  const rect = canvas.getBoundingClientRect();
  const x = ev.clientX - rect.left, y = ev.clientY - rect.top;
  const shapes = canvas._shapes || [];
  for (let i = shapes.length - 1; i >= 0; i--) { // last drawn = strongest = on top
    const s = shapes[i];
    if (y < s.yTop || y > s.yBase) continue;
    const t = (s.yBase - y) / Math.max(1, s.yBase - s.yTop); // 0 at base, 1 at top
    const lo = s.x0 + s.inset * t, hi = s.x1 - s.inset * t;
    if (x >= lo && x <= hi) return s.bssid;
  }
  return null;
}
function wireWifi() {
  $$('#wfBand button').forEach(b => b.onclick = () => { WF.band = b.dataset.v; $$('#wfBand button').forEach(x => x.classList.toggle('on', x === b)); wfRenderTable(); wfRenderCharts(); });
  $('#wfToggle').onclick = wfToggle;
  $('#wfCharts').addEventListener('click', ev => {
    const chip = ev.target.closest('.wfchip'); if (chip) { wfShowDetail(chip.dataset.b); return; }
    const c = ev.target.closest('canvas'); if (!c) return; const b = wfShapeAt(c, ev); if (b) wfShowDetail(b);
  });
  $('#wfCharts').addEventListener('mousemove', ev => {
    const c = ev.target.closest('canvas'); if (!c) return;
    const b = wfShapeAt(c, ev); c.classList.toggle('hover', !!b);
    const rect = c.getBoundingClientRect(); c._hoverPt = { x: ev.clientX - rect.left, y: ev.clientY - rect.top };
    if (b !== WF.hover) wfSetHover(b); else if (b) wfRedrawChart(c); // keep the tooltip beside the cursor
  });
  $('#wfCharts').addEventListener('mouseleave', () => wfSetHover(null));
  $('#wfCharts').addEventListener('mouseover', ev => { const chip = ev.target.closest('.wfchip'); if (chip) wfSetHover(chip.dataset.b); });
  $('#wfCharts').addEventListener('mouseout', ev => { const chip = ev.target.closest('.wfchip'); if (chip && !ev.relatedTarget?.closest?.('.wfchip')) wfSetHover(null); });
  $('#wfTable').addEventListener('mouseover', ev => { const tr = ev.target.closest('tr[data-b]'); if (tr) wfSetHover(tr.dataset.b); });
  $('#wfTable').addEventListener('mouseleave', () => wfSetHover(null));
  $('#wfDetailClose').onclick = () => { WF.focus = null; $('#wfDetail').classList.add('hidden'); wfRenderTable(); wfRenderCharts(); };
  $('#wfDetailPlot').onclick = () => { if (!WF.focus) return; if (WF.sel.has(WF.focus)) WF.sel.delete(WF.focus); else WF.sel.add(WF.focus); wfRenderTable(); wfRenderDetail(); wfRenderHistory(); };
  $('#wfCsv').onclick = async () => { const r = await api('/api/wifi/csv'); if (r.error) toast(r.error); else download(r.name, r.text, 'text/csv'); };
  $('#wfShowStale').onchange = e => { WF.showStale = e.target.checked; wfApplyFilters(); };
  $('#wfFText').addEventListener('input', e => { WF.filter.text = e.target.value; wfApplyFilters(); });
  $('#wfFMin').onchange = e => { WF.filter.minRssi = e.target.value === '' ? null : +e.target.value; wfApplyFilters(); };
  $('#wfFHidden').onchange = e => { WF.filter.hideHidden = e.target.checked; wfApplyFilters(); };
  $('#wfFOverlap').onchange = e => { WF.filter.overlapMine = e.target.checked; wfApplyFilters(); };
  $('#wfFClear').onclick = () => { WF.filter = { text: '', minRssi: null, hideHidden: false, overlapMine: false }; $('#wfFText').value = ''; $('#wfFMin').value = ''; $('#wfFHidden').checked = false; $('#wfFOverlap').checked = false; wfApplyFilters(); };
  $('#wfPlotAll').onclick = () => { wfVisible().filter(r => !r.stale).sort((a, b) => (b.rssi || -100) - (a.rssi || -100)).slice(0, 12).forEach(r => WF.sel.add(r.bssid)); WF.autoSel = false; wfRenderTable(); wfRenderHistory(); };
  $('#wfPlotClear').onclick = () => { WF.sel.clear(); WF.autoSel = false; wfRenderTable(); wfRenderHistory(); wfRenderDetail(); };
  $('#wfLegend').addEventListener('click', ev => { const lg = ev.target.closest('.lg'); if (!lg) return; WF.sel.delete(lg.dataset.b); wfRenderTable(); wfRenderHistory(); wfRenderDetail(); });
  $$('#wfTable th.sortable').forEach(th => th.onclick = () => { if (WF.sortKey === th.dataset.k) WF.sortAsc = !WF.sortAsc; else { WF.sortKey = th.dataset.k; WF.sortAsc = th.dataset.k === 'ssid' || th.dataset.k === 'channel' || th.dataset.k === 'vendor' || th.dataset.k === 'security'; } wfRenderTable(); });
  $$('#wfWin button').forEach(b => b.onclick = () => { WF.win = +b.dataset.w; $$('#wfWin button').forEach(x => x.classList.toggle('on', x === b)); wfRenderHistory(); });
  window.addEventListener('resize', () => { if (T.tab === 'wifi') { wfRenderCharts(); drawSignalHistory($('#wfHistory'), WF.hist, [...WF.sel]); } });
}

/* ------------------------------------------------------------------------ */
/* Wiring                                                                   */
/* ------------------------------------------------------------------------ */
function wireTools() {
  $$('#tabs button').forEach(b => b.onclick = () => showTab(b.dataset.tab));
  document.addEventListener('click', ensureAudio, { once: true });
  // scan
  $('#scanStart').onclick = () => SC.running ? scanStop() : scanStart();
  $('#scanRange').addEventListener('keydown', e => { if (e.key === 'Enter' && !SC.running) scanStart(); });
  $$('#portPresets button').forEach(b => b.onclick = () => scanApplyPreset(b.dataset.p));
  $('#scanPorts').addEventListener('input', scanPresetReflect);
  $('#scanRange').addEventListener('input', scanSettingsSum);
  wireCollapsibles();
  $('#scanAliveOnly').onchange = scanRender;
  $('#scanCsv').onclick = async () => { const r = await api('/api/scan/csv'); if (r.error) toast(r.error); else download(r.name, r.text, 'text/csv'); };
  $$('#scanTable th.sortable').forEach(th => th.onclick = () => { if (SC.sortKey === th.dataset.k) SC.sortAsc = !SC.sortAsc; else { SC.sortKey = th.dataset.k; SC.sortAsc = true; } scanRender(); });
  $('#scanTable').addEventListener('click', ev => {
    const b = ev.target.closest('button[data-act]'); if (!b) return;
    const ip = b.closest('tr').dataset.ip; const h = SC.hosts.get(ip) || {};
    if (b.dataset.act === 'watch') { showTab('pings'); $('#pingHost').value = ip; $('#pingLabel').value = h.hostname ? h.hostname.split('.')[0] : (h.vendor || ''); pmAdd(); }
    else if (b.dataset.act === 'arp') { $('#arpQ').value = ip; arpLookup(); $('#arpCard').scrollIntoView({ behavior: 'smooth', block: 'start' }); }
    else if (b.dataset.act === 'dns') { showTab('dns'); $('#dnsName').value = ip; dnsEnsureServers().then(dnsLookup); }
  });
  $('#scanUseNet').onclick = () => { const v = $('#scanNets').value; if (v) { $('#scanRange').value = v; toast(`Range set to ${v}`); } };
  // ARP / MAC tools
  $('#arpRefresh').onclick = arpLoad;
  $('#arpFilter').addEventListener('input', arpRender);
  $('#arpGo').onclick = arpLookup;
  $$('#arpCard [data-cmd]').forEach(b => b.onclick = () => arpRunCmd(b.dataset.cmd));
  $$('#arpCard [data-copy]').forEach(b => b.onclick = () => copyText(arpCmdText(b.dataset.copy), 'Command copied'));
  ['arpDelIp', 'arpAddIp', 'arpAddMac'].forEach(id => $('#' + id).addEventListener('input', arpRenderCmds));
  $('#arpOutCopy').onclick = () => copyText($('#arpOut').textContent, 'Output copied');
  $('#arpQ').addEventListener('input', () => { if (!$('#arpDelIp').value) { const v = $('#arpQ').value.trim(); if (/^\d+\.\d+\.\d+\.\d+$/.test(v)) { $('#arpDelIp').placeholder = v; } } });
  $('#arpQ').addEventListener('keydown', e => { if (e.key === 'Enter') arpLookup(); });
  $('#arpCsv').onclick = () => {
    const rows = AR.rows; if (!rows.length) { toast('Nothing to save yet'); return; }
    const csv = 'ip,mac,vendor,mac_type,entry,connection,hostname,in_last_scan\n' + rows.map(r => [r.ip, r.mac, r.vendor || '', r.macKind, r.kind, r.iface || '', r.hostname || '', r.inScan ? 'yes' : 'no'].map(v => `"${String(v).replace(/"/g, "'")}"`).join(',')).join('\n') + '\n';
    download(`LinkTest-arp-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.csv`, csv, 'text/csv');
  };
  // pings
  $('#pingAdd').onclick = pmAdd;
  $('#pingHost').addEventListener('keydown', e => { if (e.key === 'Enter') pmAdd(); });
  $('#pingHost').addEventListener('input', pmKindUI);
  $('#pingKind').onchange = pmKindUI;
  $('#pingPort').addEventListener('keydown', e => { if (e.key === 'Enter') pmAdd(); });
  $('#pingInterval').onchange = () => { $('#pingInterval').dataset.userSet = '1'; };
  $('#pingLabel').addEventListener('keydown', e => { if (e.key === 'Enter') pmAdd(); });
  $('#pingCollapseAll').onclick = () => pmCollapseAll(true);
  $('#pingExpandAll').onclick = () => pmCollapseAll(false);
  pmWireDragTarget();
  wireCapture();
  wireWifi();
  // dns
  $('#dnsGo').onclick = dnsLookup;
  $('#dnsName').addEventListener('keydown', e => { if (e.key === 'Enter') dnsLookup(); });
  $('#dnsAddServer').onclick = () => {
    const v = $('#dnsCustom').value.trim(); if (!v) return;
    if (!/^[0-9a-fA-F.:]+$/.test(v)) { toast('Enter the server as an IP address, e.g. 10.0.0.1'); return; }
    if (!DN.custom.includes(v) && !DN.presets.some(p => p.ip === v)) DN.custom.push(v);
    DN.selected.add(v); $('#dnsCustom').value = ''; dnsRenderChips();
  };
  $('#dnsCustom').addEventListener('keydown', e => { if (e.key === 'Enter') $('#dnsAddServer').click(); });
  window.addEventListener('resize', () => { if (T.tab === 'pings') PM.order.forEach(id => PM.t[id] && PM.t[id].el && !PM.t[id].stats.collapsed && pmUpdate(id, true)); });
}

async function initTools() {
  wireTools();
  const st = await api('/api/settings');
  T.settings = st.settings || {};
  wfLoadFilters(); applyCollapsed();
  showTab(T.settings.lastTab || 'speed', false);
  api('/api/status').then(st => { if (st.app) $('#verPill').textContent = 'v' + st.app.version; });
  await pmLoad();
}
initTools();
