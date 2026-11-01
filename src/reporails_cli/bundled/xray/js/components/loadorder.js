// part: turns, runs, start, harness, first_context, not_known, art, tokMax, starts, promptNo.
// ctx: sel, selTurn, openTurns, startOpen, text.
import { k1, tk, clock, dur, plural } from '../format.js';
import { el, row, tpl, slot, svg } from '../dom.js';
import { artByPath, nameOf } from '../model.js';
import { textBlock } from './textblock.js';

const KIND_WORD = { project: 'project instructions', memory: 'auto memory', user: 'your user instructions', local: 'local instructions', managed: 'managed instructions', nested: 'loaded because a file in that folder was read' };

// One line of the load order. `name` is a list of nodes or strings; `o.data` is a [name, value] data attribute that makes it clickable.
function orow(part, t, dot, name, why, tok, o = {}) {
  const r = row('t-or');
  if (o.data) { r.classList.add('link'); r.dataset[o.data[0]] = o.data[1]; }
  if (o.on) r.classList.add('on');
  slot(r, 'time').textContent = t == null ? '' : clock(t);
  slot(r, 'dot').classList.add(dot);
  const nm = slot(r, 'name');
  nm.title = o.title || '';
  nm.append(...name);
  const w = slot(r, 'why');
  if (o.whyCls) w.classList.add(o.whyCls);
  w.title = why;
  w.textContent = why;
  slot(r, 'num').textContent = tok ? k1(tok) : '';
  const bar = slot(r, 'bar');
  if (o.barCls) bar.classList.add(o.barCls);
  bar.style.width = (tok ? Math.max(3, Math.round(Math.min(1, tok / part.tokMax) * 100)) : 0) + '%';
  return r;
}

const nameCell = text => { const s = el('span', 'p', text); return [s]; };

function dline(mark, color, name, what, whatColor) {
  const d = row('t-dl');
  const m = slot(d, 'mark');
  m.textContent = mark;
  m.style.color = color;
  slot(d, 'name').textContent = name;
  const w = slot(d, 'what');
  w.textContent = what;
  if (whatColor) w.style.color = whatColor;
  return d;
}

const at = t => t != null ? 'at ' + clock(t) + ' · ' : '';

function agentDetail(r, part, ctx) {
  const loads = r.sb.loads || [], first = loads.filter(l => l.kind !== 'nested'), later = loads.filter(l => l.kind === 'nested');
  const d = el('div', 'detail');
  const dm = el('div', 'dm', (r.turn != null ? `started in turn ${r.turn}` : 'start turn not known') + (r.start != null ? ` at ${clock(r.start)}` : '') + (r.start != null && r.end != null ? `, ran ${dur(r.end - r.start)}` : ''));
  const head = (title, count) => { const h = el('h4', null, title); h.append(el('span', null, String(count))); return h; };
  d.append(dm, head('Started with', first.length || 'nothing'));
  if (first.length) d.append(...first.map(l => dline('+', 'var(--green)', nameOf(part, l.path), tk(l.tokens_est, true))));
  else d.append(dline('✕', 'var(--red)', 'CLAUDE.md', 'not given', 'var(--red)'));
  if (later.length) d.append(head('Loaded during its run', later.length), ...later.map(l => dline('+', 'var(--green)', nameOf(part, l.path), at(l.t) + tk(l.tokens_est, true))));
  const ran = r.sb.skill_runs || [];
  if (ran.length) d.append(head('Skills it ran', ran.length), ...ran.map(x => dline('+', 'var(--green)', x.name, at(x.t) + (x.forked ? 'in its own subagent' : tk(x.tokens_est, true)))));
  const ser = r.pts;
  if (ser.length > 1) {
    const mx = Math.max(1, ...ser.map(p => p[1]));
    const h = head('Its context', '');
    h.firstElementChild.textContent = `${k1(ser[0][1])} → ${k1(ser[ser.length - 1][1])}, peak ${k1(mx)}`;
    const spk = svg('svg', { class: 'spk', viewBox: '0 0 300 46', preserveAspectRatio: 'none' });
    spk.append(svg('path', { class: 'a', d: `M0 46 ${ser.map((p, i) => `L${(i / (ser.length - 1) * 300).toFixed(1)} ${(46 - p[1] / mx * 42).toFixed(1)}`).join(' ')} L300 46Z` }));
    d.append(h, spk);
  }
  d.append(el('h4', null, 'Its brief'), textBlock(ctx, 'b:' + r.id, 'brief?subagent=' + encodeURIComponent(r.id)));
  return d;
}

function loadRow(part, l, t) {
  const a = artByPath(part, l.path);
  return orow(part, l.t != null ? l.t : t, 'g', nameCell(nameOf(part, l.path)), KIND_WORD[l.kind] || l.kind, l.tokens_est, { data: a ? ['file', a.key] : null, title: l.path });
}

function runRow(part, r, t) {
  const a = r.path ? artByPath(part, r.path) : null;
  return orow(part, r.t != null ? r.t : t, 'g', nameCell(r.name), r.forked ? 'ran in a subagent' : 'ran', r.forked ? 0 : r.tokens_est, { data: a ? ['file', a.key] : null, title: r.path || r.name });
}

function groupNotes(notes) {
  const g = new Map();
  notes.forEach(n => {
    const k = n.kind + '|' + n.label;
    const e = g.get(k) || { ...n, count: 0, tokens_est: 0 };
    e.count++;
    e.tokens_est += n.tokens_est || 0;
    g.set(k, e);
  });
  return [...g.values()];
}

function subagentRow(part, r, ctx) {
  const on = ctx.sel && ctx.sel.run === r.id;
  const open = el('a', 'open', `${on ? 'close' : 'open'} ›`);
  const why = r.miss ? 'started without CLAUDE.md' : 'its own context' + (r.start != null && r.end != null ? `, ran ${dur(r.end - r.start)}` : '');
  const line = orow(part, r.start, r.miss ? 'r' : 'v', [`${r.type} subagent `, open], why, r.pts.length ? Math.max(...r.pts.map(p => p[1])) : 0, { data: ['run', r.id], barCls: 'a', whyCls: r.miss ? 'red' : '', on });
  return on ? [line, agentDetail(r, part, ctx)] : [line];
}

function turnRows(part, t, i, ctx) {
  const out = el('div', 'tb');
  const t0 = part.starts[i];
  const prompts = t.prompts || [];
  prompts.forEach(p => {
    const on = ctx.sel && ctx.sel.prompt === p.id;
    const r = row('t-prompt');
    if (on) r.classList.add('on');
    r.dataset.prompt = p.id;
    slot(r, 'time').textContent = clock(p.t);
    slot(r, 'no').textContent = String(part.promptNo.get(p.id));
    slot(r, 'what').textContent = `${p.queued ? 'queued prompt' : 'your prompt'} · ${p.chars.toLocaleString('en')} chars`;
    slot(r, 'open').textContent = `${on ? 'close' : 'open'} ›`;
    out.append(r);
    if (on) { const d = el('div', 'detail'); d.append(textBlock(ctx, 't:' + p.id, 'prompt?id=' + encodeURIComponent(p.id))); out.append(d); }
  });
  (t.loads || []).forEach(l => out.append(loadRow(part, l, t0)));
  (t.skill_runs || []).forEach(r => out.append(runRow(part, r, t0)));
  const notes = t.notes || [];
  groupNotes(notes.filter(n => n.kind === 'hook_note')).forEach(n => out.append(orow(part, n.t, 'm', [`${n.label} hook note${n.count > 1 ? ' ×' + n.count : ''}`], `added by your ${n.event} hook`, n.tokens_est)));
  groupNotes(notes.filter(n => n.kind === 'stop_block')).forEach(n => out.append(orow(part, n.t, 'a', [`Stop hook sent the reply back${n.count > 1 ? ' ×' + n.count : ''}`], 'its message is added each time', n.tokens_est, { whyCls: 'warn', barCls: 's' })));
  (t.subagents || []).forEach(id => {
    const r = part.runs.find(x => x.id === String(id));
    if (r) out.append(...subagentRow(part, r, ctx));
  });
  if (t.compaction) {
    const c = t.compaction;
    out.append(orow(part, c.t, 'a', [`/compact${c.trigger ? ' (' + c.trigger + ')' : ''}`], c.before != null && c.after != null ? `context ${k1(c.before)} → ${k1(c.after)}` : '', 0, { whyCls: 'warn' }));
  }
  const empty = !(t.loads || []).length && !(t.skill_runs || []).length && !notes.length && !(t.subagents || []).length && !t.compaction && !prompts.length;
  if (empty) out.append(row('t-or-mute'));
  return out;
}

function startRows(part) {
  const out = el('div', 'tb');
  part.start.forEach(l => out.append(loadRow(part, l, 0)));
  part.harness.forEach(x => {
    const note = x.kind === 'hook_note';
    out.append(orow(part, x.t != null ? x.t : 0, note ? 'm' : 'g', [x.label + (note ? ' hook note' : '') + (x.count != null ? ` · ${x.count}` : '')], note ? 'added by your hook' : 'Claude Code', x.tokens_est));
  });
  return out;
}

function turnHead(part, t, i, delta, ctx) {
  const open = ctx.openTurns.has(t.n);
  const h = row('t-turn');
  if (open) h.classList.add('on');
  if (ctx.selTurn === t.n) h.classList.add('selt');
  h.dataset.turnh = String(t.n);
  h.id = 'turn-' + t.n;
  h.querySelector('.cv').textContent = open ? '▾' : '▸';
  const tg = slot(h, 'tag');
  tg.textContent = `turn ${t.n}`;
  if (t.compaction) tg.classList.add('cmp');
  slot(h, 'start').textContent = clock(part.starts[i]);
  const prompts = t.prompts || [], no = id => part.promptNo.get(id);
  slot(h, 'label').textContent = prompts.length ? (prompts.length > 1 ? `your prompts ${no(prompts[0].id)}–${no(prompts[prompts.length - 1].id)}` : `your prompt ${no(prompts[0].id)}`) : 'no prompt of yours';
  const stops = (t.notes || []).filter(x => x.kind === 'stop_block').length;
  const rt = slot(h, 'rt');
  if (stops) rt.append(el('em', 'st', `${stops} Stop`));
  if (t.compaction) rt.append(el('em', 'st', '/compact'));
  rt.append(plural(t.replies, 'reply', 'replies') + (delta != null ? ` · ${delta >= 0 ? '+' : '−'}${k1(Math.abs(delta))}` : ''));
  return h;
}

export function render(box, part, ctx) {
  box.replaceChildren(tpl('t-order'));
  slot(box, 'expand').textContent = ctx.openTurns.size ? 'Collapse all' : 'Expand all';
  const st = slot(box, 'start');
  if (ctx.startOpen) st.classList.add('on');
  st.querySelector('.cv').textContent = ctx.startOpen ? '▾' : '▸';
  slot(box, 'first').textContent = part.first_context != null ? k1(part.first_context) + ' at the first reply' : '';
  if (ctx.startOpen) box.append(startRows(part));
  let prev = part.first_context;
  part.turns.forEach((t, i) => {
    const delta = t.context != null && prev != null ? t.context - prev : null;
    if (t.context != null) prev = t.context;
    box.append(turnHead(part, t, i, delta, ctx));
    if (ctx.openTurns.has(t.n)) box.append(turnRows(part, t, i, ctx));
  });
  if (part.not_known.length) {
    const n = el('div', 'nk', `Not known here: ${part.not_known.join(', ')}`);
    n.style.padding = '10px 16px';
    box.append(n);
  }
}
