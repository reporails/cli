// What the components read that the view does not carry as such: the view's slices, joined and counted once per version.
export function derive(view) {
  const turns = view.turns || [];
  const runs = (view.subagents || []).map(s => {
    const pts = (s.series || []).filter(p => p && p[0] != null);
    return { id: String(s.id), type: s.type || 'subagent', turn: s.turn, sb: s, pts, start: s.start, end: s.end, miss: !(s.loads || []).some(l => l.kind === 'project') };
  });
  const comp = turns.find(t => t.compaction) || null;
  const peak = Math.max(0, view.first_context || 0, ...turns.map(t => t.context || 0), ...turns.flatMap(t => (t.series || []).map(p => p[1])), comp && comp.compaction.before || 0);
  const art = (view.artifacts || []).map(a => ({ ...a, key: a.kind + ':' + a.path }));
  const harness = view.harness || [];
  const toks = [];
  turns.forEach(t => { (t.loads || []).forEach(l => toks.push(l.tokens_est || 0)); (t.notes || []).forEach(n => toks.push(n.tokens_est || 0)); });
  const tokMax = Math.max(1, ...toks, ...harness.map(h => h.tokens_est || 0));
  const starts = turns.map((t, i) => (t.prompts && t.prompts.length) ? t.prompts[0].t : (t.series && t.series.length ? t.series[0][0] : (i ? turns[i - 1].t : 0)));
  const stops = turns.flatMap(t => (t.notes || []).filter(n => n.kind === 'stop_block').map(n => ({ ...n, turn: t.n })));
  const promptNo = new Map();
  let n = 0;
  turns.forEach(t => (t.prompts || []).forEach(p => promptNo.set(p.id, ++n)));
  return {
    turns, runs, comp, peak, art, harness, tokMax, starts, stops, promptNo,
    start: view.start || [], first_context: view.first_context, length_s: view.length_s, window: view.window,
    not_known: view.not_known || [], refusals: view.refusals || [], project: view.project, session: view.session, started_at: view.started_at,
  };
}

export const artByPath = (m, p) => m.art.find(a => a.path === p);
export const nameOf = (m, p) => { const a = artByPath(m, p); return a ? a.label : p; };

const lab = n => n === 0 ? 'start' : String(n);
const ranges = ns => {
  const out = [];
  let i = 0;
  while (i < ns.length) {
    let j = i;
    while (j + 1 < ns.length && ns[j + 1] === ns[j] + 1) j++;
    out.push(ns[i] === ns[j] ? lab(ns[i]) : `${lab(ns[i])}–${ns[j]}`);
    i = j + 1;
  }
  return out.join(', ');
};

// Where and when an artifact entered the context, in words.
export function whereLoaded(m, a) {
  if (!a.loaded) return 'On disk, not loaded this session.';
  const ns = a.turns || [];
  const arrived = [m.start, ...m.turns.map(t => t.loads || [])].map((l, i) => l.some(x => x.path === a.path) ? (i === 0 ? 0 : m.turns[i - 1].n) : null).filter(x => x != null);
  const subs = m.runs.filter(r => (r.sb.loads || []).some(l => l.path === a.path));
  const was = `Arrived ${arrived.length ? (arrived[0] === 0 ? 'at session start' : 'in turn ' + arrived.join(', ')) : 'by a skill call'}; in context in ${ns.length ? 'turns ' + ranges(ns) : 'no turn recorded'}.`;
  return was + (subs.length ? ` ${subs.length} ${subs.length === 1 ? 'subagent' : 'subagents'} got it too.` : '');
}
