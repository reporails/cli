// What the components read that the view does not carry as such: the view's slices, keyed and flattened once per version.
// Every fact (peak, turn start, prompt number, Stop count, compactions, funnel counts) is the view's own.
export function derive(view) {
  const turns = view.turns || [];
  const runs = (view.subagents || []).map(s => ({
    id: String(s.id), type: s.type || 'subagent', turn: s.turn, sb: s, start: s.start, end: s.end, peak: s.peak,
    pts: (s.series || []).filter(p => p && p[0] != null),
  }));
  const art = (view.artifacts || []).map(a => ({ ...a, key: a.kind + ':' + a.path }));
  const harness = view.harness || [];
  const toks = [];
  turns.forEach(t => { (t.loads || []).forEach(l => toks.push(l.tokens_est || 0)); (t.notes || []).forEach(n => toks.push(n.tokens_est || 0)); });
  const tokMax = Math.max(1, ...toks, ...harness.map(h => h.tokens_est || 0));
  // Where each Stop block sits, for drawing: the notes the view already carries.
  const stops = turns.flatMap(t => (t.notes || []).filter(n => n.kind === 'stop_block').map(n => ({ t: n.t, turn: t.n })));
  const funnel = new Map((view.funnel || []).map(f => [f.kind, f]));
  return {
    turns, runs, art, harness, tokMax, stops, funnel,
    compactions: view.compactions || [], facts: view.facts || [], peak: view.peak, model: view.model, check: view.check || null,
    start: view.start || [], first_context: view.first_context, context_line: view.context_line || [], length_s: view.length_s, window: view.window || null,
    not_known: view.not_known || [], refusals: view.refusals || [], project: view.project, session: view.session, started_at: view.started_at,
  };
}

export const artByPath = (m, p) => m.art.find(a => a.path === p);
export const nameOf = (m, p) => { const a = artByPath(m, p); return a ? a.label : p; };
