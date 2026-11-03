export const k1 = n => {
  if (n == null) return '';
  const a = Math.abs(n), s = n < 0 ? '−' : '';
  const trim = (x, digits) => String(Number(x.toFixed(digits)));
  if (a >= 1e6 || Math.round(a / 1000) >= 1000) return s + trim(a / 1e6, a >= 1e7 ? 0 : 2) + 'M';
  return s + (a >= 1000 ? trim(a / 1000, a >= 10000 ? 0 : 1) + 'k' : String(a));
};
export const tk = (n, est) => n == null ? '' : (est ? '~' : '') + k1(n);
export const clock = t => {
  if (t == null) return '';
  t = Math.max(0, Math.round(t));
  const h = Math.floor(t / 3600), m = Math.floor(t % 3600 / 60), s = t % 60;
  return h ? `${h}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}` : `${m}:${String(s).padStart(2, '0')}`;
};
export const dur = s => {
  s = Math.round(s || 0);
  return s >= 3600 ? `${Math.floor(s / 3600)}h ${Math.floor(s % 3600 / 60)}m` : s >= 60 ? `${Math.floor(s / 60)}m ${s % 60}s` : `${s}s`;
};
export const plural = (n, w, ws) => `${n} ${n === 1 ? w : (ws || w + 's')}`;
// A template whose {names} are filled from `values`; an unknown name stays visible as written.
export const fill = (template, values) => template.replace(/\{(\w+)\}/g, (m, k) => (k in values ? String(values[k]) : m));
export const range = (a, b) => `${clock(a)}–${clock(b)}`;

// An ISO instant as `YYYY-MM-DD HH:MM UTC`; empty when it is missing or not a date.
export const startedAt = iso => {
  const d = iso ? new Date(iso) : null;
  return d && !isNaN(d) ? d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC' : '';
};
export const usd = n => '$' + (n >= 0.01 || n === 0 ? n.toFixed(2) : n.toFixed(4));
// A source's estimated cost: `~$0.09`, or `<$0.01` under a cent; null when the view has no figure.
export const costEst = c => (typeof c !== 'number' ? null : c < 0.01 ? '<$0.01' : `~$${c.toFixed(2)}`);
