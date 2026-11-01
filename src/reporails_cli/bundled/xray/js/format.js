export const k1 = n => {
  if (n == null) return '';
  const a = Math.abs(n), s = n < 0 ? '−' : '';
  if (a >= 1e6) return s + (a / 1e6).toFixed(a >= 1e7 ? 0 : 2).replace(/\.?0+$/, '') + 'M';
  return s + (a >= 1000 ? (a / 1000).toFixed(a >= 10000 ? 0 : 1).replace(/\.0$/, '') + 'k' : String(a));
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
