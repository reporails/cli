// Calls to the x-ray server: every route carries the launch token; texts are fetched once per view version.
const token = document.querySelector('meta[name="xray-token"]')?.content ?? '';

export async function xrayFetch(url, init) {
  try {
    const r = await fetch(url, { cache: 'no-store', ...init, headers: { 'X-Xray-Token': token, ...(init && init.headers) } });
    let j = null;
    try { j = await r.json(); } catch (_) { j = null; }
    return { ok: r.ok, status: r.status, j };
  } catch (_) { return null; }
}

export const viewHeaders = etag => (etag ? { 'X-Xray-Token': token, 'If-None-Match': etag } : { 'X-Xray-Token': token });

const fetched = new Map();
let redraw = () => {};
export const onTextArrived = fn => { redraw = fn; };
const kept = new Set();
export const forgetTexts = () => { for (const k of [...fetched.keys()]) if (!kept.has(k)) fetched.delete(k); };

// The text behind a key (`keep`: fetched once per page life, e.g. a recorded call that never changes): {loading}, {error} or {text, truncated}; the page draws again when it arrives.
export function text(key, url, keep = false) {
  if (fetched.has(key)) return fetched.get(key);
  if (keep) kept.add(key);
  const e = { loading: true };
  fetched.set(key, e);
  xrayFetch(url).then(res => {
    if (!res) fetched.set(key, { error: 'The x-ray server did not answer.' });
    else if (res.ok && res.j && typeof res.j.text === 'string') fetched.set(key, { text: res.j.text, truncated: !!res.j.truncated });
    else fetched.set(key, { error: (res.j && res.j.error) || `request refused (${res.status})` });
  }).then(redraw);
  return e;
}

// The page's own `?session=` and `?pick=`: read once, and added to every session route by this one helper (an explicit `session` in `params` wins).
const own = new URLSearchParams(location.search);
export function sessionUrl(route, params = {}) {
  const q = new URLSearchParams(params);
  for (const k of ['session', 'pick']) if (own.get(k) && !q.has(k)) q.set(k, own.get(k));
  const s = q.toString();
  return s ? `${route}?${s}` : route;
}

export const viewUrl = () => sessionUrl('view');
export const callUrl = id => sessionUrl('call', { id });
// A call's full reply ({loading}, {error} or {data: {tool, text, input, result, truncated}}): fetched once; the page draws again when it arrives.
const callDetails = new Map();
export function callDetail(id) {
  if (callDetails.has(id)) return callDetails.get(id);
  const e = { loading: true };
  callDetails.set(id, e);
  xrayFetch(callUrl(id)).then(res => {
    if (res && res.ok && res.j) callDetails.set(id, { data: res.j });
    else callDetails.set(id, { error: (res && res.j && res.j.error) || (res ? `request refused (${res.status})` : 'The x-ray server did not answer.') });
  }).then(redraw);
  return e;
}
export const callText = id => text('call:' + id, callUrl(id), true);
export const briefUrl = id => sessionUrl('brief', { subagent: id });
export const promptUrl = id => sessionUrl('prompt', { id });
export const peekUrl = path => sessionUrl('peek', { path });
export const sessionsUrl = () => sessionUrl('sessions');
export const firstPromptUrl = id => sessionUrl('first-prompt', { session: id });
