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
// The texts the last view had fetched: a text shows as it was while the new view's copy is fetched, so it never goes back to loading.
let shown = new Map();
// `view` is the new view when one arrived: a call still running (no result yet) is kept until that view shows it with a result.
export const forgetTexts = view => {
  const finished = new Set();
  for (const t of view ? view.track : []) for (const c of t.calls) if (c.result_tokens_est != null || c.duration_s != null) finished.add(c.use_id);
  shown = new Map();
  for (const [k, e] of [...fetched.entries()]) {
    if (kept.has(k)) continue;
    if (e.text !== undefined) shown.set(k, e);
    fetched.delete(k);
  }
  // A call whose request failed is asked again after 30 s at the earliest; one whose result had not landed, once its result shows.
  const now = Date.now();
  for (const [k, e] of [...callDetails.entries()]) if ((e.error && now - e.at >= RETRY_MS) || (e.data && e.data.result == null && finished.has(k))) callDetails.delete(k);
};

// The text behind a key (`keep`: fetched once per page life, e.g. a recorded call that never changes): {loading}, {error} or {text, truncated, frontmatter, body}; the page draws again when it arrives.
export function text(key, url, keep = false) {
  if (fetched.has(key)) return fetched.get(key);
  if (keep) kept.add(key);
  const before = shown.get(key);
  shown.delete(key);
  const e = before || { loading: true };
  fetched.set(key, e);
  xrayFetch(url).then(res => {
    let now;
    if (!res) now = { error: 'The x-ray server did not answer.' };
    else if (res.ok && res.j && typeof res.j.text === 'string') now = { text: res.j.text, truncated: !!res.j.truncated, frontmatter: res.j.frontmatter ?? null, body: typeof res.j.body === 'string' ? res.j.body : res.j.text };
    else now = { error: (res.j && res.j.error) || `request refused (${res.status})` };
    const same = before && now.text === before.text && now.truncated === before.truncated && now.body === before.body;
    fetched.set(key, same ? before : now);
    if (!same) redraw();
  });
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
// A call's full reply ({loading}, {error} or {data: {tool, text, input, result, truncated}, text}): fetched once per view version; the page draws again when it arrives.
const callDetails = new Map();
const RETRY_MS = 30000;
export function callDetail(id) {
  if (callDetails.has(id)) return callDetails.get(id);
  const e = { loading: true };
  callDetails.set(id, e);
  xrayFetch(callUrl(id)).then(res => {
    if (res && res.ok && res.j) callDetails.set(id, { data: res.j, text: typeof res.j.text === 'string' ? res.j.text : null });
    else callDetails.set(id, { at: Date.now(), error: (res && res.j && res.j.error) || (res ? `request refused (${res.status})` : 'The x-ray server did not answer.') });
  }).then(redraw);
  return e;
}
export const systemUrl = type => sessionUrl('system', { type });
export const briefUrl = id => sessionUrl('brief', { subagent: id });
export const promptUrl = id => sessionUrl('prompt', { id });
export const peekUrl = path => sessionUrl('peek', { path });
export const sessionsUrl = () => sessionUrl('sessions');
export const firstPromptUrl = id => sessionUrl('first-prompt', { session: id });
