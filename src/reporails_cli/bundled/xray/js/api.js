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

export const callUrl = id => 'call?id=' + encodeURIComponent(id);
export const callText = id => text('call:' + id, callUrl(id), true);
export const briefUrl = id => 'brief?subagent=' + encodeURIComponent(id);
export const promptUrl = id => 'prompt?id=' + encodeURIComponent(id);
export const peekUrl = path => 'peek?path=' + encodeURIComponent(path);
