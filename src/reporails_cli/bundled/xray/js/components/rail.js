// The jump rail: a thin column beside the canvas with the density of the agent's calls down the graph and one button per
// landmark (repeated failures, fan-outs, the selection, the agent's end) that scrolls the graph to it.
import { el, svg } from '../dom.js';

export const BINS = 48;

// Calls per bin over the canvas height, bin by bin, from the calls' y positions.
export function density(ys, height) {
  const bins = new Array(BINS).fill(0);
  for (const y of ys) bins[Math.min(BINS - 1, Math.max(0, Math.floor(y / Math.max(1, height) * BINS)))]++;
  return bins;
}

// `plan` is { height, ys, marks: [{ id, y, kind, label }] }; each mark's anchor is an element on the canvas.
export function render(box, plan) {
  const bins = density(plan.ys, plan.height);
  const most = Math.max(1, ...bins);
  const strip = svg('svg', { class: 'rail-density', viewBox: `0 0 22 ${BINS}`, preserveAspectRatio: 'none', 'aria-hidden': 'true' });
  bins.forEach((n, i) => strip.append(svg('rect', { x: 7, y: i + 0.15, width: 8, height: 0.7, rx: 0.3, fill: '#6E7076', 'fill-opacity': (0.1 + 0.6 * n / most).toFixed(2) })));
  const marks = plan.marks.map(m => {
    const b = el('button', 'rail-mark ' + m.kind);
    b.type = 'button';
    b.dataset.jump = m.id;
    b.setAttribute('aria-label', m.label);
    b.title = m.label;
    b.style.top = `${Math.min(98, Math.max(1, m.y / plan.height * 100)).toFixed(2)}%`;
    return b;
  });
  box.replaceChildren(strip, ...marks);
}

// Scrolls the graph so the anchor sits in the middle of the view.
export function jump(id) {
  const a = document.getElementById(id);
  if (a) a.scrollIntoView({ block: 'center' });
}
