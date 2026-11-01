// A test-only node kind: registers a renderer for "stub" nodes with the page's own registry.
import { register } from '/static/js/components/nodes/index.js';

register('stub', {
  card: node => {
    const box = document.createElement('div');
    box.className = 'stubcard';
    box.textContent = `STUB ${node.name}`;
    return box;
  },
  inspector: node => {
    const box = document.createElement('div');
    box.className = 'stubinspector';
    box.textContent = `stub inspector for ${node.id}`;
    return box;
  },
});
