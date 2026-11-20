// Formatting marks (the bar's ¶), as Word's Show/Hide ¶ shows them: ¶ at the
// end of each paragraph, empty ones too; · for a space, ° for a non-breaking
// one, → for a tab, ↵ for a line break inside a paragraph (Shift+Enter), ¬ for
// a soft hyphen, ¤ at the end of a table cell. They are drawn in a layer over
// the text, where the browser lays out each character; nothing goes into the
// text that is saved or sent. Only what is in view is drawn.
// The Mail app has the same code in its app.js (formattingMarks).
export function formattingMarks(editor, onToggle) {
  const layer = document.createElement('div');
  layer.className = 'marks-layer';
  layer.setAttribute('aria-hidden', 'true');
  layer.hidden = true;
  editor.after(layer);
  const BLOCKS = /^(DIV|P|LI|UL|OL|BLOCKQUOTE|H[1-6]|PRE|TABLE|THEAD|TBODY|TFOOT|TR|TD|TH|HR|FIGURE|FIGCAPTION|SECTION|ARTICLE|HEADER|FOOTER|ADDRESS|DL|DT|DD|CENTER)$/;
  const block = n => n.nodeType === 1 && (BLOCKS.test(n.tagName) || /^(block|list-item|flex|grid|table|table-row|table-cell)$/.test(getComputedStyle(n).display));
  const SIGNS = {' ': '·', '\u00a0': '°', '\t': '→', '\u00ad': '¬'};
  let on = false, frame = 0;

  // The paragraphs: each block without blocks inside, and each run of text
  // between blocks; a table cell's last paragraph ends with ¤.
  function paragraphs() {
    const out = [];
    const visit = (box, cell) => {
      let run = [];
      const flush = () => {
        if (run.some(n => n.nodeType !== 3 || /\S|\u00a0/.test(n.data))) out.push({nodes: run, box, cell: false});
        run = [];
      };
      const from = out.length;
      for (const n of box.childNodes) {
        if (n.nodeType === 1 && block(n)) {
          flush();
          if (n.tagName === 'HR') continue;
          const before = out.length;
          visit(n, /^(TD|TH)$/.test(n.tagName));
          if (out.length === before && !/^(TABLE|THEAD|TBODY|TFOOT|TR|UL|OL|DL)$/.test(n.tagName)) out.push({nodes: [], box: n, cell: false});
        } else if (n.nodeType === 3 || n.nodeType === 1) run.push(n);
      }
      flush();
      if (cell && out.length > from) out[out.length - 1].cell = true;
    };
    visit(editor, false);
    return out;
  }

  // The parts of a paragraph in order: text, line breaks, and the rest
  // (pictures and the like), down through inline elements.
  function tokens(nodes) {
    const out = [];
    const walk = n => {
      if (n.nodeType === 3) { if (n.data.length) out.push(n); }
      else if (n.nodeType === 1) {
        if (n.tagName === 'BR' || n.tagName === 'IMG' || !n.firstChild) out.push(n);
        else for (const c of n.childNodes) walk(c);
      }
    };
    nodes.forEach(walk);
    return out;
  }

  const rectsOf = node => { const r = document.createRange(); r.selectNode(node); return [...r.getClientRects()].filter(x => x.height > 0); };
  const lastRect = node => {
    if (node.nodeType === 3) {
      const r = document.createRange();
      for (let i = node.data.length; i > 0; i--) {
        r.setStart(node, i - 1); r.setEnd(node, i);
        const all = [...r.getClientRects()].filter(x => x.height > 0);
        if (all.length) return all[all.length - 1];
      }
      return null;
    }
    const all = rectsOf(node);
    return all.length ? all[all.length - 1] : null;
  };
  const sizes = new Map();
  const sizeOf = el => {
    if (!sizes.has(el)) sizes.set(el, getComputedStyle(el).fontSize);
    return sizes.get(el);
  };

  function paint() {
    frame = 0;
    if (!on) return;
    sizes.clear();
    const box = editor.getBoundingClientRect();
    layer.style.left = '0px'; layer.style.top = '0px';
    const base = layer.getBoundingClientRect();
    Object.assign(layer.style, {left: box.left - base.left + 'px', top: box.top - base.top + 'px', width: box.width + 'px', height: box.height + 'px'});
    const seen = (top, bottom) => bottom >= box.top && top <= box.bottom;
    const parts = [];
    const put = (sign, rect, size, kind) => {
      parts.push(`<span class="mark ${kind}" style="left:${(rect.left - box.left).toFixed(1)}px;top:${(rect.top - box.top).toFixed(1)}px;` +
        `width:${Math.max(rect.width, 1).toFixed(1)}px;height:${rect.height.toFixed(1)}px;font-size:${size}">${sign}</span>`);
    };
    // Spaces and the like, character by character, in the text in view.
    const range = document.createRange(), walk = document.createTreeWalker(editor, NodeFilter.SHOW_TEXT);
    for (let n = walk.nextNode(); n && parts.length < 6000; n = walk.nextNode()) {
      if (!/[ \u00a0\t\u00ad]/.test(n.data)) continue;
      range.selectNodeContents(n);
      const all = range.getBoundingClientRect();
      if (!seen(all.top, all.bottom)) continue;
      const size = sizeOf(n.parentElement);
      for (let i = 0; i < n.data.length; i++) {
        const sign = SIGNS[n.data[i]];
        if (!sign) continue;
        range.setStart(n, i); range.setEnd(n, i + 1);
        const r = [...range.getClientRects()].find(x => x.height > 0);
        if (!r || (r.width < 0.5 && n.data[i] !== '\u00ad') || !seen(r.top, r.bottom)) continue;  // a space the line collapsed shows nothing
        // A tab is as wide as a space in mail, and a soft hyphen has no width:
        // their signs shrink to fit rather than cover the letters beside them.
        const fit = n.data[i] === '\t' ? Math.min(parseFloat(size), r.width * 1.4) + 'px' : n.data[i] === '\u00ad' ? parseFloat(size) * 0.7 + 'px' : size;
        put(sign, r, fit, n.data[i] === '\u00ad' ? 'at' : 'in');
      }
    }
    // The end of each line and paragraph.
    for (const p of paragraphs()) {
      const list = tokens(p.nodes), end = p.cell ? '¤' : '¶';
      const at = (rect, sign, size) => put(sign, {left: rect.right, top: rect.top, width: 0, height: rect.height}, size, 'end');
      if (!list.length) {
        const r = p.box.getBoundingClientRect(), s = getComputedStyle(p.box);
        const top = r.top + parseFloat(s.paddingTop) + parseFloat(s.borderTopWidth), left = r.left + parseFloat(s.paddingLeft) + parseFloat(s.borderLeftWidth);
        const line = parseFloat(s.lineHeight) || parseFloat(s.fontSize) * 1.4;
        if (seen(top, top + line)) at({right: left, top, height: line}, end, s.fontSize);
        continue;
      }
      const last = list[list.length - 1];
      list.forEach((t, i) => {
        if (t.nodeType !== 1 || t.tagName !== 'BR') return;
        const r = rectsOf(t)[0] || (i > 0 && lastRect(list[i - 1]));
        if (!r || !seen(r.top, r.bottom)) return;
        const size = sizeOf(t.parentElement);
        if (t !== last) at(r, '↵', size);
        // A line break at the end with text before it adds no line: the
        // paragraph ends there. One alone, or after another, holds an empty
        // line, where the paragraph ends.
        else if (i === 0 || (list[i - 1].nodeType === 1 && list[i - 1].tagName === 'BR')) at({right: r.left, top: r.top, height: r.height}, end, size);
      });
      const lastBr = last.nodeType === 1 && last.tagName === 'BR';
      if (lastBr && !(list.length > 1 && !(list[list.length - 2].nodeType === 1 && list[list.length - 2].tagName === 'BR'))) continue;
      const content = lastBr ? list[list.length - 2] : last;
      const r = lastRect(content);
      if (r && seen(r.top, r.bottom)) at(r, end, sizeOf(content.nodeType === 3 ? content.parentElement : content.parentElement || editor));
    }
    layer.innerHTML = parts.join('');
  }
  const later = () => { if (on && !frame) frame = requestAnimationFrame(paint); };
  editor.addEventListener('input', later);
  editor.addEventListener('load', later, true);  // a picture changes the lines once it arrives
  document.addEventListener('scroll', later, true);
  addEventListener('resize', later);
  new ResizeObserver(later).observe(editor);
  new MutationObserver(later).observe(editor, {childList: true, subtree: true, characterData: true, attributes: true});
  document.fonts?.ready.then(later);

  return {
    get on() { return on; },
    show(value) {
      on = !!value;
      editor.classList.toggle('show-marks', on);
      layer.hidden = !on;
      if (on) paint(); else layer.textContent = '';
      onToggle?.(on);
    },
  };
}
