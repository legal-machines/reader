// Writing an end-to-end encrypted message inside the Mail app: the subject,
// the text and the files are typed and added here, in a frame of another
// site that the mail page cannot read, and encrypted here to keys this
// reader carries (keys.mjs, published with it), never to keys the mail page
// offers. It looks as Mail's own composer does (its stylesheet, its
// formatting bar, the signature Mail hands over at the start); the mail page
// gets the encrypted message and sends it. This page sends nothing itself.
//
// While this frame has the keyboard, it shows the owner's mark (mark.mjs) in
// the Subject line: a field that only looks like this one cannot.

import {MAIL_SITES} from './sites.mjs';
import {widths} from './width.mjs';
import {addressOf, escape, linkify} from './mime.mjs';
import {icon} from './icons.mjs';
import {keyOf} from './seal.mjs';
import {explained, markFor, setExplained, tile} from './mark.mjs';
import {formattingMarks} from './marks.mjs';
import * as vault from './vault.mjs';
import {openWith, recipientsOf} from './decrypt.mjs';
import {fromOurFrame, readerFrames} from './tab.mjs';
import {NOTICES} from './notices.mjs';
import {alarmText, raised} from './alarm.mjs';

const form = document.getElementById('compose'), subject = document.getElementById('subject'), editor = document.getElementById('editor');
const tools = document.getElementById('tools'), filesBox = document.getElementById('files'), dock = document.getElementById('mark-dock');
document.getElementById('e2e-label').innerHTML = icon('lock') + '<span>End to end</span>';
const pictureInput = document.getElementById('pictures'), filesInput = document.getElementById('attach'), dropHint = form.querySelector('.drop-hint');
const LIMIT = 15 * 1024 * 1024;  // the files of one message, as the mail server takes them encrypted
let parentOrigin = null, from = '', own = null, started = false, typed = false, wrote = false, lastTrusted = 0, engaged = false;
// An address as it may stand in a header (as send.mjs checks it): nothing
// that could end the line and start a header of Mail's choosing.
const ADDRESS = /^[a-z0-9._%+-]{1,64}@[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})+$/;
// Characters that change how text reads without showing: direction
// overrides and isolates, zero-width ones, invisible tags, the soft hyphen.
const HIDDEN = /[\u00ad\u061c\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]|\udb40[\udc00-\udc7f]/g;
// Typed here by a person (the browser marks such events as trusted).
for (const type of ['keydown', 'pointerdown', 'paste', 'drop']) addEventListener(type, e => {
  if (!e.isTrusted) return;
  typed = true; lastTrusted = Date.now();
  if (!engaged) { engaged = true; showSeal(); }
}, true);
// Text typed, pasted or dropped into the message or its subject, or a file
// picked with the clip: only then may Send take this composer. A click alone,
// which a page can trick you into, does not make it yours.
addEventListener('beforeinput', e => { if (e.isTrusted) wrote = true; }, true);
// The mark shows only after something of yours in this frame since it last
// got the keyboard: a page that only moves the focus here does not light it.
addEventListener('blur', () => { engaged = false; });
// In Chrome the browser can tell whether this composer is truly seen (not
// covered, faded, shrunk or moved off: IntersectionObserver v2). Where it
// can, the mark shows and Send takes the message only while it is, Send only
// after a second of it.
// In every browser it can tell how much of the composer is on the screen:
// the mark shows only while all of it is, so a page cannot cut the frame
// down to the corner with the mark and set that beside a field of its own.
let seeing = null, seenSince = 0, whole = true;
try {
  new IntersectionObserver(entries => {
    for (const en of entries) {
      whole = en.intersectionRatio >= 0.98;
      if (typeof en.isVisible === 'boolean') {
        if (en.isVisible && !seeing) seenSince = Date.now();
        seeing = en.isVisible;
      }
      showSeal();
    }
  }, {trackVisibility: true, delay: 100, threshold: [0, 0.5, 0.9, 0.98, 1]}).observe(form);
} catch (e) {}
const seen = (ms = 0) => seeing === null || (seeing && Date.now() - seenSince >= ms);
const files = [];                 // {file, id}
const pictures = new Map();       // number -> File, for <img data-pic>
let pictureCount = 0;
const tell = m => { if (parentOrigin) parent.postMessage(m, parentOrigin); };
// Mail hears once that the text changed (so an old encrypted copy is not
// sent), not at every key: the timing of keys is the writer's own.
let lastUse = 0, dirty = false;
const touched = () => {
  if (!dirty) { dirty = true; tell({type: 'reader-dirty'}); }
  // The key stays open for a writer at work: only after an action of yours,
  // never for a change Mail made happen (a message put back to edit).
  if (Date.now() - lastTrusted < 3000 && Date.now() - lastUse > 30000) { lastUse = Date.now(); vault.used(true); }
};

// ---- The formatting bar, as Mail draws it (webmail/src/RoutesCompose.cpp, editor_tools).
function bar() {
  const tool = (cmd, glyph, title, keys = '') =>
    `<button type="button" class="icon-button" data-cmd="${cmd}"${keys ? ` data-keys="${keys}"` : ''} title="${title}" aria-label="${title}">${icon(glyph)}</button>`;
  const item = (cmd, value, label, extra = '') => `<button type="button" class="menu-item" data-cmd="${cmd}" data-value="${escape(value)}"${extra}>${label}</button>`;
  const pop = (glyph, title, items) =>
    `<details class="pop up"><summary class="icon-button" title="${title}" aria-label="${title}">${icon(glyph)}</summary><div class="pop-card">${items}</div></details>`;
  const sizes = '<p class="pop-title">Text size</p>' + item('fontSize', '2', '<small>Small</small>') + item('fontSize', '3', 'Normal') +
                item('fontSize', '5', '<span class="big">Large</span>') + item('fontSize', '6', '<span class="huge">Huge</span>');
  const swatch = (cmd, hex, name) => `<button type="button" class="swatch" data-cmd="${cmd}" data-value="${hex}" title="${name}" aria-label="${name}" style="background:${hex}"></button>`;
  const colors = '<p class="pop-title">Text color</p><div class="swatches">' +
    [['#1f1f1f', 'Black'], ['#5f6368', 'Gray'], ['#d93025', 'Red'], ['#e8710a', 'Orange'], ['#188038', 'Green'], ['#12a4af', 'Teal'], ['#1a73e8', 'Blue'], ['#9334e6', 'Purple']]
      .map(([h, n]) => swatch('foreColor', h, n)).join('') + '</div><p class="pop-title">Highlight</p><div class="swatches">' +
    [['#fff475', 'Yellow'], ['#ccff90', 'Green'], ['#cbf0f8', 'Blue'], ['#fdcfe8', 'Pink'], ['#e8eaed', 'Gray']].map(([h, n]) => swatch('hiliteColor', h, n + ' highlight')).join('') +
    '<button type="button" class="swatch none" data-cmd="hiliteColor" data-value="transparent" title="No highlight" aria-label="No highlight"></button></div>';
  const aligns = '<p class="pop-title">Align</p>' + item('justifyLeft', '', icon('align_left') + '<span>Left</span>', ' data-keys="Shift+L"') +
    item('justifyCenter', '', icon('align_center') + '<span>Center</span>', ' data-keys="Shift+E"') +
    item('justifyRight', '', icon('align_right') + '<span>Right</span>', ' data-keys="Shift+R"') +
    item('justifyFull', '', icon('align_justify') + '<span>Justify</span>', ' data-keys="Shift+J"');
  const emoji = '<div class="emoji-grid">' + ['😀', '😃', '😄', '😁', '😆', '😅', '😂', '🙂', '😉', '😊', '😍', '😘', '😎', '🤔', '😐', '😴', '😢', '😭', '😡', '😮',
    '👍', '👎', '👏', '🙏', '💪', '👋', '🤝', '✌️', '👌', '🔥', '🎉', '✅', '❌', '⭐', '❤️', '💡', '📎', '📅', '📞', '✉️', '🚀', '💼', '📈', '🏆', '☕', '🌍', '🎯', '⚖️']
    .map(e => `<button type="button" data-cmd="insertText" data-value="${e}">${e}</button>`).join('') + '</div>';
  let table = '<p class="pop-title table-size">Table</p><div class="table-grid">';
  for (let r = 1; r <= 6; r++) for (let c = 1; c <= 8; c++) table += `<button type="button" data-cmd="insertTable" data-value="${c}x${r}" aria-label="${c} by ${r} table"></button>`;
  table += '</div>';
  return '<span class="tool-group">' + tool('undo', 'undo', 'Undo') + tool('redo', 'redo', 'Redo') + '</span>' +
    '<span class="tool-group">' + pop('text_size', 'Text size', sizes) + tool('bold', 'bold', 'Bold', 'B') + tool('italic', 'italic', 'Italic', 'I') +
    tool('underline', 'underline', 'Underline', 'U') + tool('strikeThrough', 'strike', 'Strikethrough', 'Shift+X') + pop('text_color', 'Text color', colors) +
    '</span><span class="tool-group">' + pop('align_left', 'Align', aligns) + tool('insertOrderedList', 'numbers', 'Numbered list', 'Shift+7') +
    tool('insertUnorderedList', 'bullets', 'Bulleted list', 'Shift+8') + tool('outdent', 'indent_less', 'Indent less', '[') +
    tool('indent', 'indent_more', 'Indent more', ']') + tool('blockquote', 'quote', 'Quote', 'Shift+9') +
    '</span><span class="tool-group pictures">' + tool('attachFiles', 'attach', 'Attach files') + tool('insertImage', 'image', 'Insert picture') + '</span><span class="tool-group">' + tool('createLink', 'link', 'Link', 'K') +
    pop('emoji', 'Emoji', emoji) + pop('table', 'Table', table) +
    `<button type="button" class="icon-button" data-cmd="deleteTable" title="Delete table" aria-label="Delete table" hidden>${icon('delete')}</button>` +
    tool('removeFormat', 'clear', 'Remove formatting', '\\') + tool('toggleMarks', 'pilcrow', 'Formatting marks') + '</span>';
}
tools.innerHTML = bar();
dropHint.querySelector('span').innerHTML = icon('attach') + 'Drop files to attach them';

const mac = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);
for (const b of tools.querySelectorAll('[data-keys]')) b.title += ' (' + (mac ? '⌘' + b.dataset.keys.replace('Shift+', '⇧') : 'Ctrl+' + b.dataset.keys) + ')';
const closeMenus = () => { for (const d of tools.querySelectorAll('details[open]')) d.open = false; };
document.addEventListener('click', e => { for (const d of tools.querySelectorAll('details[open]')) if (!d.contains(e.target)) d.open = false; });
tools.addEventListener('toggle', e => { if (e.target.open) for (const d of tools.querySelectorAll('details[open]')) if (d !== e.target) d.open = false; }, true);

let saved = null;
document.addEventListener('selectionchange', () => {
  const sel = getSelection();
  if (sel.rangeCount && editor.contains(sel.anchorNode)) saved = sel.getRangeAt(0).cloneRange();
});
const restore = range => { editor.focus({preventScroll: true}); if (range) { const sel = getSelection(); sel.removeAllRanges(); sel.addRange(range); } };

// A link: its address asked in a small card over the bar, as Mail asks it.
const linkCard = document.getElementById('link-card'), linkAddress = document.getElementById('link-address');
let linkRange = null;
function askLink() {
  linkRange = saved;
  linkCard.hidden = false;
  linkAddress.value = 'https://';
  linkAddress.focus();
  linkAddress.setSelectionRange(8, 8);
}
function insertLink() {
  const address = linkAddress.value.trim();
  linkCard.hidden = true;
  restore(linkRange);
  if (!/^(https?:\/\/|mailto:)\S+$/i.test(address)) return;
  if (getSelection().isCollapsed) document.execCommand('insertText', false, address);
  if (!getSelection().isCollapsed) document.execCommand('createLink', false, address);
  touched();
}
document.getElementById('link-insert').addEventListener('click', insertLink);
document.getElementById('link-cancel').addEventListener('click', () => { linkCard.hidden = true; restore(linkRange); });
linkAddress.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); insertLink(); } if (e.key === 'Escape') { linkCard.hidden = true; restore(linkRange); } });

const format = (cmd, value) => {
  restore(saved);
  if (cmd === 'createLink') { closeMenus(); askLink(); return; }
  if (cmd === 'insertImage') { closeMenus(); pictureInput.click(); return; }
  if (cmd === 'attachFiles') { closeMenus(); filesInput.click(); return; }
  if (cmd === 'toggleMarks') { showMarks(!editor.classList.contains('show-marks')); closeMenus(); return; }
  if (cmd === 'blockquote') document.execCommand('formatBlock', false, 'blockquote');
  else if (cmd === 'deleteTable') {
    // The table the caret is in, as one deletion, which Undo brings back.
    const sel = getSelection(), at = sel.anchorNode && (sel.anchorNode.nodeType === 1 ? sel.anchorNode : sel.anchorNode.parentElement);
    const table = at?.closest('table');
    if (table && editor.contains(table)) {
      const r = document.createRange();
      r.selectNode(table);
      sel.removeAllRanges();
      sel.addRange(r);
      document.execCommand('delete');
    }
  } else if (cmd === 'insertTable') {
    const [cols, rows] = value.split('x').map(Number);
    const cell = '<td style="border:1px solid #c4c7c5;padding:6px 10px;min-width:48px">&nbsp;</td>';
    document.execCommand('insertHTML', false, '<table style="border-collapse:collapse;margin:8px 0"><tbody>' +
      ('<tr>' + cell.repeat(cols) + '</tr>').repeat(rows) + '</tbody></table><p><br></p>');
  } else if (cmd === 'hiliteColor') {
    document.execCommand('styleWithCSS', false, true);
    document.execCommand('hiliteColor', false, value);
    document.execCommand('styleWithCSS', false, false);
  } else document.execCommand(cmd, false, value || null);
  touched();
  closeMenus();
  mark();
};
tools.addEventListener('mousedown', e => { if (e.target.closest('[data-cmd]')) e.preventDefault(); });  // the text keeps its selection
tools.addEventListener('click', e => { const b = e.target.closest('[data-cmd]'); if (b) format(b.dataset.cmd, b.dataset.value); });

// The bar follows the caret, as in Mail.
const toggles = ['bold', 'italic', 'underline', 'strikeThrough', 'insertOrderedList', 'insertUnorderedList'];
const alignButton = tools.querySelector('.menu-item[data-cmd="justifyLeft"]')?.closest('details')?.querySelector('summary');
const applies = cmd => { try { return document.queryCommandState(cmd); } catch (e) { return false; } };
function mark() {
  const sel = getSelection();
  if (!sel.rangeCount || !editor.contains(sel.anchorNode)) return;
  const at = sel.anchorNode.nodeType === 1 ? sel.anchorNode : sel.anchorNode.parentElement;
  const inside = tag => { const e = at?.closest(tag); return !!e && editor.contains(e); };
  for (const cmd of toggles) tools.querySelector(`.icon-button[data-cmd="${cmd}"]`)?.setAttribute('aria-pressed', String(applies(cmd)));
  tools.querySelector('[data-cmd="blockquote"]')?.setAttribute('aria-pressed', String(inside('blockquote:not([style*="border"])')));  // a quote, not an indent
  tools.querySelector('[data-cmd="createLink"]')?.setAttribute('aria-pressed', String(inside('a')));
  tools.querySelector('[data-cmd="deleteTable"]')?.toggleAttribute('hidden', !inside('table'));
  const sized = at?.closest('font[size]'), size = sized && editor.contains(sized) ? sized.getAttribute('size') : '3';
  for (const item of tools.querySelectorAll('.menu-item[data-cmd="fontSize"]')) item.setAttribute('aria-checked', String(item.dataset.value === size));
  const align = ['justifyCenter', 'justifyRight', 'justifyFull'].find(applies) || 'justifyLeft';
  for (const item of tools.querySelectorAll('.menu-item[data-cmd^="justify"]')) item.setAttribute('aria-checked', String(item.dataset.cmd === align));
  if (alignButton && alignButton.dataset.align !== align) {
    const glyph = tools.querySelector(`.menu-item[data-cmd="${align}"] svg.i`);
    if (glyph) { alignButton.querySelector('svg.i').replaceWith(glyph.cloneNode(true)); alignButton.dataset.align = align; }
  }
}
for (const cmd of [...toggles, 'blockquote', 'createLink']) tools.querySelector(`.icon-button[data-cmd="${cmd}"]`)?.setAttribute('aria-pressed', 'false');
document.addEventListener('selectionchange', mark);
const grid = tools.querySelector('.table-grid'), sizeLabel = tools.querySelector('.table-size');
const showSize = value => {
  const [c, r] = value.split('x').map(Number);
  for (const cell of grid.children) { const [cc, rr] = cell.dataset.value.split('x').map(Number); cell.classList.toggle('on', cc <= c && rr <= r); }
  sizeLabel.textContent = `Table ${c} × ${r}`;
};
grid.addEventListener('mouseover', e => { const b = e.target.closest('button'); if (b) showSize(b.dataset.value); });
// A finger (or pen) presses a cell and slides: the size follows it, as rows
// do in Mail's list, and lifting it puts the table in. The mouse hovers and
// clicks as before.
let sizing = null, swallow = 0;
const sizeAt = (x, y) => { const b = document.elementFromPoint(x, y)?.closest('.table-grid button'); return b && grid.contains(b) ? b.dataset.value : null; };
grid.addEventListener('pointerdown', e => {
  if (e.pointerType === 'mouse') return;
  const value = sizeAt(e.clientX, e.clientY);
  if (!value) return;
  e.preventDefault();
  grid.setPointerCapture(e.pointerId);
  sizing = value;
  showSize(value);
});
grid.addEventListener('pointermove', e => {
  if (!sizing) return;
  const value = sizeAt(e.clientX, e.clientY);
  if (value && value !== sizing) { sizing = value; showSize(value); }
});
grid.addEventListener('pointerup', () => { if (!sizing) return; const value = sizing; sizing = null; swallow = Date.now(); format('insertTable', value); });
grid.addEventListener('pointercancel', () => { sizing = null; });
grid.addEventListener('click', e => { if (Date.now() - swallow < 700) { e.preventDefault(); e.stopPropagation(); } }, true);  // the lift was the choice
// Backspace at the very start of a quote takes the quote off that line, as
// in Gmail; browsers leave a quote with text in it alone. Android sends it
// only as beforeinput, Safari only as the key (no beforeinput when nothing
// is before the caret). Outdent first (Undo brings it back), by hand if not.
const liftQuote = () => {
  const sel = getSelection();
  if (!sel.rangeCount || !sel.isCollapsed) return false;
  const r = sel.getRangeAt(0), at = r.startContainer.nodeType === 1 ? r.startContainer : r.startContainer.parentElement;
  const quote = at?.closest('blockquote');
  if (!quote || !editor.contains(quote)) return false;
  const before = document.createRange();
  before.setStart(quote, 0);
  before.setEnd(r.startContainer, r.startOffset);
  if (before.toString() !== '' || before.cloneContents().querySelector('img, table, br')) return false;
  const node = r.startContainer, offset = r.startOffset;
  document.execCommand('outdent');
  if (quote.isConnected && quote.contains(node)) {
    quote.replaceWith(...quote.childNodes);
    const back = document.createRange();
    back.setStart(node, Math.min(offset, node.nodeType === 3 ? node.length : node.childNodes.length));
    back.collapse(true);
    sel.removeAllRanges();
    sel.addRange(back);
  }
  touched(); mark();
  return true;
};
editor.addEventListener('keydown', e => { if (e.key === 'Backspace' && !e.metaKey && !e.ctrlKey && !e.altKey && !e.shiftKey && liftQuote()) e.preventDefault(); });
editor.addEventListener('beforeinput', e => { if (e.inputType === 'deleteContentBackward' && liftQuote()) e.preventDefault(); });
// Formatting marks (the bar's ¶), as Word shows them: marks.mjs.
const marksKey = 'reader-show-marks';
const marks = formattingMarks(editor, on => {
  tools.querySelector('[data-cmd="toggleMarks"]')?.setAttribute('aria-pressed', String(on));
  try { localStorage.setItem(marksKey, on ? '1' : ''); } catch (e) {}
});
const showMarks = on => marks.show(on);
try { if (localStorage.getItem(marksKey) === '1') showMarks(true); else tools.querySelector('[data-cmd="toggleMarks"]')?.setAttribute('aria-pressed', 'false'); } catch (e) {}
const plainKeys = {KeyB: 'bold', KeyI: 'italic', KeyU: 'underline', KeyK: 'createLink', Backslash: 'removeFormat', BracketLeft: 'outdent', BracketRight: 'indent'};
const shiftKeys = {KeyX: 'strikeThrough', Digit7: 'insertOrderedList', Digit8: 'insertUnorderedList', Digit9: 'blockquote',
  KeyL: 'justifyLeft', KeyE: 'justifyCenter', KeyR: 'justifyRight', KeyJ: 'justifyFull'};
editor.addEventListener('keydown', e => {
  if (!(mac ? e.metaKey : e.ctrlKey) || e.altKey) return;
  const cmd = (e.shiftKey ? shiftKeys : plainKeys)[e.code];
  if (cmd) { e.preventDefault(); format(cmd); }
});
editor.addEventListener('input', () => { touched(); mark(); });
// A click in the empty space of a message with nothing written yet starts
// it at the top, above the signature, as in Mail.
let untouched = null;
editor.addEventListener('mouseup', e => {
  if (e.target !== editor || editor.innerHTML !== untouched || !getSelection().isCollapsed) return;
  const range = document.createRange();
  range.setStart(editor, 0);
  range.collapse(true);
  restore(range);
});
subject.addEventListener('input', touched);
// Enter in Subject goes on to the text, as in Mail.
subject.addEventListener('keydown', e => {
  if (e.key !== 'Enter') return;
  e.preventDefault();
  const range = document.createRange();
  range.setStart(editor, 0);
  range.collapse(true);
  restore(range);
});
form.addEventListener('submit', e => e.preventDefault());

// ---- Pictures in the text: from the picture button, pasted, or dropped.
const isPicture = f => /^image\/(png|jpeg|gif|webp)$/.test(f.type);
function placePictures(list) {
  let markup = '';
  for (const f of list) {
    const n = ++pictureCount;
    pictures.set(n, f);
    markup += `<img src="${URL.createObjectURL(f)}" data-pic="${n}" alt="${escape(f.name || 'picture')}">`;
  }
  if (!markup) return;
  restore(saved);
  document.execCommand('insertHTML', false, markup);
  touched();
}
pictureInput.addEventListener('change', e => { if (e.isTrusted) wrote = true; placePictures([...pictureInput.files].filter(isPicture)); pictureInput.value = ''; });
// Files are picked here, in the reader, with its clip: Mail's own clip is
// not shown while writing end to end, and the keyboard stays in the reader,
// so your mark stays in view as you attach.
filesInput.addEventListener('change', e => { if (e.isTrusted) wrote = true; attach([...filesInput.files]); filesInput.value = ''; });
editor.addEventListener('paste', e => {
  const list = [...(e.clipboardData?.files || [])];
  if (!list.length) return;
  e.preventDefault();
  placePictures(list.filter(isPicture));
  attach(list.filter(f => !isPicture(f)));
});

// ---- Attachments: chips as Mail's, added from the clip (attach.html, a
// frame of this site in Mail's row of buttons) or dropped on the message.
const sizeText = n => n < 1024 ? `${n} B` : n < 1048576 ? `${Math.round(n / 1024)} KB` : `${(n / 1048576).toFixed(1)} MB`;
const total = () => files.reduce((n, f) => n + f.file.size, 0) + [...pictures.values()].reduce((n, f) => n + f.size, 0);
function attach(list) {
  for (const file of list) {
    if (!(file instanceof File) || !file.size) continue;
    if (total() + file.size > LIMIT) { tell({type: 'reader-error', message: 'End-to-end messages take files of up to 15 MB in all.'}); break; }
    const id = Math.random().toString(36).slice(2);
    files.push({file, id});
    const chipEl = document.createElement('span');
    chipEl.className = 'attachment';
    chipEl.dataset.id = id;
    const url = URL.createObjectURL(new Blob([file], {type: 'application/octet-stream'}));  // saved, never shown as a page of this site
    chipEl.innerHTML = `${icon('attach')}<a download="${escape(file.name)}" href="${url}" draggable="false">${escape(file.name)}</a><small>${sizeText(file.size)}</small>` +
      `<button class="icon-button" type="button" title="Remove" aria-label="Remove ${escape(file.name)}">${icon('close')}</button>`;
    chipEl.querySelector('button').addEventListener('click', () => {
      files.splice(files.findIndex(f => f.id === id), 1);
      URL.revokeObjectURL(url);
      chipEl.remove();
      touched();
      showSeal();
    });
    filesBox.append(chipEl);
    touched();
    showSeal();
  }
}
let dragging = 0;
const hasFiles = e => [...(e.dataTransfer?.types || [])].includes('Files');
form.addEventListener('dragenter', e => { if (hasFiles(e)) { dragging++; dropHint.hidden = false; } });
form.addEventListener('dragleave', e => { if (hasFiles(e) && --dragging <= 0) { dragging = 0; dropHint.hidden = true; } });
form.addEventListener('dragover', e => { if (hasFiles(e)) e.preventDefault(); });
form.addEventListener('drop', e => {
  if (!hasFiles(e)) return;
  e.preventDefault();
  dragging = 0;
  dropHint.hidden = true;
  const list = [...e.dataTransfer.files];
  if (editor.contains(e.target)) {
    const at = document.caretRangeFromPoint?.(e.clientX, e.clientY);
    if (at) saved = at;
    placePictures(list.filter(isPicture));
    attach(list.filter(f => !isPicture(f)));
  } else attach(list);
});

// ---- The mark, while this frame has the keyboard: a square of four pictures
// at the foot of the text, which a field that only looks like this one
// cannot show (Mail can neither read it nor have it shown elsewhere), and
// right above it the count of files this frame holds, which tells a file
// attached here from one Mail took. A tap on either says what they are, in a
// Material 3 rich tooltip; the first time, it says so by itself. Before this browser knows the mark, the square is empty. Nothing
// here takes the keyboard from the text.
dock.innerHTML = '<span class="mark-files" hidden></span>' +
  '<button class="mark-button" type="button" aria-haspopup="dialog" aria-expanded="false" aria-controls="mark-about"></button>' +
  '<div class="mark-about" id="mark-about" role="dialog" aria-labelledby="mark-about-title" hidden><p class="mark-about-title" id="mark-about-title">Your mark</p><div class="mark-about-text"></div>' +
  '<div class="mark-about-actions"><button class="text" type="button" data-got-it>Got it</button></div></div>';
const markButton = dock.querySelector('.mark-button'), markCount = dock.querySelector('.mark-files');
const about = dock.querySelector('.mark-about'), aboutText = about.querySelector('.mark-about-text');
const aboutActions = about.querySelector('.mark-about-actions');
let shownMark = null, shownText = '';
function setAbout(open) {
  if (open === !about.hidden) return;
  about.hidden = !open;
  markButton.setAttribute('aria-expanded', String(open));
  // Beside the mark, up from its foot, never past the top of the frame.
  if (open) about.style.maxHeight = Math.max(96, markButton.getBoundingClientRect().bottom - 16) + 'px';
}
function showSeal() {
  const m = own && markFor(own.subkeys);
  const shown = document.hasFocus() && !!from && engaged && whole && seen();
  dock.dataset.shown = String(shown);
  if (!shown) { setAbout(false); return; }
  markCount.hidden = !files.length;
  requestAnimationFrame(keepBar);  // a file in or out changes the room
  markCount.textContent = files.length === 1 ? '1 file' : files.length + ' files';
  editor.parentElement.classList.toggle('with-files', files.length > 0);
  const count = files.length ? `<p>The count above it is the files that go end to end. A file that does not raise it went to Mail.</p>` : '';
  const check = `<a href="/setup.html#keys" target="_blank" rel="noopener">${location.host}</a>`;
  const text = m
    ? '<p>Only Seal can show these four pictures, made from your key, and only here as you type. Mail and its server cannot. ' +
      'They are not part of the message, and nobody you write to sees them.</p>' + count +
      `<p>Your mark is next to your key at ${check}. If a composer like this one shows none or other pictures, stop typing there and report it.</p>`
    : '<p>Your four pictures appear in this square once you unlock encrypted mail in this browser. They are not part of the message.</p>' + count;
  // Drawn again only when it changes: a link pressed in it must still be there for the click.
  if (text !== shownText) aboutText.innerHTML = shownText = text;
  const state = m ? m.keyId + m.mark : '';
  if (state !== shownMark) {
    shownMark = state;
    markButton.innerHTML = m ? tile(m.mark) : '<span class="mark-tile" data-none role="img" aria-label="No mark yet"><span></span><span></span><span></span><span></span></span>';
    markButton.title = m ? 'What is this?' : 'Where is my mark?';
    aboutActions.querySelector('[data-report]')?.remove();
    if (m) aboutActions.insertAdjacentHTML('beforeend', `<a class="text" href="/setup.html#alarm" target="_blank" rel="noopener" data-report>Report</a>`);
    if (m && !explained(m.keyId)) setAbout(true);
  }
}
dock.addEventListener('mousedown', e => e.preventDefault());  // the caret stays in the text; a link still opens on the click
markButton.addEventListener('click', () => setAbout(about.hidden));
markCount.addEventListener('click', () => setAbout(about.hidden));
about.addEventListener('click', e => { if (e.target.closest('a')) setAbout(false); });  // the link opens in a tab of its own; the tooltip has done its work
about.querySelector('[data-got-it]').addEventListener('click', () => {
  const m = own && markFor(own.subkeys);
  if (m) setExplained(m.keyId);
  setAbout(false);
});
addEventListener('keydown', e => { if (e.key === 'Escape' && !about.hidden) { e.stopPropagation(); setAbout(false); } }, true);
addEventListener('pointerdown', e => { if (!about.hidden && !dock.contains(e.target)) setAbout(false); }, true);
addEventListener('focus', showSeal);
addEventListener('blur', showSeal);
document.addEventListener('focusin', showSeal);

// A phone's keyboard makes this frame shorter (Mail sizes it to end at the
// keyboard). The text stays where it was under the Subject line and moves only
// as far as the line with the caret needs to stay in sight, above your mark.
// A browser may scroll it on its own as the keyboard comes up: for a moment
// after, that is undone, until you touch, scroll or type.
let rest = editor.scrollTop, height = innerHeight, hold = null, until = 0;
const settled = () => hold !== null && performance.now() < until;
editor.addEventListener('scroll', () => {
  if (settled()) { if (editor.scrollTop !== hold) editor.scrollTop = hold; }
  else if (innerHeight === height) rest = editor.scrollTop;
});
addEventListener('scroll', () => { if (settled() && scrollY) scrollTo(0, 0); });
for (const type of ['touchstart', 'wheel', 'keydown', 'input']) editor.addEventListener(type, () => { hold = null; }, {passive: true});
addEventListener('resize', () => {
  height = innerHeight;
  if (scrollY) scrollTo(0, 0);
  editor.scrollTop = rest;
  const s = getSelection(), r = s.rangeCount && editor.contains(s.anchorNode) ? caretLine(s, editor) : null;
  if (r) {
    const box = editor.getBoundingClientRect(), style = getComputedStyle(editor);
    const top = box.top + parseFloat(style.paddingTop), end = box.bottom - parseFloat(style.paddingBottom);
    if (r.bottom > end) editor.scrollTop += r.bottom - end;
    else if (r.top < top) editor.scrollTop -= top - r.top;
  }
  hold = rest = editor.scrollTop;
  until = performance.now() + 700;
  keepBar();
});
// When the frame is shorter than the composer, the For and Subject lines
// scroll up while you write, so the bar rests on the frame's foot (on the
// keyboard) with the text and your mark above it; in a frame tall enough,
// nothing moves.
// The browser's own scroll toward the caret is undone, as in Mail; a scroll
// of your own (a touch, the wheel) stays.
let barAt = 0, ownScroll = false;
function keepBar() {
  document.body.classList.toggle('short', innerHeight < 300);
  const over = form.scrollHeight - form.clientHeight;
  barAt = over <= 0 ? 0 : document.activeElement === editor ? over : form.scrollTop;
  form.scrollTop = barAt;
}
form.addEventListener('scroll', () => { if (!ownScroll && form.scrollTop !== barAt) form.scrollTop = barAt; });
for (const type of ['touchstart', 'wheel']) form.addEventListener(type, () => { ownScroll = true; }, {passive: true});
addEventListener('resize', () => { ownScroll = false; });
editor.addEventListener('focus', () => requestAnimationFrame(keepBar));
// The line the caret is on. In an empty line a browser gives the caret no box:
// then the node beside it, never the whole field.
function caretLine(s, field) {
  const rects = s.getRangeAt(0).getClientRects();
  if (rects.length) return rects[0];
  const a = s.anchorNode, at = s.anchorOffset, line = parseFloat(getComputedStyle(field).lineHeight) || 24;
  const box = n => { if (n.nodeType === 1) return n.getBoundingClientRect(); const r = document.createRange(); r.selectNode(n); return r.getBoundingClientRect(); };
  let top;
  if (a.nodeType === 1 && a.childNodes[at]) top = box(a.childNodes[at]).top;
  else if (a.nodeType === 1 && at > 0) top = box(a.childNodes[at - 1]).bottom - line;
  else if (a !== field) top = box(a).top;
  else return null;
  return {top, bottom: top + line};
}

// ---- The message, encrypted.
// RFC 2047, for a header that is not plain ASCII.
const header = text => /^[\x20-\x7e]*$/.test(text) ? text : '=?UTF-8?B?' + b64(new TextEncoder().encode(text)) + '?=';
const list = addresses => addresses.join(', ');
function b64(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i += 32768) s += String.fromCharCode(...bytes.subarray(i, i + 32768));
  return btoa(s);
}
const lines = bytes => b64(bytes).replace(/.{76}/g, '$&\r\n').replace(/\r\n$/, '');
const boundary = kind => `=_reader_${kind}_${crypto.getRandomValues(new Uint32Array(3)).join('')}`;
const ascii = name => name.replace(/[^\x20-\x7e]|["\\]/g, '_') || 'file';
const named = (kind, name) => /^[\x20-\x7e]*$/.test(name) && !/["\\]/.test(name) ? `${kind}="${name}"`
  : `${kind}="${ascii(name)}"; ${kind}*=UTF-8''${encodeURIComponent(name).replace(/['()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase())}`;
const filePart = async (file, disposition, extra = '') => {
  const type = /^[\w.+-]+\/[\w.+-]+$/.test(file.type) ? file.type : 'application/octet-stream';
  return `Content-Type: ${type}; ${named('name', file.name || 'file')}\r\n${extra}Content-Disposition: ${disposition}; ${named('filename', file.name || 'file')}\r\n` +
         `Content-Transfer-Encoding: base64\r\n\r\n${lines(new Uint8Array(await file.arrayBuffer()))}\r\n`;
};

// The text as it goes out: the editor's HTML with its pictures named by
// Content-ID, and the same as plain text.
async function body() {
  const holder = document.createElement('template');  // inert: its pictures load nothing
  holder.innerHTML = editor.innerHTML;
  const copy = holder.content;
  const used = [];
  for (const img of copy.querySelectorAll('img')) {
    const n = Number(img.dataset.pic);
    if (!pictures.has(n)) { img.remove(); continue; }
    const id = `pic-${n}.${crypto.getRandomValues(new Uint32Array(2)).join('')}@reader`;
    used.push({file: pictures.get(n), id});
    img.setAttribute('src', 'cid:' + id);
    img.removeAttribute('data-pic');
  }
  const text = (editor.innerText || '').replace(/\u00a0/g, ' ').replace(/\n{3,}/g, '\n\n').trim();
  const html = '<!doctype html><html><head><meta charset="utf-8"></head><body>' + holder.innerHTML + '</body></html>';
  const enc = new TextEncoder();
  const alt = boundary('alt');
  let part = `Content-Type: multipart/alternative; boundary="${alt}"\r\n\r\n` +
    `--${alt}\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n${lines(enc.encode(text.replace(/\r?\n/g, '\r\n') + '\r\n'))}\r\n` +
    `--${alt}\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n${lines(enc.encode(html))}\r\n--${alt}--\r\n`;
  if (used.length) {
    const rel = boundary('rel');
    let wrapped = `Content-Type: multipart/related; boundary="${rel}"\r\n\r\n--${rel}\r\n${part}`;
    for (const p of used) wrapped += `--${rel}\r\n` + await filePart(p.file, 'inline', `Content-ID: <${p.id}>\r\n`);
    part = wrapped + `--${rel}--\r\n`;
  }
  return part;
}

// The whole message as MIME text, for the reader's Send (send.mjs), which
// seals and encrypts it: the headers people read travel inside
// (protected-headers="v1", as Thunderbird writes them; outside the subject
// is "..."), padded to a step of 4 KB (64 KB past 64 KB) with blank lines
// before the first part, which every mail program skips, so that the size
// of the encrypted message tells Mail little about how much was written.
async function message({to, cc, from: sender}) {
  // Send's sender and this composer's must agree, and be plain addresses, as
  // must everyone the message goes to: Mail hands over all of them.
  if (sender !== from || !ADDRESS.test(from) || [...to, ...cc].some(a => !ADDRESS.test(a)))
    throw new Error('The addresses Send and this message were given differ: nothing was sent. Reload the page.');
  if (!subject.value.trim() && !(editor.innerText || '').trim() && !files.length) throw new Error('The message is empty.');
  if (total() > LIMIT) throw new Error('End-to-end messages take files of up to 15 MB in all.');
  const heads = `From: ${from}\r\nTo: ${list(to)}\r\n` + (cc.length ? `Cc: ${list(cc)}\r\n` : '') +
                `Subject: ${header(subject.value.trim())}\r\nDate: ${new Date().toUTCString()}\r\n` +
                `Message-ID: <${crypto.randomUUID()}@${from.split('@')[1]}>\r\nMIME-Version: 1.0\r\n`;
  let inner = await body();
  if (files.length) {
    const mixed = boundary('mix');
    let all = `--${mixed}\r\n${inner}`;
    for (const f of files) all += `--${mixed}\r\n` + await filePart(f.file, 'attachment');
    inner = `Content-Type: multipart/mixed; boundary="${mixed}"; protected-headers="v1"\r\n${heads}\r\n${all}--${mixed}--\r\n`;
  } else {
    inner = inner.replace(/^Content-Type: ([^\r]+)\r\n/, (_, t) => `Content-Type: ${t}; protected-headers="v1"\r\n${heads}`);
  }
  const enc = new TextEncoder(), size = enc.encode(inner).length + 2;
  const step = size < 65536 ? 4096 : 65536, pad = Math.ceil(size / step) * step - size;
  const cut = inner.indexOf('\r\n\r\n') + 4;
  const filler = (' '.repeat(74) + '\r\n').repeat(Math.floor(pad / 76)) + ' '.repeat(pad % 76);
  return inner.slice(0, cut) + filler + '\r\n' + inner.slice(cut);
}

// Answering or forwarding an encrypted message: Mail hands over its
// encrypted text (its server has it anyway); with your key open, the reader
// opens it here and starts the new one as Mail would any other: "Re: " and
// the real subject, and the old text quoted under the signature.
async function answer(armored, mode) {
  const forward = mode === 'forward';
  try {
    const ids = await recipientsOf(armored), s = await vault.state();
    const keyId = ids.find(id => s.keyIds.includes(id));
    if (!keyId) return;
    const m = await openWith(armored, s.infos[keyId]);
    // Only a message you sealed comes back to edit: anyone can encrypt one
    // to your key, with any words and files in it.
    if (mode === 'edit') {
      if (m.seal?.state === 'ok' && m.seal.inside && addressOf(m.from) === from && editor.innerHTML === untouched && !subject.value) restoreMessage(m);
      return;
    }
    if (typed) return;
    const base = (m.subject || '').replace(/^\s*((re|fwd?|aw|wg)\s*:\s*)+/i, '');
    if (!subject.value && base) subject.value = (forward ? 'Fwd: ' : 'Re: ') + base;
    let text = m.text;
    if (text === undefined && m.html !== undefined) text = new DOMParser().parseFromString(m.html, 'text/html').body?.innerText || '';
    const date = m.date && !isNaN(new Date(m.date)) ? new Date(m.date).toLocaleString(undefined, {dateStyle: 'medium', timeStyle: 'short'}) : '';
    // Who wrote it, as the message says, only when its seal holds: anyone can
    // encrypt to your key and write any sender inside.
    const verified = m.seal?.state === 'ok' && m.seal.inside;
    const said = forward ? `---------- Forwarded message${verified ? '' : ' (not sealed)'} ----------`
                         : `On ${date}, ${m.from || 'the sender'} wrote${verified ? '' : ' (not sealed, so the sender is not verified)'}:`;
    const quote = escape((text || '').trim()).replace(/\r?\n/g, '<br>');
    editor.insertAdjacentHTML('beforeend', `<br><br><div class="quoted">${escape(said)}</div>` + (forward ? `<div>${quote}</div>` : `<blockquote>${quote}</blockquote>`));
    untouched = editor.innerHTML;
  } catch (e) {}  // locked, or not a message for this key: the subject stays to write
}

// A message of yours to change (Edit on a scheduled one): its subject, its
// text with the pictures in place, and its files come back into this
// composer. The text is cleaned as anything Mail hands over is: anyone can
// encrypt a message to your key, so the text earns no more trust than that.
function restoreMessage(m) {
  subject.value = m.subject || '';
  const isInline = f => f.id && isPicture(f) && (m.html || '').includes('cid:' + f.id);
  let html = m.html !== undefined ? m.html : escape(m.text || '').replace(/\r?\n/g, '<br>');
  html = html.replace(/<img\b[^>]*?\bsrc\s*=\s*["']?cid:([^"'\s>]+)["']?[^>]*>/gi, (all, cid) => {
    const f = m.files.find(x => x.id === cid && isPicture(x));
    if (!f) return '';
    const n = ++pictureCount;
    pictures.set(n, new File([f.data], f.name || 'picture', {type: f.type}));
    return `\ue000${n}\ue001`;  // a mark that cleaning keeps, for the picture to come back
  });
  editor.innerHTML = clean(html, true).replace(/\ue000(\d+)\ue001/g, (all, n) =>
    `<img src="${URL.createObjectURL(pictures.get(Number(n)))}" data-pic="${n}" alt="${escape(pictures.get(Number(n)).name)}">`);
  attach(m.files.filter(f => !isInline(f)).map(f => new File([f.data], f.name || 'attachment', {type: f.type || 'application/octet-stream'})));
  placeNotices();
  untouched = editor.innerHTML;
  showSeal();
}

// What Mail hands over at the start (the signature) is made plain markup:
// text, line breaks, links, bold and the signature's gray, nothing that runs
// or loads, no quote (only this composer quotes, from a message it opened
// itself), no runs of empty lines, and no more than a signature's length. A
// message of your own put back to edit keeps its quotes (ownWords).
function clean(html, ownWords = false) {
  const doc = new DOMParser().parseFromString(String(html || ''), 'text/html');
  const keep = new Set(['B', 'STRONG', 'I', 'EM', 'U', 'BR', 'P', 'DIV', 'SPAN', 'A', 'FONT', 'UL', 'OL', 'LI', ...(ownWords ? ['BLOCKQUOTE'] : [])]);
  const walk = node => {
    for (const child of [...node.childNodes]) {
      if (child.nodeType === 3) { child.data = child.data.replace(HIDDEN, ''); continue; }
      if (child.nodeType !== 1 || ['SCRIPT', 'STYLE', 'TEMPLATE', 'NOSCRIPT'].includes(child.tagName)) { child.remove(); continue; }
      walk(child);  // inside first, so what is lifted out of an element is clean already
      if (!keep.has(child.tagName)) { child.replaceWith(...child.childNodes); continue; }
      for (const a of [...child.attributes]) {
        const ok = (child.tagName === 'A' && a.name === 'href' && /^(https?:|mailto:)/i.test(a.value)) ||
                   // A signature's gray only: nothing Mail hands over can hide in tiny or
                   // pale letters and go out sealed as your words. Small type is for the
                   // reader's own notices (placeNotices), so Mail cannot dress a text of
                   // its own as one.
                   (child.tagName === 'FONT' && a.name === 'color' && /^#5f6368$/i.test(a.value)) ||
                   (a.name === 'class' && (a.value === 'signature' || (ownWords && a.value === 'quoted')));
        if (!ok) child.removeAttribute(a.name);
      }
      // A link that reads as one address and goes to another shows where it goes.
      if (child.tagName === 'A' && child.hasAttribute('href')) {
        const text = child.textContent.trim(), href = child.getAttribute('href');
        const host = s => { try { return new URL(/^[a-z]+:/i.test(s) ? s : 'https://' + s).hostname.replace(/^www\./, ''); } catch (e) { return null; } };
        if (/^\S+\.\S+$/.test(text) && /^https?:/i.test(href) && host(text) !== host(href)) child.textContent = href;
      }
    }
  };
  walk(doc.body);
  if (!ownWords) {
    // At most two empty lines in a row, and a signature's length of text.
    let blank = 0;
    for (const el of [...doc.body.querySelectorAll('br, div, p')]) {
      const empty = el.tagName === 'BR' || !el.textContent.trim();
      blank = empty ? blank + 1 : 0;
      if (empty && blank > 2) el.remove();
    }
    let left = 2000;
    const cut = node => {
      for (const child of [...node.childNodes]) {
        if (left <= 0) { child.remove(); continue; }
        if (child.nodeType === 3) { if (child.data.length > left) child.data = child.data.slice(0, left); left -= child.data.length; }
        else cut(child);
      }
    };
    cut(doc.body);
  }
  return doc.body.innerHTML;
}

// The notices under the signature: the reader writes them, from its own copy
// (notices.mjs), for the sender's domain. Mail hands over the signature
// alone; a paragraph that reads as a notice is taken out wherever it came
// from, and the reader's own go at the end of the signature, small and gray.
raised().then(at => {
  if (!at) return;
  const note = document.createElement('div');
  note.className = 'reader-alert';
  note.setAttribute('role', 'alert');
  note.innerHTML = `${icon('warning')}<div><p>${escape(alarmText())}</p></div>`;
  form.prepend(note);
});
const plainText = s => String(s || '').replace(/\s+/g, ' ').trim();
const known = new Set(Object.values(NOTICES).flatMap(n => [n.sealed, n.notice]).filter(Boolean).map(plainText));
function placeNotices() {
  for (const p of [...editor.querySelectorAll('p, div')]) if (known.has(plainText(p.textContent))) p.remove();
  const n = NOTICES[from.split('@')[1] || ''];
  if (!n) return;
  let sig = editor.querySelector(':scope > .signature');
  if (!sig) {
    sig = document.createElement('div');
    sig.className = 'signature';
    sig.innerHTML = '-- <br>';
    const quote = editor.querySelector(':scope > .quoted, :scope > blockquote');
    if (quote) quote.before(sig); else { editor.append(document.createElement('br'), document.createElement('br'), sig); }
  }
  // The notices come after everything Mail handed over, so nothing of its
  // own can sit under them; only a quote this composer made follows them.
  const quote = editor.querySelector(':scope > .quoted, :scope > blockquote');
  for (const t of [n.sealed, n.notice].filter(Boolean)) {
    const p = document.createElement('p');
    p.innerHTML = `<font size="2" color="#5f6368">${linkify(t)}</font>`;
    if (quote) quote.before(p); else editor.append(p);
  }
}

addEventListener('message', async e => {
  if (e.source !== parent || !MAIL_SITES.includes(e.origin)) return;
  parentOrigin = e.origin;
  const d = e.data || {};
  if (Number.isFinite(d.vw)) widths(d.vw);
  if (d.type === 'reader-compose' && !started) {  // the frame's first word from Mail: the start of the text, and who writes
    started = true;
    from = typeof d.from === 'string' && ADDRESS.test(d.from.toLowerCase()) ? d.from.toLowerCase() : '';
    if (from) keyOf(from).then(k => { own = k || null; showSeal(); });  // your key, for your mark (keys.mjs knows addresses by hash)
    if (typeof d.subject === 'string') subject.value = d.subject.slice(0, 998);
    editor.innerHTML = clean(d.html);
    placeNotices();
    untouched = editor.innerHTML;
    if (d.original && typeof d.original.armored === 'string' && d.original.armored.length <= 4e6) answer(d.original.armored, d.original.mode);
    for (const w of readerFrames('send.html')) w.postMessage({type: 'compose-hello'}, location.origin);  // Send shows us whom it encrypts to
    showSeal();
  }
});

// The reader's Send (send.mjs), in this tab, finds this composer itself and
// asks for the message once you press it; Mail cannot have it encrypted at
// any other time, nor have Send ask another composer. Only a composer you
// have typed into answers: one Mail filled with its own words does not.
// The For line also names who it is from, as Send will seal it: the address
// Send itself holds, not Mail's word for it.
// Beside an address outside our mailboxes, what Seal has for it (send.mjs).
const KEY_NOTE = {known: 'key from their mail', checked: 'key checked', changed: 'new key: accept it first', none: 'no key', unpublished: 'no key published yet'};
const listShown = (to, cc, bcc, sender, keys = {}) => {
  const line = document.getElementById('sealed-for'), who = document.getElementById('sealed-who');
  const all = [...to, ...cc];
  const named = list => list.map(a => escape(a) + (KEY_NOTE[keys[a]] ? ` <span class="key-note${['none', 'changed', 'unpublished'].includes(keys[a]) ? ' bad' : ''}">(${KEY_NOTE[keys[a]]})</span>` : '')).join(', ');
  who.classList.toggle('empty', !all.length && !bcc.length);
  who.innerHTML = (!all.length && !bcc.length ? 'Add who it is for above' :
    named(all) + (bcc.length ? `${all.length ? ' ' : ''}<span class="bcc">Bcc</span> ${named(bcc)}` : '')) +
    (sender ? `<span class="sealed-from">from ${escape(sender)}</span>` : '');
  line.title = 'Only these addresses and yours can open this message';
};
addEventListener('message', async e => {
  if (!fromOurFrame(e, 'send.html')) return;
  const x = e.data || {};
  const s = v => Array.isArray(v) ? v.filter(a => typeof a === 'string').map(a => a.toLowerCase()).slice(0, 100) : [];
  if (x.type === 'send-shows') {
    const keys = x.keys && typeof x.keys === 'object' ? Object.fromEntries(Object.entries(x.keys).filter(([, v]) => typeof v === 'string')) : {};
    listShown(s(x.to), s(x.cc), s(x.bcc), typeof x.from === 'string' && ADDRESS.test(x.from) ? x.from.toLowerCase() : '', keys);
    return;
  }
  if (x.type !== 'compose-message' || typeof x.id !== 'string') return;
  const reply = m => e.source.postMessage({type: 'message', id: x.id, ...m}, location.origin);
  if (!(wrote || (typed && seeing !== null))) { reply({error: 'Type into the message first, then press Send.'}); return; }
  if (!seen(1000)) { reply({error: 'The message is not fully in view: nothing was sent.'}); return; }
  try {
    reply({text: await message({to: s(x.to), cc: s(x.cc), from: typeof x.from === 'string' ? x.from : ''})});
    dirty = false;
  } catch (err) {
    reply({error: err.message});
  }
});
if (parent !== window) parent.postMessage({type: 'reader-ready'}, '*');
