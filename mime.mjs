// Reading the decrypted message (a MIME entity, RFC 2045 and 2046): its
// protected headers, its text or HTML, and its attachments. Nothing here
// touches the network or the page outside the reader.

const latin1 = bytes => Array.from(bytes, b => String.fromCharCode(b)).join('');

function decoder(charset) {
  try { return new TextDecoder((charset || 'utf-8').trim().toLowerCase()); } catch (e) { return new TextDecoder('utf-8'); }
}

// Header values with RFC 2047 words (=?charset?B?...?=) as text.
export function words(value) {
  return value.replace(/=\?([^?]+)\?([bqBQ])\?([^?]*)\?=(\s+(?==\?))?/g, (_, charset, kind, text) => {
    let bytes;
    if (kind.toLowerCase() === 'b') bytes = Uint8Array.from(atob(text.replace(/[^A-Za-z0-9+/=]/g, '')), c => c.charCodeAt(0));
    else bytes = Uint8Array.from(text.replace(/_/g, ' ').replace(/=([0-9A-Fa-f]{2})/g, (m, h) => String.fromCharCode(parseInt(h, 16))), c => c.charCodeAt(0));
    return decoder(charset).decode(bytes);
  });
}

function split(bytes) {
  for (let i = 0; i + 1 < bytes.length; i++) {
    if (bytes[i] === 10 && bytes[i + 1] === 10) return [bytes.subarray(0, i), bytes.subarray(i + 2)];
    if (bytes[i] === 13 && bytes[i + 1] === 10 && bytes[i + 2] === 13 && bytes[i + 3] === 10) return [bytes.subarray(0, i), bytes.subarray(i + 4)];
  }
  return [bytes, new Uint8Array(0)];
}

function headers(block) {
  const out = new Map();
  let name = null;
  for (const line of latin1(block).split(/\r?\n/)) {
    if (/^[ \t]/.test(line) && name) out.set(name, out.get(name) + ' ' + line.trim());
    else {
      const at = line.indexOf(':');
      if (at < 1) continue;
      name = line.slice(0, at).trim().toLowerCase();
      if (!out.has(name)) out.set(name, line.slice(at + 1).trim());
    }
  }
  return out;
}

// A parameter of a header (name, filename, charset, boundary). RFC 2231
// first: key*=charset'lang'percent-encoded, or in pieces (key*0*=, key*1=),
// which stands over the plain key= that mail apps add for older ones (often
// with _ for every letter outside ASCII); else the plain one, with any
// RFC 2047 words in it.
function param(value, key) {
  const v = String(value || ''), value_ = m => m[4] !== undefined ? m[4] : m[3];
  const pieces = [...v.matchAll(new RegExp(`(?:^|;)\\s*${key}\\*(\\d{1,2})?(\\*)?=\\s*("([^"]*)"|[^;\\s]*)`, 'gi'))]
    .map(m => ({n: m[1] === undefined ? -1 : Number(m[1]), encoded: m[1] === undefined || !!m[2], text: value_(m)}))
    .sort((a, b) => a.n - b.n);
  if (pieces.length) {
    let charset = 'utf-8';
    const bytes = [];
    pieces.forEach((p, i) => {
      let text = p.text;
      if (p.encoded && i === 0) {
        const head = /^([^']*)'[^']*'(.*)$/.exec(text);
        if (head) { charset = head[1] || 'utf-8'; text = head[2]; }
      }
      for (let j = 0; j < text.length; j++) {
        if (p.encoded && text[j] === '%' && /^[0-9A-Fa-f]{2}$/.test(text.substr(j + 1, 2))) { bytes.push(parseInt(text.substr(j + 1, 2), 16)); j += 2; }
        else bytes.push(text.charCodeAt(j) & 0xff);
      }
    });
    return decoder(charset).decode(Uint8Array.from(bytes));
  }
  const m = new RegExp(`(?:^|;)\\s*${key}=\\s*("([^"]*)"|[^;\\s]*)`, 'i').exec(v);
  return m ? words(m[2] !== undefined ? m[2] : m[1]) : '';
}

function body(bytes, transfer) {
  transfer = (transfer || '').toLowerCase();
  if (transfer === 'base64') return Uint8Array.from(atob(latin1(bytes).replace(/[^A-Za-z0-9+/=]/g, '')), c => c.charCodeAt(0));
  if (transfer === 'quoted-printable') {
    const text = latin1(bytes).replace(/=\r?\n/g, '');
    const out = [];
    for (let i = 0; i < text.length; i++) {
      if (text[i] === '=' && /^[0-9A-Fa-f]{2}$/.test(text.substr(i + 1, 2))) { out.push(parseInt(text.substr(i + 1, 2), 16)); i += 2; }
      else out.push(text.charCodeAt(i) & 0xff);
    }
    return new Uint8Array(out);
  }
  return bytes;
}

function parts(bytes, into, depth = 0) {
  const [block, rest] = split(bytes);
  const h = headers(block);
  const type = (h.get('content-type') || 'text/plain').split(';')[0].trim().toLowerCase();
  if (type.startsWith('multipart/') && depth < 8) {
    const boundary = param(h.get('content-type'), 'boundary');
    if (!boundary) return h;
    const text = latin1(rest), mark = '--' + boundary;
    let at = text.indexOf(mark);
    while (at !== -1) {
      const start = text.indexOf('\n', at) + 1;
      if (text.startsWith(mark + '--', at) || start === 0) break;
      const next = text.indexOf(mark, start);
      const end = next === -1 ? text.length : next;
      const chunk = rest.subarray(start, Math.max(start, end - (text[end - 2] === '\r' ? 2 : 1)));
      parts(chunk, into, depth + 1);
      at = next;
    }
    return h;
  }
  const disposition = (h.get('content-disposition') || '').toLowerCase();
  const name = param(h.get('content-disposition'), 'filename') || param(h.get('content-type'), 'name');
  const data = body(rest, h.get('content-transfer-encoding'));
  const id = (h.get('content-id') || '').replace(/[<>]/g, '');
  if ((type === 'text/plain' || type === 'text/html') && !disposition.startsWith('attachment') && !(name && type !== 'text/html' && type !== 'text/plain')) {
    const text = decoder(param(h.get('content-type'), 'charset')).decode(data);
    if (type === 'text/plain' && into.text === undefined) into.text = text;
    if (type === 'text/html' && into.html === undefined) into.html = text;
  } else {
    into.files.push({name: name || 'attachment', type, data, id});
  }
  return h;
}

// The message: subject, from, to, date (protected headers when there are any),
// text and/or HTML, and its files.
export function read(bytes) {
  const out = {files: []};
  const h = parts(bytes, out);
  out.subject = words(h.get('subject') || '');
  out.from = words(h.get('from') || '');
  out.to = words(h.get('to') || '');
  out.bcc = words(h.get('bcc') || '');  // in a Bcc's own copy: that reader alone (send.mjs)
  out.date = h.get('date') || '';
  return out;
}

// The address in a From line ("Name <a@b>" or a@b), in lower case.
export const addressOf = text => (/<([^<>\s]+@[^<>\s]+)>/.exec(text)?.[1] || /[^\s<>"',;]+@[^\s<>"',;]+/.exec(text)?.[0] || '').toLowerCase();

export const escape = text => text.replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));

// Plain text as HTML, with web addresses as links that open in a new tab.
export function linkify(text) {
  return escape(text).replace(/\bhttps?:\/\/[^\s<>"']+[^\s<>"'.,;:!?)]/g, url => `<a href="${url}" target="_blank" rel="noopener noreferrer">${url}</a>`);
}
