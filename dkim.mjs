// A message's DKIM signature (RFC 6376; Ed25519, RFC 8463), checked here in
// the browser. The sender's mail service signs every message it sends with a
// key whose public half it publishes in its domain's DNS; our mail server
// does not hold that key, so a message it made up, or changed, does not pass.
// The key comes from public DNS through two resolvers of two companies,
// Cloudflare and Google, and counts only when both give the same: the mail
// server answers neither. They learn the signing domain and its selector
// (google._domainkey.a16z.com), which the message shows in the open anyway,
// and nothing else: no address, nothing of what is encrypted.
//
// It proves that the domain's mail service sent the message as it is (its
// sender, date, subject and whole body, the encrypted text included), not
// which person at that domain wrote it: that is the sender's own OpenPGP
// signature (decrypt.mjs).

const RESOLVERS = [
  name => `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=TXT`,
  name => `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=TXT`,
];

const latin1 = bytes => {
  let out = '';
  for (let i = 0; i < bytes.length; i += 0x8000) out += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return out;
};
const bytesOf = text => Uint8Array.from(text, c => c.charCodeAt(0));
const unbase64 = text => Uint8Array.from(atob(text), c => c.charCodeAt(0));
const sha256 = async text => new Uint8Array(await crypto.subtle.digest('SHA-256', bytesOf(text)));
const b64 = bytes => btoa(latin1(bytes));
const HOST = /^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*$/;

// The header fields (each with its folding and its CRLF) and the body of a
// message, with SMTP's line ends (a lone LF counts as CRLF).
export function fieldsOf(raw) {
  const text = (typeof raw === 'string' ? raw : latin1(raw)).replace(/\r?\n/g, '\r\n');
  const at = text.indexOf('\r\n\r\n');
  const head = at < 0 ? text : text.slice(0, at + 2), body = at < 0 ? '' : text.slice(at + 4);
  const fields = head.split(/\r\n(?![ \t])/).filter(Boolean).map(f => f + '\r\n');
  return {fields, body};
}
const nameOf = field => field.slice(0, Math.max(0, field.indexOf(':'))).replace(/[ \t]+$/, '').toLowerCase();
const valueOf = field => field.slice(field.indexOf(':') + 1).replace(/\r\n$/, '');
// Every value of a header field, in order.
export const values = (fields, name) => fields.filter(f => nameOf(f) === name).map(valueOf);

// tag=value; tag=value (section 3.2)
function tags(text) {
  const out = new Map();
  for (const part of text.split(';')) {
    const at = part.indexOf('=');
    if (at < 0) { if (part.trim()) return null; continue; }
    const name = part.slice(0, at).replace(/[ \t\r\n]/g, ''), value = part.slice(at + 1).replace(/^[ \t\r\n]+|[ \t\r\n]+$/g, '');
    if (!/^[A-Za-z][A-Za-z0-9_]*$/.test(name) || out.has(name)) return null;
    out.set(name, value);
  }
  return out;
}

// Canonical forms (section 3.4).
const relaxedField = field => nameOf(field) + ':' + valueOf(field).replace(/\r\n(?=[ \t])/g, '').replace(/[ \t]+/g, ' ').replace(/^ | $/g, '') + '\r\n';
function canonicalBody(body, relaxed) {
  let lines = body.split('\r\n');
  if (relaxed) lines = lines.map(l => l.replace(/[ \t]+$/, '').replace(/[ \t]+/g, ' '));
  let end = lines.length;
  while (end > 0 && lines[end - 1] === '') end--;
  if (!end) return relaxed ? '' : '\r\n';
  return lines.slice(0, end).join('\r\n') + '\r\n';
}

// TXT data as the resolvers give it: Cloudflare quotes each string of the
// record ("a" "b"), Google joins them.
function txtOf(data) {
  data = String(data);
  if (!data.startsWith('"')) return data;
  let out = '';
  for (let i = 0; i < data.length;) {
    if (data[i++] !== '"') continue;
    while (i < data.length && data[i] !== '"') {
      if (data[i] === '\\' && /^\d{3}$/.test(data.substr(i + 1, 3))) { out += String.fromCharCode(Number(data.substr(i + 1, 3))); i += 4; }
      else if (data[i] === '\\') { out += data[i + 1] || ''; i += 2; }
      else out += data[i++];
    }
    i++;
  }
  return out;
}

// The TXT records of a name, the same from both resolvers, or an error:
// 'unreachable' (a resolver did not answer) or 'disagree'.
const asked = new Map();
async function txt(name) {
  const hit = asked.get(name);
  if (hit && Date.now() - hit.at < 10 * 60e3) return hit.answer;
  const answer = Promise.all(RESOLVERS.map(async url => {
    const r = await fetch(url(name), {headers: {accept: 'application/dns-json'}, credentials: 'omit', referrerPolicy: 'no-referrer', cache: 'no-store', signal: AbortSignal.timeout(8000)});
    if (!r.ok) throw new Error('unreachable');
    const d = await r.json();
    if (d.Status !== 0 && d.Status !== 3) throw new Error('unreachable');  // 3: no such name
    return (d.Answer || []).filter(a => a.type === 16).map(a => txtOf(a.data)).sort();
  })).catch(() => { throw new Error('unreachable'); }).then(([a, b]) => {
    if (JSON.stringify(a) !== JSON.stringify(b)) throw new Error('disagree');
    return a;
  });
  asked.set(name, {at: Date.now(), answer});
  answer.catch(() => asked.delete(name));
  return answer;
}

// DER for an RSA key published bare (RSAPublicKey) rather than as
// SubjectPublicKeyInfo, which is what WebCrypto reads.
function spkiOf(rsaPublicKey) {
  const len = n => n < 128 ? [n] : n < 256 ? [0x81, n] : [0x82, n >> 8, n & 255];
  const tlv = (tag, bytes) => new Uint8Array([tag, ...len(bytes.length), ...bytes]);
  const algorithm = new Uint8Array([0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]);
  return tlv(0x30, new Uint8Array([...algorithm, ...tlv(0x03, new Uint8Array([0, ...rsaPublicKey]))]));
}
async function publicKey(kind, data) {
  if (kind === 'ed25519') {
    if (data.length !== 32) throw new Error('bad key');
    return crypto.subtle.importKey('raw', data, {name: 'Ed25519'}, false, ['verify']);
  }
  const algorithm = {name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256'};
  let key;
  try { key = await crypto.subtle.importKey('spki', data, algorithm, false, ['verify']); }
  catch (e) { key = await crypto.subtle.importKey('spki', spkiOf(data), algorithm, false, ['verify']); }
  if (key.algorithm.modulusLength < 1024) throw new Error('weak key');
  return key;
}

// One DKIM-Signature field, checked: {state: 'pass', domain, covers} or
// {state: 'fail' | 'unknown', why}.
async function one(field, fields, body) {
  const t = tags(valueOf(field));
  if (!t || t.get('v') !== '1') return {state: 'fail', why: 'unreadable'};
  const a = (t.get('a') || '').toLowerCase(), d = (t.get('d') || '').toLowerCase(), s = (t.get('s') || '').toLowerCase();
  const kind = a === 'rsa-sha256' ? 'rsa' : a === 'ed25519-sha256' ? 'ed25519' : null;
  if (!kind) return {state: 'fail', why: 'algorithm'};  // rsa-sha1 among them: no longer safe
  if (!HOST.test(d) || !HOST.test(s) || !d.includes('.')) return {state: 'fail', why: 'unreadable'};
  const covers = (t.get('h') || '').replace(/[ \t\r\n]/g, '').toLowerCase().split(':').filter(Boolean);
  if (!covers.includes('from')) return {state: 'fail', why: 'unreadable'};
  const i = (t.get('i') || '').toLowerCase(), iDomain = i.slice(i.lastIndexOf('@') + 1);
  if (i && iDomain !== d && !iDomain.endsWith('.' + d)) return {state: 'fail', why: 'unreadable'};
  const [hc, bc = 'simple'] = (t.get('c') || 'simple/simple').toLowerCase().split('/');
  if (!['simple', 'relaxed'].includes(hc) || !['simple', 'relaxed'].includes(bc)) return {state: 'fail', why: 'unreadable'};

  // The body: all of it signed, or the signature counts for nothing here
  // (l= leaves whatever follows open to anyone).
  const canon = canonicalBody(body, bc === 'relaxed');
  if (t.has('l') && !(/^\d{1,76}$/.test(t.get('l')) && Number(t.get('l')) >= canon.length)) return {state: 'fail', why: 'part'};
  if (b64(await sha256(canon)) !== (t.get('bh') || '').replace(/[ \t\r\n]/g, '')) return {state: 'fail', why: 'body'};

  // The header fields it covers, each taken from the bottom up, then the
  // signature's own field with its b= emptied.
  const canonField = hc === 'relaxed' ? relaxedField : f => f;
  const taken = new Map();
  let data = '';
  for (const name of covers) {
    const all = fields.filter(f => nameOf(f) === name), k = taken.get(name) || 0;
    if (k < all.length) { data += canonField(all[all.length - 1 - k]); taken.set(name, k + 1); }
  }
  data += canonField(field).replace(/\r\n$/, '').replace(/([;:][ \t\r\n]*b[ \t\r\n]*=)[^;]*/, '$1');

  let records;
  try { records = await txt(`${s}._domainkey.${d}`); }
  catch (e) { return {state: 'unknown', why: e.message}; }
  if (!records.length) return {state: 'fail', why: 'no key'};
  let signature;
  try { signature = unbase64((t.get('b') || '').replace(/[ \t\r\n]/g, '')); } catch (e) { return {state: 'fail', why: 'unreadable'}; }
  let why = 'signature';
  for (const record of records) {
    const k = tags(record);
    if (!k || (k.has('v') && k.get('v') !== 'DKIM1') || (k.get('k') || 'rsa').toLowerCase() !== kind) continue;
    if (k.has('h') && !k.get('h').toLowerCase().split(':').map(x => x.trim()).includes('sha256')) continue;
    if (k.has('s') && !k.get('s').split(':').map(x => x.trim()).some(x => x === '*' || x === 'email')) continue;
    const flags = (k.get('t') || '').split(':').map(x => x.trim().toLowerCase());
    if (flags.includes('s') && i && iDomain !== d) continue;
    const p = (k.get('p') || '').replace(/[ \t\r\n]/g, '');
    if (!p) { why = 'revoked'; continue; }  // the domain has withdrawn this key
    let ok = false;
    try {
      const key = await publicKey(kind, unbase64(p));
      ok = kind === 'rsa' ? await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, signature, bytesOf(data))
                          : await crypto.subtle.verify('Ed25519', key, signature, await sha256(data));
    } catch (e) {
      if (e.name === 'NotSupportedError') return {state: 'unknown', why: 'browser'};
      continue;
    }
    // A domain still trying DKIM out (t=y) asks that its signatures count
    // for nothing yet.
    if (ok) return flags.includes('y') ? {state: 'fail', why: 'testing'} : {state: 'pass', domain: d, covers};
  }
  return {state: 'fail', why};
}

// Whether two domains belong together the way DMARC's relaxed alignment
// asks: one is the other or under it.
const aligned = (a, b) => a === b || a.endsWith('.' + b) || b.endsWith('.' + a);

// The message's signatures, the best of them: {state: 'pass', domain,
// aligned (with the domain of From), covers (the header fields it signs)},
// or {state: 'fail' | 'unknown' | 'none', why}. from: the address in From.
export async function dkim(raw, fromAddress) {
  const {fields, body} = fieldsOf(raw);
  // Two From fields: the signature covers one, a mail program may show the
  // other.
  if (values(fields, 'from').length !== 1) return {state: 'fail', why: 'from'};
  const fromDomain = (fromAddress || '').split('@')[1] || '';
  const signatures = fields.filter(f => nameOf(f) === 'dkim-signature').slice(0, 5);
  if (!signatures.length) return {state: 'none'};
  const results = await Promise.all(signatures.map(f => one(f, fields, body).catch(() => ({state: 'fail', why: 'signature'}))));
  for (const r of results) if (r.state === 'pass') r.aligned = !!fromDomain && aligned(r.domain, fromDomain);
  return results.find(r => r.state === 'pass' && r.aligned) || results.find(r => r.state === 'pass') ||
         results.find(r => r.state === 'unknown') || results[0];
}
