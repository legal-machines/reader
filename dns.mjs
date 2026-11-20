// The DKIM key of a sender's domain, from public DNS through Cloudflare and
// Google (both must give the same), for the page of this site that frames
// this one (dkim.mjs). This page is apart so that the pages that hold
// messages and keys reach no network at all. It takes only a DKIM key name.

const RESOLVERS = [
  name => `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=TXT`,
  name => `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=TXT`,
];
const NAME = /^(?=.{1,253}$)[a-z0-9_]([a-z0-9_.-]*[a-z0-9_])?\._domainkey\.[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/;

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

async function ask(name) {
  const answers = await Promise.all(RESOLVERS.map(async url => {
    const r = await fetch(url(name), {headers: {accept: 'application/dns-json'}, credentials: 'omit', referrerPolicy: 'no-referrer', cache: 'no-store', signal: AbortSignal.timeout(8000)});
    if (!r.ok) throw new Error('unreachable');
    const d = await r.json();
    if (d.Status !== 0 && d.Status !== 3) throw new Error('unreachable');  // 3: no such name
    return (d.Answer || []).filter(a => a.type === 16).map(a => txtOf(a.data)).sort();
  })).catch(() => { throw new Error('unreachable'); });
  if (JSON.stringify(answers[0]) !== JSON.stringify(answers[1])) throw new Error('disagree');
  return answers[0];
}

if (parent !== window) {
  addEventListener('message', async e => {
    if (e.source !== parent || e.origin !== location.origin || e.data?.type !== 'dns-ask') return;
    const {id, name} = e.data;
    try {
      if (typeof name !== 'string' || !NAME.test(name)) throw new Error('unreadable');
      parent.postMessage({type: 'dns-answer', id, records: await ask(name)}, location.origin);
    } catch (err) {
      parent.postMessage({type: 'dns-answer', id, error: err.message}, location.origin);
    }
  });
  parent.postMessage({type: 'dns-ready'}, location.origin);
}
