// Fetches one of our public keys from the Web Key Directory (RFC draft, the
// advanced method: openpgpkey.<domain>), for the page of this site that
// frames this one (wkd.mjs). It takes only an address at one of our domains.
const DOMAINS = ['legalmachines.org', 'dzyza.com'];
const ZBASE32 = 'ybndrfg8ejkmcpqxot1uwisza345h769';
async function wkdHash(local) {
  const d = new Uint8Array(await crypto.subtle.digest('SHA-1', new TextEncoder().encode(local.toLowerCase())));
  let bits = '';
  for (const b of d) bits += b.toString(2).padStart(8, '0');
  let out = '';
  for (let i = 0; i < bits.length; i += 5) out += ZBASE32[parseInt(bits.slice(i, i + 5).padEnd(5, '0'), 2)];
  return out;
}
if (parent !== window) {
  addEventListener('message', async e => {
    if (e.source !== parent || e.origin !== location.origin || e.data?.type !== 'wkd-ask') return;
    const {id, address} = e.data;
    try {
      const m = /^([a-z0-9._%+-]{1,64})@([a-z0-9.-]+)$/.exec(String(address || '').toLowerCase());
      if (!m || !DOMAINS.includes(m[2])) throw new Error('not ours');
      // Without ?l=: the local part does not leave this browser, only its hash.
      const url = `https://openpgpkey.${m[2]}/.well-known/openpgpkey/${m[2]}/hu/${await wkdHash(m[1])}`;
      const r = await fetch(url, {credentials: 'omit', referrerPolicy: 'no-referrer', cache: 'no-store', signal: AbortSignal.timeout(10000)});
      if (!r.ok) throw new Error('not found');
      const bytes = new Uint8Array(await r.arrayBuffer());
      if (bytes.length > 64000) throw new Error('too large');
      parent.postMessage({type: 'wkd-answer', id, bytes}, location.origin);
    } catch (err) {
      parent.postMessage({type: 'wkd-answer', id, error: err.message}, location.origin);
    }
  });
  parent.postMessage({type: 'wkd-ready'}, location.origin);
}
