// Link a device (link.mjs, qr.mjs): the codes this site draws read back as
// written (with jsqr.js, as link.html reads them), and the key travels only
// to the device whose code was read, unchanged, and nowhere else.
// Plain node: node tests/link.mjs
import {createRequire} from 'node:module';
import {qr} from '../qr.mjs';
import {newOffer, offerUrl, readOffer, sealFor, openFrom, packKey, unpackKey, b64u} from '../link.mjs';

const jsQR = createRequire(import.meta.url)('../jsqr.js');
let failures = 0, checks = 0;
const check = (ok, what) => { checks++; if (!ok) { failures++; console.log('FAIL: ' + what); } };
const rejects = async (p) => { try { await p; return false; } catch (e) { return true; } };

// A code as a camera would see it: four pixels a module, a quiet zone of four.
function read(text) {
  const m = qr(text), scale = 4, size = (m.length + 8) * scale;
  const px = new Uint8ClampedArray(size * size * 4).fill(255);
  m.forEach((row, r) => row.forEach((on, c) => {
    if (!on) return;
    for (let y = 0; y < scale; y++) for (let x = 0; x < scale; x++) {
      const i = (((r + 4) * scale + y) * size + (c + 4) * scale + x) * 4;
      px[i] = px[i + 1] = px[i + 2] = 0;
    }
  }));
  return {got: jsQR(px, size, size)?.data, version: (m.length - 17) / 4};
}

// Every length the code holds, versions 1 to 9, read back as written.
const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.';
const versions = new Set();
for (let n = 1; n <= 180; n += n < 40 ? 1 : 7) {
  let text = '';
  for (let i = 0; i < n; i++) text += alphabet[(i * 37 + n * 11) % alphabet.length];
  const {got, version} = read(text);
  versions.add(version);
  check(got === text, `a code of ${n} characters (version ${version}) reads back`);
}
check([1, 2, 3, 4, 5, 6, 7, 8, 9].every(v => versions.has(v)), 'versions 1 to 9 are all drawn');
let tooLong = false;
try { qr('x'.repeat(200)); } catch (e) { tooLong = true; }
check(tooLong, 'a text too long for version 9 is refused');

// A real offer: its code reads back, and only its own form is taken.
const offer = await newOffer();
check(read(offer.text).got === offer.text && read(offer.text).version <= 5, 'an offer\'s code reads back, small enough to scan');
const read1 = readOffer(offer.text);
check(read1 && read1.channel === offer.channel && b64u(read1.pub) === b64u(offer.pub), 'the offer read from its text');
for (const junk of ['', 'SEAL1', 'SEAL2.' + offer.text.slice(6), offer.text + 'A', 'https://example.com/', offer.text.replace('SEAL1.', 'SEAL1..')])
  check(readOffer(junk) === null, `not an offer: ${JSON.stringify(junk.slice(0, 20))}`);

// A key, as a record describes it, there and back.
const record = {keyId: '0123456789abcdef', info: {fingerprint: 'ab'.repeat(20), keyId: '0123456789abcdef', hash: 8, cipher: 9},
  addresses: ['Someone@legalmachines.org'], signer: {keyId: 'fedcba9876543210', fingerprint: 'cd'.repeat(20)}};
const scalar = crypto.getRandomValues(new Uint8Array(32)), seed = crypto.getRandomValues(new Uint8Array(32));
const pkcs8 = new Uint8Array([...new Uint8Array(16), ...scalar]).buffer, signPkcs8 = new Uint8Array([...new Uint8Array(16), ...seed]).buffer;
const blob = await sealFor(read1, packKey(record, pkcs8, signPkcs8));
const back = unpackKey(await openFrom(offer, blob));
check(b64u(back.scalar) === b64u(scalar) && b64u(back.seed) === b64u(seed) && back.keyId === record.keyId && back.addresses[0] === 'someone@legalmachines.org' &&
      back.signer.fingerprint === record.signer.fingerprint, 'the key arrives whole at the device whose code was read');
check(!blob.includes(b64u(scalar)) && !blob.includes(b64u(seed)), 'nothing of the key shows in what Mail carries');

// Only that device: another offer, a changed byte, another channel.
const other = await newOffer();
check(await rejects(openFrom(other, blob)), 'another device cannot open it');
const d = JSON.parse(blob), bytes = Uint8Array.from(atob(d.sealed.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
bytes[5] ^= 1;
check(await rejects(openFrom(offer, JSON.stringify({...d, sealed: b64u(bytes)}))), 'a changed byte does not open');
check(await rejects(openFrom({...offer, channel: other.channel}, blob)), 'it opens only on its own channel');
check(await rejects(openFrom(offer, JSON.stringify({...d, pub: b64u(other.pub)}))), 'with another sender\'s half it does not open');
check(await rejects(openFrom(offer, 'not json')) && await rejects(openFrom(offer, JSON.stringify({v: 2}))), 'what is not a link\'s answer is refused');
// A public half of low order (all zeros) gives no key.
check(await rejects(sealFor({channel: offer.channel, pub: new Uint8Array(32)}, new Uint8Array(4))), 'a public half of low order is refused');
// Shapes that are not a key.
const bad = obj => { try { unpackKey(new TextEncoder().encode(JSON.stringify(obj))); return false; } catch (e) { return true; } };
const good = {v: 1, keyId: record.keyId, info: record.info, addresses: ['a@legalmachines.org'], scalar: b64u(scalar), signer: null, seed: null};
check(!bad(good), 'a key without the part that signs is taken');
check(bad({...good, keyId: 'zz'}) && bad({...good, scalar: b64u(new Uint8Array(31))}) && bad({...good, addresses: []}) && bad({...good, info: {...good.info, keyId: 'ffffffffffffffff'}}),
      'a key of the wrong shape is refused');

// The code as a new device shows it: an address of Seal's link page, which a
// phone's own camera opens; it reads as the offer it carries, and nothing
// else that looks like an address does.
{
  const url = offerUrl(offer, 'https://seal.legalmachines.org');
  check(url === 'https://seal.legalmachines.org/link.html#' + offer.text, 'the code is the link page with the offer after the #');
  check(read(url).got === url && read(url).version <= 7, `the address as a code reads back (version ${read(url).version}), for any phone's camera`);
  const fromUrl = readOffer(url);
  check(fromUrl && fromUrl.channel === offer.channel && b64u(fromUrl.pub) === b64u(offer.pub), 'the address reads as its offer');
  check(readOffer('  ' + url + '  ')?.channel === offer.channel, 'with spaces around it too');
  for (const wrong of ['https://seal.legalmachines.org/setup.html#' + offer.text, 'https://seal.legalmachines.org/link.html', 'https://seal.legalmachines.org/link.html#' + offer.text + 'x',
                       'https://seal.legalmachines.org/link.html?' + offer.text, 'https://[bad/link.html#' + offer.text, 'javascript:alert(1)//link.html#' + offer.text])
    check(readOffer(wrong) === null, `not a code: ${wrong.slice(0, 48)}`);
}

console.log(`${checks - failures} of ${checks} checks passed`);
process.exit(failures ? 1 : 0);
