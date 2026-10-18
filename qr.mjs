// A QR code of a short text, made here (ISO/IEC 18004): byte mode, error
// correction level M, versions 1 to 9, the mask with the lowest penalty.
// Enough for Link a device (link.mjs), whose code is some 75 characters; no
// code of anyone else's is needed for it. qr(text) gives the modules as rows
// of booleans (true is dark), svg(text) a picture of them with the quiet zone.

// Per version (index 1 to 9) at level M: error correction codewords per
// block, and the blocks as [count, data codewords] groups.
const LEVEL_M = [null,
  [10, [[1, 16]]], [16, [[1, 28]]], [26, [[1, 44]]], [18, [[2, 32]]], [24, [[2, 43]]],
  [16, [[4, 27]]], [18, [[4, 31]]], [22, [[2, 38], [2, 39]]], [22, [[3, 36], [2, 37]]]];
const ALIGN = [null, [], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34], [6, 22, 38], [6, 24, 42], [6, 26, 46]];
const REMAINDER = [0, 0, 7, 7, 7, 7, 7, 0, 0, 0];

// GF(256) with the polynomial x^8 + x^4 + x^3 + x^2 + 1, for Reed-Solomon.
const EXP = new Uint8Array(512), LOG = new Uint8Array(256);
for (let i = 0, x = 1; i < 255; i++) { EXP[i] = x; LOG[x] = i; x = (x << 1) ^ (x & 0x80 ? 0x11d : 0); }
for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
const mul = (a, b) => (a && b ? EXP[LOG[a] + LOG[b]] : 0);

// The error correction codewords of one block: the remainder of the data
// times x^n divided by the generator (x - a^0)(x - a^1)...(x - a^(n-1)).
function eccOf(data, n) {
  let gen = [1];
  for (let i = 0; i < n; i++) {
    const next = new Array(gen.length + 1).fill(0);
    for (let j = 0; j < gen.length; j++) { next[j] ^= gen[j]; next[j + 1] ^= mul(gen[j], EXP[i]); }
    gen = next;
  }
  const rest = [...data, ...new Array(n).fill(0)];
  for (let i = 0; i < data.length; i++) {
    const f = rest[i];
    if (f) for (let j = 1; j < gen.length; j++) rest[i + j] ^= mul(gen[j], f);
  }
  return rest.slice(data.length);
}

// The codewords in the order the symbol holds them: data and error
// correction, each interleaved across the blocks.
function codewords(bytes, version) {
  const [ecc, groups] = LEVEL_M[version];
  const capacity = groups.reduce((s, [c, d]) => s + c * d, 0);
  const bits = [];
  const put = (value, length) => { for (let i = length - 1; i >= 0; i--) bits.push((value >>> i) & 1); };
  put(0b0100, 4);              // byte mode
  put(bytes.length, 8);        // its count (8 bits up to version 9)
  for (const b of bytes) put(b, 8);
  put(0, Math.min(4, capacity * 8 - bits.length));  // terminator
  while (bits.length % 8) bits.push(0);
  const data = [];
  for (let i = 0; i < bits.length; i += 8) data.push(bits.slice(i, i + 8).reduce((v, b) => (v << 1) | b, 0));
  for (let pad = 0; data.length < capacity; pad ^= 1) data.push(pad ? 0x11 : 0xec);
  const blocks = [];
  let at = 0;
  for (const [count, size] of groups) for (let i = 0; i < count; i++) { const d = data.slice(at, at + size); at += size; blocks.push({d, e: eccOf(d, ecc)}); }
  const out = [];
  const longest = Math.max(...blocks.map(b => b.d.length));
  for (let i = 0; i < longest; i++) for (const b of blocks) if (i < b.d.length) out.push(b.d[i]);
  for (let i = 0; i < ecc; i++) for (const b of blocks) out.push(b.e[i]);
  return out;
}

// BCH codes of the format (15, 5) and the version (18, 6) information.
function bch(value, poly, bits) {
  let v = value << bits;
  const top = 31 - Math.clz32(poly);
  while (31 - Math.clz32(v) >= top) v ^= poly << (31 - Math.clz32(v) - top);
  return (value << bits) | v;
}

const MASKS = [
  (r, c) => (r + c) % 2 === 0, (r) => r % 2 === 0, (r, c) => c % 3 === 0, (r, c) => (r + c) % 3 === 0,
  (r, c) => (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0, (r, c) => (r * c) % 2 + (r * c) % 3 === 0,
  (r, c) => ((r * c) % 2 + (r * c) % 3) % 2 === 0, (r, c) => ((r + c) % 2 + (r * c) % 3) % 2 === 0];

function build(version, words, mask) {
  const size = 17 + 4 * version;
  const dark = Array.from({length: size}, () => new Array(size).fill(false));
  const fixed = Array.from({length: size}, () => new Array(size).fill(false));
  const set = (r, c, on) => { dark[r][c] = on; fixed[r][c] = true; };
  // Finder patterns with their separators.
  for (const [r0, c0] of [[0, 0], [0, size - 7], [size - 7, 0]])
    for (let r = -1; r <= 7; r++) for (let c = -1; c <= 7; c++) {
      const rr = r0 + r, cc = c0 + c;
      if (rr < 0 || cc < 0 || rr >= size || cc >= size) continue;
      const ring = Math.max(Math.abs(r - 3), Math.abs(c - 3));
      set(rr, cc, ring !== 2 && ring !== 4);
    }
  // Timing patterns.
  for (let i = 8; i < size - 8; i++) { set(6, i, i % 2 === 0); set(i, 6, i % 2 === 0); }
  // Alignment patterns, where no finder pattern is.
  const at = ALIGN[version];
  for (const r of at) for (const c of at) {
    if ((r === 6 && c === 6) || (r === 6 && c === at[at.length - 1]) || (r === at[at.length - 1] && c === 6)) continue;
    for (let dr = -2; dr <= 2; dr++) for (let dc = -2; dc <= 2; dc++) set(r + dr, c + dc, Math.max(Math.abs(dr), Math.abs(dc)) !== 1);
  }
  // Format information (level M is 00), and the dark module.
  const format = bch((0b00 << 3) | mask, 0x537, 10) ^ 0x5412;
  const fbit = i => ((format >>> i) & 1) === 1;
  for (let i = 0; i <= 5; i++) set(i, 8, fbit(i));
  set(7, 8, fbit(6)); set(8, 8, fbit(7)); set(8, 7, fbit(8));
  for (let i = 9; i < 15; i++) set(8, 14 - i, fbit(i));
  for (let i = 0; i < 8; i++) set(8, size - 1 - i, fbit(i));
  for (let i = 8; i < 15; i++) set(size - 15 + i, 8, fbit(i));
  set(size - 8, 8, true);
  // Version information, from version 7.
  if (version >= 7) {
    const v = bch(version, 0x1f25, 12);
    for (let i = 0; i < 18; i++) {
      const on = ((v >>> i) & 1) === 1, a = size - 11 + (i % 3), b = Math.floor(i / 3);
      set(a, b, on); set(b, a, on);
    }
  }
  // The codewords, two columns at a time from the bottom right, in a zigzag.
  const bits = [];
  for (const w of words) for (let i = 7; i >= 0; i--) bits.push(((w >>> i) & 1) === 1);
  for (let i = 0; i < REMAINDER[version]; i++) bits.push(false);
  let k = 0;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < size; vert++) {
      for (let j = 0; j < 2; j++) {
        const c = right - j, upward = ((right + 1) & 2) === 0, r = upward ? size - 1 - vert : vert;
        if (fixed[r][c]) continue;
        const on = k < bits.length ? bits[k++] : false;
        dark[r][c] = on !== MASKS[mask](r, c);
      }
    }
  }
  return dark;
}

// The penalty of a symbol (rules N1 to N4): the mask chosen has the lowest.
function penalty(m) {
  const size = m.length;
  let score = 0;
  const lines = [];
  for (let i = 0; i < size; i++) { lines.push(m[i]); lines.push(m.map(row => row[i])); }
  for (const line of lines) {
    for (let i = 0, run = 1; i < size; i++) {
      if (i + 1 < size && line[i + 1] === line[i]) { run++; continue; }
      if (run >= 5) score += run - 2;
      run = 1;
    }
    for (let i = 0; i + 11 <= size; i++) {
      const s = line.slice(i, i + 11).map(Number).join('');
      if (s === '10111010000' || s === '00001011101') score += 40;
    }
  }
  for (let r = 0; r + 1 < size; r++) for (let c = 0; c + 1 < size; c++) {
    const v = m[r][c];
    if (m[r][c + 1] === v && m[r + 1][c] === v && m[r + 1][c + 1] === v) score += 3;
  }
  const darkCount = m.reduce((s, row) => s + row.filter(Boolean).length, 0);
  score += Math.floor(Math.abs(darkCount * 20 - size * size * 10) / (size * size)) * 10;
  return score;
}

export function qr(text) {
  const bytes = [...new TextEncoder().encode(text)];
  let version = 1;
  while (version <= 9) {
    const [, groups] = LEVEL_M[version];
    const capacity = groups.reduce((s, [c, d]) => s + c * d, 0);
    if (4 + 8 + bytes.length * 8 <= capacity * 8) break;
    version++;
  }
  if (version > 9) throw new Error('Too long for a QR code here.');
  const words = codewords(bytes, version);
  let best = null, bestScore = Infinity;
  for (let mask = 0; mask < 8; mask++) {
    const m = build(version, words, mask), s = penalty(m);
    if (s < bestScore) { best = m; bestScore = s; }
  }
  return best;
}

// The code as an SVG picture, dark on light with four modules of quiet zone
// (its colours fixed: a camera reads dark on light, whatever the page's theme).
export function svg(text, label = 'QR code') {
  const m = qr(text), size = m.length + 8;
  let path = '';
  m.forEach((row, r) => row.forEach((on, c) => { if (on) path += `M${c + 4} ${r + 4}h1v1h-1z`; }));
  return `<svg class="qr" viewBox="0 0 ${size} ${size}" role="img" aria-label="${label}" shape-rendering="crispEdges">` +
    `<rect width="${size}" height="${size}" fill="#fff"/><path d="${path}" fill="#000"/></svg>`;
}
