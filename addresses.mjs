// The Mail app's rule for addresses written out (app.js's addresses, in webmail/src/Assets.h; the server's Links.cpp),
// copied by make-styles.py. Do not edit here.
const addresses = (() => {
  const SITES = new Set(('com org net edu gov mil int info biz app dev tech online blog shop news live studio design agency digital law legal capital ventures fund ' +
    'partners ' +
    'ac ad ae af ag ai al am ao aq ar as at au aw ax az ba bb bd be bf bg bh bi bj bm bn bo br bs bt bw by bz ca cc cd cf cg ch ci ck cl cm cn ' +
    'co cr cu cv cw cx cy cz de dj dk dm do dz ec ee eg er es et eu fi fj fk fm fo fr ga gd ge gf gg gh gi gl gm gn gp gq gr gs gt gu gw gy hk ' +
    'hm hn hr ht hu id ie il im in io iq ir is it je jm jo jp ke kg kh ki km kn kp kr kw ky kz la lb lc li lk lr ls lt lu lv ly ma mc md me mg ' +
    'mh mk ml mm mn mo mp mq mr ms mt mu mv mw mx my mz na nc ne nf ng ni nl no np nr nu nz om pa pe pf pg ph pk pl pm pn pr ps pt pw py qa re ' +
    'ro rs ru rw sa sb sc sd se sg sh si sk sl sm sn so sr ss st su sv sx sy sz tc td tf tg th tj tk tl tm tn to tr tt tv tw tz ua ug uk us uy ' +
    'uz va vc ve vg vi vn vu wf ws ye yt za zm zw').split(' '));
  const FILES = new Set('ac am cc cf gd gs id in md mk ml mm ms pl pm ps pt py rs sc sh so sv tf'.split(' '));
  const WIDE = /[\u00A0\u2000-\u200B\u2028\u2029\u202F\u205F\u3000\uFEFF]/, CLOSING = '\u201D\u2019\u00BB\u2026\u2014\u2013\u203A\u3002\uFF0C\uFF09\u300D\u300F';
  const alnum = c => c !== undefined && /[A-Za-z0-9]/.test(c), digit = c => c !== undefined && c >= '0' && c <= '9';
  const local = c => c !== undefined && /[A-Za-z0-9._%+-]/.test(c);
  const opens = (t, i) => i === 0 || t[i - 1] <= ' ' || t.charCodeAt(i - 1) >= 0x80 || '([{<>"\'*,;:!?|'.includes(t[i - 1]);
  const glued = (t, i) => i < t.length && (alnum(t[i]) || '_@%+(=[{'.includes(t[i]));
  const restEnd = (t, from, start) => {
    const limit = Math.min(t.length, start + 2048);
    let j = from;
    while (j < limit && !(t[j] <= ' ' || '\x7f<>"`\\'.includes(t[j]) || WIDE.test(t[j]))) j++;
    let opened = 0, closed = 0, openedSq = 0, closedSq = 0;
    for (let k = from; k < j; k++) opened += t[k] === '(', closed += t[k] === ')', openedSq += t[k] === '[', closedSq += t[k] === ']';
    while (j > from) {
      const c = t[j - 1];
      if ('.,;:!?*_~\''.includes(c) || CLOSING.includes(c)) j--;
      else if (c === ')' && closed > opened) j--, closed--;
      else if (c === ']' && closedSq > openedSq) j--, closedSq--;
      else break;
    }
    return j;
  };
  const hostAt = (t, i) => {
    let j = i;
    while (j < t.length && j - i <= 253 && /[A-Za-z0-9.-]/.test(t[j])) j++;
    if (j - i > 253) return null;
    while (j > i && (t[j - 1] === '.' || t[j - 1] === '-')) j--;
    const labels = t.slice(i, j).split('.'), ending = labels[labels.length - 1];
    if (labels.length < 2 || labels.some(l => !l || l.length > 63 || l[0] === '-' || l[l.length - 1] === '-') || !/^[A-Za-z]{2,24}$/.test(ending)) return null;
    return {end: j, labels, ending};
  };
  const emailAt = (t, i) => {
    let j = i;
    while (j < t.length && j - i <= 64 && local(t[j])) j++;
    if (j === i || j - i > 64 || t[j] !== '@' || !alnum(t[i]) || t[j - 1] === '.' || t.slice(i, j).includes('..')) return null;
    const h = hostAt(t, j + 1);
    return h && !glued(t, h.end) ? {end: h.end, href: t.slice(i, h.end), email: true} : null;
  };
  const siteAt = (t, i) => {
    const h = hostAt(t, i);
    if (!h) return null;
    let needsPath = false;
    if (!(h.labels.length >= 3 && h.labels[0].toLowerCase() === 'www')) {
      const ending = h.ending.toLowerCase();
      // An ending in capitals only where all of it is (EXAMPLE.COM, not done.It).
      if (!SITES.has(ending) || (ending !== h.ending && /[a-z]/.test(t.slice(i, h.end)))) return null;
      needsPath = FILES.has(ending);
    }
    let e = h.end;
    if (t[e] === ':' && digit(t[e + 1])) {  // a port
      let p = e + 1;
      while (p < t.length && p - e <= 6 && digit(t[p])) p++;
      if (p - e - 1 <= 5 && !alnum(t[p])) e = p;
    }
    if (glued(t, e)) return null;
    const end = e < t.length && '/?#'.includes(t[e]) ? restEnd(t, e, i) : e;
    if (needsPath && !(t[e] === '/' && end > e + 1)) return null;
    return {end, href: 'https://' + t.slice(i, end), email: false};
  };
  const at = (t, i) => {
    if (!alnum(t[i]) || (i > 0 && alnum(t[i - 1]))) return null;
    for (const scheme of ['https://', 'http://']) {
      if (t.slice(i, i + scheme.length).toLowerCase() !== scheme) continue;
      const from = i + scheme.length, c = t[from];
      if (c === undefined || !(alnum(c) || c === '[' || (c.charCodeAt(0) >= 0x80 && !WIDE.test(c)))) return null;
      const end = restEnd(t, from, i);
      return end === from ? null : {end, href: scheme + t.slice(from, end), email: false};
    }
    if (t.slice(i, i + 7).toLowerCase() === 'mailto:') return emailAt(t, i + 7);
    if (!opens(t, i)) return null;
    let j = i;  // an email address and a site's name start alike, up to an @
    while (j < t.length && j - i <= 64 && local(t[j])) j++;
    return t[j] === '@' ? emailAt(t, i) : siteAt(t, i);
  };
  // Every address that starts in t[from, to) and ends by `to`, each with its start.
  const all = (t, from = 0, to = t.length) => {
    const out = [];
    for (let i = from; i < to;) {
      const f = alnum(t[i]) ? at(t, i) : null;
      if (f && f.end <= to) { out.push({start: i, ...f}); i = f.end; } else i++;
    }
    return out;
  };
  return {at, all};
})();
export const {at, all} = addresses;
