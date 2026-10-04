// The alarm: raised by you on this site's own page (setup.html), when a
// composer showed no mark, or not yours. It is kept in this site's storage,
// which the Mail app cannot reach, so only you can raise or clear it: while it
// stands, the worker takes no key (sw.js), Unlock and Send refuse, and every
// frame of the reader says why.
const DB = 'reader-alarm', STORE = 'alarm', KEY = 'raised';

function open() {
  return new Promise((resolve, reject) => {
    const r = indexedDB.open(DB, 1);
    r.onupgradeneeded = () => r.result.createObjectStore(STORE);
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}
async function run(mode, f) {
  const db = await open();
  try {
    return await new Promise((resolve, reject) => {
      const t = db.transaction(STORE, mode), req = f(t.objectStore(STORE));
      t.oncomplete = () => resolve(req?.result);
      t.onerror = () => reject(t.error);
    });
  } finally { db.close(); }
}

// When it was raised (an ISO date), or null.
export async function raised() {
  try { const v = await run('readonly', s => s.get(KEY)); return v && typeof v.at === 'string' ? v.at : null; } catch (e) { return null; }
}
export const raise = () => run('readwrite', s => s.put({at: new Date().toISOString()}, KEY));
export const clear = () => run('readwrite', s => s.delete(KEY));

// What a frame of the reader says while it stands.
export const alarmText = () => `You reported a problem in this browser. Encrypted mail stays locked here until you clear the report at ${location.host}/setup.html.`;
