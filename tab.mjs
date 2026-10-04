// The reader's own frames in this tab. A page may reach the frames of the
// tab it is in, and use those of its own site: so Send finds the composer
// itself, and the composer finds Send, by walking the tab's frames from the
// top. Mail cannot point them at other frames, put one in another tab, or
// hide a second composer from Send.
export function readerFrames(page) {
  const found = [];
  const walk = w => {
    let n = 0;
    try { n = w.frames.length; } catch (e) { return; }
    for (let i = 0; i < n; i++) {
      let f = null;
      try { f = w.frames[i]; } catch (e) { continue; }
      try { if (f.location.origin === location.origin && f.location.pathname.endsWith('/' + page)) found.push(f); } catch (e) {}  // another site's frame
      walk(f);
    }
  };
  walk(top);
  return found;
}

// Whether a message came from one of the reader's own frames in this tab,
// a given page of it.
export function fromOurFrame(e, page) {
  if (e.origin !== location.origin || !e.source) return false;
  try { return e.source.top === top && e.source.location.pathname.endsWith('/' + page); } catch (err) { return false; }
}
