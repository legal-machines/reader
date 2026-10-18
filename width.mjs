// The Mail app's window width, which its stylesheet's rules for narrow
// windows follow (make-styles.py keys them to classes on the root): a frame
// is narrower than the window, and must look as the page around it does.
// Until the page says, the frame's own width stands in.
export function widths(vw) {
  const w = Number.isFinite(vw) && vw > 0 ? vw : innerWidth;
  const root = document.documentElement.classList;
  root.toggle('narrow', w <= 840);
  root.toggle('phone', w <= 640);
  root.toggle('wide', w >= 841);
}
widths();

// A frame that came without its styles shows its icons as large as it is
// wide. That happens when a newer Seal's worker takes over while the frame
// loads: the older worker, which served the page, finds its copy of the
// files gone and has no stylesheet to give. Loaded again, it comes whole from
// the newer worker; once a minute at most, so that nothing can loop.
{
  const whole = [...document.querySelectorAll('link[rel=stylesheet]')].every(l => { try { return l.sheet?.cssRules.length > 0; } catch (e) { return false; } });
  if (!whole) {
    let last = 0;
    try { last = Number(sessionStorage.getItem('seal-restyled')) || 0; } catch (e) {}
    if (Date.now() - last > 60000) {
      try { sessionStorage.setItem('seal-restyled', String(Date.now())); } catch (e) {}
      setTimeout(() => location.reload(), 300);
    }
  }
}
