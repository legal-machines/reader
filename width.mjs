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
