// The time by GitHub's clock, not by this device's. A device can be hours
// off without showing it (a wrong time zone, with the time then set by hand
// to look right), and a key or a signature made with such a clock carries
// that time: mail apps take a key from the future only once its time comes,
// and a signature from the future does not hold. The service worker asks
// this site for the time past every cache (sw.js, time); the mail server
// cannot answer for GitHub. Within a minute, this device's clock stands.
import {timeOffset} from './vault.mjs';

let offset = 0, measured = null;
export const measure = () => (measured ||= timeOffset().then(o => {
  if (Number.isFinite(o) && Math.abs(o) > 60e3) offset = o;
  return offset;
}, () => offset));
export const now = () => Date.now() + offset;
// How far off this device is, in words, or '' within a couple of minutes.
export function drift() {
  const m = Math.round(Math.abs(offset) / 60e3);
  if (m < 2) return '';
  const size = m >= 90 ? `about ${Math.round(m / 60)} hours` : `about ${m} minutes`;
  return `${size} ${offset < 0 ? 'ahead' : 'behind'}`;
}
