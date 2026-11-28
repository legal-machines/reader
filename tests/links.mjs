// Addresses written out in a letter are links here as in the Mail app
// (addresses.mjs, copied from the Mail app by make-styles.py; linkify in
// mime.mjs): a web address with or without its scheme, www., an email
// address (mailto:); every character escaped, nothing that could leave the
// link's address; no file's name, no sentence that lost its space.
// Run with plain node from the repository: node tests/links.mjs
import assert from 'node:assert/strict';
import {linkify} from '../mime.mjs';
import {all} from '../addresses.mjs';

let passed = 0;
const it = (name, f) => { f(); passed++; console.log(`ok ${passed} - ${name}`); };
const link = (href, text = href) => `<a href="${href}" target="_blank" rel="noopener noreferrer">${text}</a>`;

it('a site written without its scheme, without the sentence\'s period', () => {
  assert.equal(linkify('Contact page at illuminate.com/contact/.'), 'Contact page at ' + link('https://illuminate.com/contact/', 'illuminate.com/contact/') + '.');
});
it('with its scheme, www., and a bracket it opened', () => {
  assert.equal(linkify('See https://en.wikipedia.org/wiki/Foo_(bar). or www.example.org'),
               'See ' + link('https://en.wikipedia.org/wiki/Foo_(bar)') + '. or ' + link('https://www.example.org', 'www.example.org'));
  assert.equal(linkify('(see example.com/a)'), '(see ' + link('https://example.com/a', 'example.com/a') + ')');
});
it('an email address, to the reader\'s own mail app', () => {
  assert.equal(linkify('Write to cindy@illuminate.com.'), 'Write to ' + link('mailto:cindy@illuminate.com', 'cindy@illuminate.com') + '.');
});
it('no link in a file\'s name, a lost space, code or half an address', () => {
  for (const text of ['AGENTS.md', 'agent.py and main.cf', 'done.It works', 'setup.zip', 'e.g. U.S.', 'log.info(x)', '_dmarc.legalmachines.org', '@claude@legalmachines.org', 'user@localhost'])
    assert.equal(linkify(text), text, text);
});
it('every character escaped; nothing leaves the link\'s address', () => {
  assert.equal(linkify('<b>"x"</b> & \''), '&lt;b&gt;&quot;x&quot;&lt;/b&gt; &amp; &#39;');
  assert.ok(!linkify('example.com"onclick="x').includes('onclick="'));
  assert.equal(linkify('https://example.com/it\'s'), link('https://example.com/it&#39;s'));
});
it('long odd text stays fast', () => {
  const started = Date.now();
  all('a(b.c'.repeat(40000) + 'https://.'.repeat(20000) + ' ' + 'a'.repeat(100000) + '.com');
  assert.ok(Date.now() - started < 2000);
});
console.log(`${passed} passed`);
