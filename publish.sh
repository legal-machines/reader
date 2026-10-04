#!/bin/sh
# Publishes the reader to both of its addresses. This repository is
# seal.legalmachines.org (CNAME); legal-machines/reader2 is the same files
# for seal.dzyza.com, since a GitHub Pages site serves one address, and a
# frame shares the browser's key storage with the reader's own tab only on
# the same site as the mail page. keys.html differs: each site shows only
# its own domain's key, so its pins and SHA256SUMS are made again there.
set -e
cd "$(dirname "$0")"
python3 make-keys.py --keys-page legalmachines.org
python3 make-styles.py
python3 make-pins.py
shasum -a 256 *.html *.mjs *.js *.css CNAME > SHA256SUMS
git add -A
git diff --cached --quiet || git commit -q -m "${1:-Update the reader}"
git push -q origin main
out="$(mktemp -d)"
git archive HEAD | tar -x -C "$out"
printf seal.dzyza.com > "$out/CNAME"  # as GitHub writes it, no line end: its own commits then change nothing
(cd "$out" && python3 make-keys.py --keys-page dzyza.com > /dev/null && python3 make-pins.py > /dev/null && shasum -a 256 *.html *.mjs *.js *.css CNAME > SHA256SUMS && git init -q && git add -A &&
 git -c user.name="Alexander Dzyza" -c user.email="quirites.suijuris@gmail.com" commit -q -m "${1:-Update the reader}" &&
 git push -q --force https://github.com/legal-machines/reader2.git HEAD:main)
rm -rf "$out"
echo "published: seal.legalmachines.org and seal.dzyza.com"
