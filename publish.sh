#!/bin/sh
# Publishes the reader to both of its addresses. This repository is
# seal.legalmachines.org (CNAME); legal-machines/reader2 is the same files
# for seal.dzyza.com, since a GitHub Pages site serves one address, and a
# frame shares the browser's key storage with the reader's own tab only on
# the same site as the mail page. keys.html differs: each site shows only
# its own domain's key, so its pins and SHA256SUMS are made again there.
set -e
cd "$(dirname "$0")"
# Everything on GitHub must be here, in Seal and in the mail repository whose
# keys go into keys.mjs: keys-approve.py publishes from copies of its own, and
# a publish from a folder behind GitHub would take its keys out of Seal.
mail_repo="${MAIL_REPO:-$HOME/Desktop/Projects/mail}"
for repo in . "$mail_repo"; do
  if ! git -C "$repo" fetch -q origin main || ! git -C "$repo" merge-base --is-ancestor origin/main HEAD; then
    echo "$repo is behind GitHub's main (or GitHub could not be reached): git pull there first, then publish." >&2
    exit 1
  fi
done
python3 make-keys.py --keys-page legalmachines.org
python3 make-notices.py
python3 make-styles.py
python3 make-pins.py
shasum -a 256 *.html *.mjs *.js *.css CNAME > SHA256SUMS
git add -A
git diff --cached --quiet || git commit -q -m "${1:-Update the reader}"
git push -q origin main
# reader2 gets a commit on top of its own history, never a rewrite of it:
# while GitHub Pages is slow to build, the watch passes files of the commits
# before (reader-watch.py, check_files), and it finds them only in that history.
out="$(mktemp -d)"
git clone -q --depth 6 https://github.com/legal-machines/reader2.git "$out"
(cd "$out" && git rm -rq --cached . && find . -mindepth 1 -maxdepth 1 ! -name .git -exec rm -rf {} +)
git archive HEAD | tar -x -C "$out"
printf seal.dzyza.com > "$out/CNAME"  # as GitHub writes it, no line end: its own commits then change nothing
(cd "$out" && python3 make-keys.py --keys-page dzyza.com > /dev/null && python3 make-pins.py > /dev/null && shasum -a 256 *.html *.mjs *.js *.css CNAME > SHA256SUMS && git add -A &&
 { git diff --cached --quiet || git -c user.name="Alexander Dzyza" -c user.email="61204471+Koshkej@users.noreply.github.com" commit -q -m "${1:-Update the reader}"; } &&
 git push -q origin HEAD:main)
# The hashes of both sites as published from here go straight to the mail
# server, whose watch checks the served files against them rather than
# against the SHA256SUMS at GitHub (reader-watch.py, check_pins): a change
# made at GitHub alone shows there.
python3 - "$out/SHA256SUMS" "$(cat "$out/CNAME")" > "$out/pins.json" <<'PY'
import datetime, json, sys
def sums(path):
    out = {}
    for line in open(path):
        if line.strip():
            digest, name = line.split(None, 1)
            out[name.strip().lstrip('*')] = digest
    return out
print(json.dumps({"published": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  "sites": {open("CNAME").read().strip(): sums("SHA256SUMS"), sys.argv[2]: sums(sys.argv[1])}}))
PY
# The server keeps the last few publishes beside the newest (previous), so
# that while GitHub Pages builds two publishes made minutes apart, the one
# between still passes the watch (reader-watch.py, check_pins). One
# connection: the host's firewall limits new ones.
merge='import json, sys
path = "/var/lib/mail-status/reader-pins.json"
new = json.load(sys.stdin)
try: old = json.load(open(path))
except Exception: old = {}
kept = ([{"published": old["published"], "sites": old["sites"]}] if old.get("sites") else []) + old.get("previous", [])
new["previous"] = kept[:4]
open(path + ".new", "w").write(json.dumps(new))'
if ssh "${MAIL_HOST:-legalmachines-prod}" "sudo python3 -c '$merge' && sudo mv -f /var/lib/mail-status/reader-pins.json.new /var/lib/mail-status/reader-pins.json && sudo chmod 0644 /var/lib/mail-status/reader-pins.json" < "$out/pins.json"; then
  echo "pins: sent to the mail server"
else
  echo "pins: NOT sent; the mail server's watch will report the sites as changed until they are"
fi
rm -rf "$out"
echo "published: seal.legalmachines.org and seal.dzyza.com"
