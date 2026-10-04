#!/usr/bin/env python3
"""Writes into sw.js the SHA-256 of every file of the reader that pages load,
so that the worker serves only those (see sw.js). Run by publish.sh before
SHA256SUMS is made; sw.js itself is not in the list."""
import glob, hashlib, json, os, re
here = os.path.dirname(os.path.abspath(__file__))
names = sorted(n for n in (os.path.basename(p) for pat in ("*.html", "*.mjs", "*.css", "*.js") for p in glob.glob(os.path.join(here, pat))) if n != "sw.js")
pins = {n: hashlib.sha256(open(os.path.join(here, n), "rb").read()).hexdigest() for n in names}
path = os.path.join(here, "sw.js")
sw = open(path).read()
sw = re.sub(r"// PINS-BEGIN \(make-pins.py\)\n.*?\n// PINS-END", "// PINS-BEGIN (make-pins.py)\nconst PINS = " + json.dumps(pins, indent=1) + ";\n// PINS-END", sw, flags=re.S)
open(path, "w").write(sw)
print(f"make-pins: {len(pins)} files")
