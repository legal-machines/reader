#!/usr/bin/env python3
"""Watches Seal sites (seal.legalmachines.org, seal.dzyza.com)
for signs that someone other than GitHub Pages serves them. Two places that
do not depend on each other run it: this server every 10 minutes
(mail-reader-watch.timer), and GitHub Actions in legal-machines/reader every
15 (.github/workflows/watch.yml, with watch/watch.py, a copy of this file).

  reader-watch.py server          on the host: the webmail's alert file
                                  (/var/lib/mail-status/reader-alert.json) and
                                  a note to each domain's postmaster on a change
  reader-watch.py github FILE     in GitHub Actions: the run fails, and GitHub
                                  mails the repository's owner; also checks the
                                  webmail's static files against FILE, and our
                                  public keys against keys.json beside it
  reader-watch.py expected        prints FILE for the webmail as deployed
                                  (scripts/watch-sync.sh, after deploy.sh)

A problem is any of these:
 - a domain's delegation at its registry is not deSEC's (NS), or its DS does
   not match deSEC's key, or a DS that was there is gone;
 - seal.<domain> at deSEC is not a CNAME to legal-machines.github.io;
 - a certificate for seal.<domain> in the Certificate Transparency logs
   (SSLMate's Cert Spotter) whose key GitHub Pages does not serve, half an
   hour after it was issued: a certificate is what someone who took the name
   would need first;
 - a reader file served other than its repository's SHA256SUMS, unless it is
   that of one of its recent commits within six hours of the last (GitHub
   Pages catching up, named in a note), or the last commit is under 20
   minutes old (not verified until then); or (github mode) a webmail file
   other than FILE says, unless FILE changed in the last 20 minutes;
 - our public keys other than GitHub holds them (watch/keys.json in
   legal-machines/reader, made by its make-keys.py from the keys it
   publishes): a fingerprint on https://mail.<domain>/encryption that is not
   ours, or ours missing there, or a key for one of our addresses, served by
   the Web Key Directory (openpgpkey.<domain>) or by the guide's download
   (/encryption/key), that is not exactly our key with that address's user ID
   alone, or no key at all. Both are asked by the WKD hash of the address's
   local part, so the watch knows no addresses. The host's own run reads
   keys.json from GitHub, never from this server.
A run ends in one of three states. ALARM: a problem. UNVERIFIED: no problem
found, but a check could not be done (the network, a timeout, an API's limit
or error, an answer that cannot be read, a file that cannot be fetched), so
the run cannot say all is well; the GitHub run fails on it too (watch.yml),
in a step of its own, so the host's run can tell it from a problem. OK: every
check was done and found nothing. A file that differs stays a problem when
GitHub's history cannot be read: nothing then says a publish is on its way.
"""
import base64
import datetime
import hashlib
import json
import os
import re
import smtplib
import socket
import ssl
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request

READERS = {"legalmachines.org": ("seal.legalmachines.org", "legal-machines/reader"),
           "dzyza.com": ("seal.dzyza.com", "legal-machines/reader2")}
MAIL_SITES = ["https://mail.legalmachines.org", "https://mail.dzyza.com"]
MAIL_FILES = ["/static/app.js", "/static/app.css"]
NAMESERVERS = {"ns1.desec.io.", "ns2.desec.org."}
PAGES_NAME = "legal-machines.github.io."
PAGES_IPS = ["185.199.108.153", "185.199.109.153", "185.199.110.153", "185.199.111.153"]
CERT_GRACE = 30 * 60      # GitHub serves a certificate it got within minutes
CERT_RECENT = 3 * 86400   # older issuances were weighed before
SETTLING = 20 * 60        # GitHub Pages and raw.githubusercontent.com caches
STATE = "/var/lib/mail-status/reader-watch.json"
ALERT = "/var/lib/mail-status/reader-alert.json"
PINS = "/var/lib/mail-status/reader-pins.json"  # what this Mac published last (publish.sh), sent here directly
WATCH_RUNS = "https://api.github.com/repos/legal-machines/reader/actions/workflows/watch.yml/runs?per_page=10"
KEYS_URL = "https://raw.githubusercontent.com/legal-machines/reader/main/watch/keys.json"
ZBASE32 = "ybndrfg8ejkmcpqxot1uwisza345h769"

notes = []
unverified = []  # checks that could not be done: the run cannot say all is well
EXIT = {"OK": 0, "ALARM": 1, "UNVERIFIED": 3}


def outcome(problems):
    return "ALARM" if problems else "UNVERIFIED" if unverified else "OK"


def now():
    return time.time()


def iso(t):
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_time(text):
    return datetime.datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()


def fetch(url, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": "mail-reader-watch", "Accept": "application/json, */*"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read(), r.headers


def fetch_json(url):
    return json.loads(fetch(url)[0])


def read_json(path):
    with open(path) as f:
        return json.load(f)


# ---- DNS, asked of the registries and of deSEC directly (dig).
def records(server, name, kind):
    name = name.rstrip(".").lower() + "."
    out = subprocess.run(["dig", "+norec", "+noall", "+answer", "+authority", "+time=5", "+tries=2", f"@{server}", name, kind],
                         capture_output=True, text=True, timeout=60).stdout
    found = []
    for line in out.splitlines():
        parts = line.split(None, 4)
        if len(parts) == 5 and parts[0].lower() == name and parts[3] == kind:
            found.append(parts[4].strip())
    return found


def registry_servers(domain):
    tld = domain.rsplit(".", 1)[1] + "."
    out = subprocess.run(["dig", "+short", tld, "NS"], capture_output=True, text=True, timeout=60).stdout.split()
    return sorted(out)[:3]


def ds_at_registry(domain, servers):
    """The DS records the registry publishes, asked of its servers in turn, and
    whether it said there are none: two servers must answer NOERROR without
    one. A server that times out or fails is not taken for one that said so,
    so a slow registry is a note, not a domain without DNSSEC."""
    name, none = domain.rstrip(".").lower() + ".", 0
    for server in servers:
        out = subprocess.run(["dig", "+norec", "+noall", "+comments", "+answer", "+time=5", "+tries=2", f"@{server}", name, "DS"],
                             capture_output=True, text=True, timeout=60).stdout
        if "status: NOERROR" not in out:
            continue
        found = [l.split(None, 4)[4].strip() for l in out.splitlines()
                 if not l.startswith(";") and len(l.split(None, 4)) == 5 and l.split()[0].lower() == name and l.split()[3] == "DS"]
        if found:
            return found, True
        none += 1
    return [], none >= 2


def ds_from_key(domain, dnskey, digest_type):
    """The DS record of a DNSKEY (RFC 4034, section 5.1.4, and appendix B)."""
    flags, protocol, algorithm, key = dnskey.split(None, 3)
    rdata = struct.pack("!HBB", int(flags), int(protocol), int(algorithm)) + base64.b64decode(key.replace(" ", ""))
    owner = b"".join(bytes([len(label)]) + label.encode() for label in domain.lower().rstrip(".").split(".")) + b"\0"
    total = sum(b if i & 1 else b << 8 for i, b in enumerate(rdata))
    tag = (total + (total >> 16)) & 0xFFFF
    digest = {1: hashlib.sha1, 2: hashlib.sha256, 4: hashlib.sha384}[digest_type](owner + rdata).hexdigest().upper()
    return (tag, int(algorithm), digest_type, digest)


def ds_parts(text):
    tag, algorithm, digest_type, digest = text.split(None, 3)
    return (int(tag), int(algorithm), int(digest_type), digest.replace(" ", "").upper())


def check_dns(domain, ds_required):
    """Problems with the domain's delegation and its reader's name, and the DS
    records seen (to be required from then on)."""
    problems, seen = [], []
    servers = registry_servers(domain)
    if not servers:
        unverified.append(f"{domain}: the registry's name servers could not be found")
        return problems, seen
    ns = set()
    for server in servers:
        ns = {r.lower() for r in records(server, domain, "NS")}
        if ns == NAMESERVERS:
            break
    if not ns:
        unverified.append(f"{domain}: the registry did not answer for NS")
    elif ns != NAMESERVERS:
        problems.append(f"{domain} is delegated to {', '.join(sorted(ns))} at its registry, not to deSEC")
    ds_list, answered = ds_at_registry(domain, servers)
    ds = [ds_parts(r) for r in ds_list]
    seen = [" ".join(map(str, d)) for d in ds]
    if ds:
        keys = [k for k in records("ns1.desec.io", domain, "DNSKEY") if k.split()[0] == "257"]
        if not keys:
            unverified.append(f"{domain}: deSEC did not answer for DNSKEY")
        else:
            wanted = {ds_from_key(domain, k, d[2]) for k in keys for d in ds if d[2] in (1, 2, 4)}
            if not any(d in wanted for d in ds):
                problems.append(f"the DS of {domain} at its registry does not match deSEC's key")
    elif ds_required and answered:
        problems.append(f"the DS of {domain} at its registry is gone (DNSSEC is off for it)")
    elif ds_required:
        unverified.append(f"{domain}: the registry did not answer for DS")
    # The reader, and the Web Key Directory (other people's apps take our keys
    # from it), are GitHub Pages sites.
    for host in (READERS[domain][0], f"openpgpkey.{domain}"):
        cname = [c.lower() for c in records("ns1.desec.io", host, "CNAME")]
        if not cname and not records("ns1.desec.io", host, "A"):
            unverified.append(f"{host}: deSEC did not answer")
        elif cname != [PAGES_NAME]:
            problems.append(f"{host} points to {', '.join(cname) or 'an address'} at deSEC, not to GitHub Pages")
    return problems, seen


# ---- Certificates: what the CT logs list against what GitHub Pages serves.
def served_key(host):
    """SHA-256 of the public key GitHub Pages serves for the name, asked at
    GitHub's own addresses (not through DNS)."""
    for ip in PAGES_IPS:
        try:
            with socket.create_connection((ip, 443), timeout=15) as sock:
                with ssl.create_default_context().wrap_socket(sock, server_hostname=host) as tls:
                    der = tls.getpeercert(binary_form=True)
        except OSError:
            continue
        pem = ssl.DER_cert_to_PEM_cert(der)
        key = subprocess.run(["openssl", "x509", "-pubkey", "-noout"], input=pem.encode(), capture_output=True, timeout=30).stdout
        spki = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "der"], input=key, capture_output=True, timeout=30).stdout
        if spki:
            return hashlib.sha256(spki).hexdigest()
    return None


def check_certificates(host):
    problems, issuances, after = [], [], None
    try:
        for _ in range(20):
            url = f"https://api.certspotter.com/v1/issuances?domain={host}&expand=dns_names" + (f"&after={after}" if after else "")
            page = fetch_json(url)
            if not page:
                break
            issuances += page
            after = page[-1]["id"]
        else:
            raise ValueError("more issuances than pages read")
        recent = [i for i in issuances if now() - parse_time(i["not_before"]) < CERT_RECENT]
    except (OSError, ValueError, KeyError, TypeError, IndexError, AttributeError, urllib.error.URLError) as e:
        unverified.append(f"{host}: the CT logs could not be read ({type(e).__name__})")
        return problems
    if not recent:
        return problems
    key = served_key(host)
    if key is None:
        unverified.append(f"{host}: GitHub Pages did not answer")
        return problems
    for i in recent:
        if i.get("pubkey_sha256") != key and now() - parse_time(i["not_before"]) > CERT_GRACE:
            problems.append(f"a certificate for {host} was issued on {i['not_before'][:16].replace('T', ' ')} UTC "
                            f"that GitHub Pages does not serve (crt.sh/?sha256={i.get('cert_sha256', '')})")
    return problems


# ---- Files: the reader as served against its repository.
def recent_commits(repo):
    """The newest commits on main, newest first: (sha, time), or None."""
    try:
        return [(c["sha"], parse_time(c["commit"]["committer"]["date"]))
                for c in fetch_json(f"https://api.github.com/repos/{repo}/commits?sha=main&per_page=6")] or None
    except (OSError, ValueError, KeyError, TypeError, AttributeError, urllib.error.URLError):
        return None


def read_sums(text):
    """{name: digest} of a SHA256SUMS file; ValueError for a line that is not
    a digest and a name."""
    out = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        digest, name = line.split(None, 1)
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("not a SHA-256")
        out[name.strip().lstrip("*")] = digest
    return out


def check_files(host, repo):
    """Problems with the reader's files as served, against its repository's
    SHA256SUMS. A file that cannot be fetched, or sums that cannot be read,
    leave the check unverified; a file that differs is a problem, unless
    GitHub's history shows a publish it is part of, or one still on its way."""
    try:
        sums = read_sums(fetch(f"https://raw.githubusercontent.com/{repo}/main/SHA256SUMS")[0].decode())
    except (OSError, ValueError, urllib.error.URLError) as e:
        unverified.append(f"{repo}: SHA256SUMS could not be read ({type(e).__name__}): {host} not checked")
        return []
    if not sums:
        unverified.append(f"{repo}: SHA256SUMS lists no files: {host} not checked")
        return []
    differ, missing = {}, []
    for name, digest in sorted(sums.items()):
        try:
            body = fetch(f"https://{host}/{name}")[0]
        except (OSError, urllib.error.URLError):
            missing.append(name)
            continue
        got = hashlib.sha256(body).hexdigest()
        if got != digest:
            differ[name] = got
    if missing:
        unverified.append(f"{host}: {len(missing)} file(s) could not be fetched: {', '.join(missing[:8])}")
    if not differ:
        return []
    problem = lambda names: [f"{host} serves files that differ from {repo}: {', '.join(names)}"]
    commits = recent_commits(repo)
    if not commits:
        # Nothing then says a publish is on its way: unknown is not taken
        # for one.
        notes.append(f"{repo}: its commit history could not be read, so a publish on its way could not be ruled out")
        return problem(sorted(differ))
    age = now() - commits[0][1]
    if age >= 6 * 3600:
        return problem(sorted(differ))
    # GitHub Pages builds through Actions and can serve an earlier commit
    # for an hour or more when Actions is slow: a file of one of the recent
    # commits passes, for six hours (named in a note). Each commit's sums by
    # its own hash, the newest included: raw.githubusercontent.com can serve
    # main's of a few minutes before. A commit made at GitHub alone is not
    # passed by this: the host compares with this Mac's hashes too.
    known, unread = set(), 0
    for sha, _ in commits:
        try:
            known |= set(read_sums(fetch(f"https://raw.githubusercontent.com/{repo}/{sha}/SHA256SUMS")[0].decode()).items())
        except (OSError, ValueError, urllib.error.URLError):
            unread += 1
    still = sorted(n for n, got in differ.items() if (n, got) not in known)
    if len(still) < len(differ):
        notes.append(f"{host}: {len(differ) - len(still)} file(s) are those of another recent commit of {repo} (GitHub Pages catching up)")
    if unread:
        notes.append(f"{repo}: the sums of {unread} recent commit(s) could not be read")
    if still and age < SETTLING:
        # A publish minutes old: what is served may still be on its way, so
        # neither all clear nor a problem yet.
        unverified.append(f"{host}: {', '.join(still)} not as {repo} has them, {int(age // 60)} minutes after its last commit")
        return []
    return problem(still) if still else []


def check_mail(expected):
    """The webmail's static files and its pages' Content-Security-Policy, as
    they were right after the last deploy (watch/expected.json)."""
    if now() - parse_time(expected["updated"]) < SETTLING:
        notes.append("the webmail was deployed in the last 20 minutes: its files not checked yet")
        return []
    problems = []
    for site, want in expected["mail"].items():
        for path in MAIL_FILES:
            try:
                body = fetch(site + path)[0]
            except (OSError, urllib.error.URLError):
                unverified.append(f"{site}{path} could not be fetched")
                continue
            if hashlib.sha256(body).hexdigest() != want.get(path):
                problems.append(f"{site}{path} is not the file deployed on {expected['updated'][:10]}")
        try:
            csp = fetch(site + "/login")[1].get("Content-Security-Policy", "")
            if csp != want.get("csp"):
                problems.append(f"{site}/login has another Content-Security-Policy than deployed")
        except (OSError, urllib.error.URLError):
            unverified.append(f"{site}/login could not be fetched")
    return problems


# ---- Our public keys: what the server hands out against what GitHub holds.
def key_packets(data):
    """(tag, body) of each OpenPGP packet (RFC 9580, section 4.2), or None."""
    out, at = [], 0
    try:
        while at < len(data):
            head = data[at]
            at += 1
            if not head & 0x80:
                return None
            if head & 0x40:
                tag, first = head & 0x3F, data[at]
                at += 1
                if first < 192:
                    length = first
                elif first < 224:
                    length = ((first - 192) << 8) + data[at] + 192
                    at += 1
                elif first == 255:
                    length = int.from_bytes(data[at:at + 4], "big")
                    at += 4
                else:
                    return None
            else:
                tag, kind = (head >> 2) & 0x0F, head & 3
                if kind == 3:
                    return None
                length = int.from_bytes(data[at:at + (1 << kind)], "big")
                at += 1 << kind
            if at + length > len(data):
                return None
            out.append((tag, data[at:at + length]))
            at += length
    except IndexError:
        return None
    return out


def key_fingerprint(body):
    if body[:1] == b"\x04":
        return hashlib.sha1(b"\x99" + len(body).to_bytes(2, "big") + body).hexdigest().upper()
    if body[:1] == b"\x06":
        return hashlib.sha256(b"\x9b" + len(body).to_bytes(4, "big") + body).hexdigest().upper()
    return None


def wkd_hash(local):
    digest = hashlib.sha1(local.encode().lower()).digest()
    bits = "".join(f"{b:08b}" for b in digest)
    return "".join(ZBASE32[int(bits[i:i + 5].ljust(5, "0"), 2)] for i in range(0, len(bits), 5))


def armor_body(text):
    """The binary inside an ASCII-armored public key block, or b""."""
    lines, body, inside, headers = text.splitlines(), [], False, False
    for line in lines:
        if line.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----"):
            inside, headers = True, True
        elif line.startswith("-----END PGP"):
            break
        elif inside and headers:
            if not line.strip() or ":" not in line:
                headers = False
                if line.strip():
                    body.append(line.strip())
        elif inside and not line.startswith("="):
            body.append(line.strip())
    try:
        return base64.b64decode("".join(body))
    except ValueError:
        return b""


def key_problem(data, domain, hu, fingerprint, subkeys):
    """What is wrong with a key served for the address with this WKD hash, or
    None when it is exactly ours with that address's user ID alone."""
    found = key_packets(data)
    if not found:
        return "something that is not a key"
    if sum(t == 6 for t, _ in found) != 1 or found[0][0] != 6 or any(t in (5, 7) for t, _ in found):
        return "more than one key, or not a public key"
    served = key_fingerprint(found[0][1])
    if served != fingerprint:
        return f"another key ({served or 'unknown'})"
    uids = [b for t, b in found if t == 13]
    if len(uids) != 1 or any(t == 17 for t, _ in found):
        return f"our key with {len(uids)} user IDs"
    text = uids[0].decode("utf-8", "replace")
    address = (re.search(r"<([^<>]*)>\s*$", text) or re.match(r"(.*)", text)).group(1).strip().lower()
    local, _, at = address.rpartition("@")
    if at != domain or wkd_hash(local) != hu:
        return "our key with the user ID of another address"
    if sorted(key_fingerprint(b) or "" for t, b in found if t == 14) != sorted(subkeys):
        return "our key with other subkeys"
    return None


def check_keys(expected):
    """Our public keys as served, against keys.json (see the top)."""
    if now() - parse_time(expected["updated"]) < SETTLING:
        notes.append("keys.json changed in the last 20 minutes: keys not checked")
        return []
    problems = []
    for domain, want in expected["domains"].items():
        keys = want["keys"]
        page = f"https://mail.{domain}/encryption"
        try:
            html = fetch(page)[0].decode("utf-8", "replace")
            shown = {re.sub(r"\s+", "", f) for f in re.findall(r"\b[0-9A-F]{4}(?:\s+[0-9A-F]{4}){9}\b", re.sub(r"<[^>]*>", " ", html))}
            for fpr in sorted(shown - set(keys)):
                problems.append(f"mail.{domain}/encryption shows the fingerprint {fpr}, which is not our key")
            for fpr in sorted(set(keys) - shown):
                problems.append(f"mail.{domain}/encryption does not show our key {fpr}")
        except (OSError, urllib.error.URLError) as e:
            unverified.append(f"{page} could not be fetched ({type(e).__name__})")
        for hu, fpr in sorted(want["wkd"].items()):
            for where, url, armored in ((f"openpgpkey.{domain}", f"https://openpgpkey.{domain}/.well-known/openpgpkey/{domain}/hu/{hu}", False),
                                        (f"mail.{domain}/encryption/key", f"https://mail.{domain}/encryption/key?hu={hu}", True)):
                try:
                    data = fetch(url)[0]
                except urllib.error.HTTPError as e:
                    if e.code == 404:
                        problems.append(f"{where} serves no key for one of our addresses (WKD hash {hu})")
                    else:
                        unverified.append(f"{where} answered {e.code} for WKD hash {hu}")
                    continue
                except (OSError, urllib.error.URLError) as e:
                    unverified.append(f"{where} could not be fetched for WKD hash {hu} ({type(e).__name__})")
                    continue
                wrong = key_problem(armor_body(data.decode("latin-1")) if armored else data, domain, hu, fpr, keys[fpr]["subkeys"])
                if wrong:
                    problems.append(f"{where} serves {wrong} for one of our addresses (WKD hash {hu})")
    return problems


def check_webauthn(host):
    """Nothing at /.well-known/webauthn: that file would let other sites, the
    webmail among them, ask for this site's passkeys (WebAuthn Related Origin
    Requests), and the browser reads it from the network, past Seal's worker."""
    url = f"https://{host}/.well-known/webauthn"
    try:
        fetch(url)
    except urllib.error.HTTPError as e:
        if e.code != 404:
            unverified.append(f"{url} answered {e.code}")
        return []
    except (OSError, urllib.error.URLError) as e:
        unverified.append(f"{url} could not be asked ({type(e).__name__})")
        return []
    return [f"{url} exists: it would let other sites use this site's passkeys"]


def check_pins(state):
    """On the host: each Seal site's files against the hashes this Mac sent at
    its last publish, not against the SHA256SUMS at GitHub, so that a change
    made at GitHub alone, sums and all, shows here. Until GitHub Pages has
    built a new publish (its builds can wait an hour when Actions is slow), a
    file of a recent publish before still passes, for six hours; one in none
    of them is a problem at once."""
    try:
        with open(PINS) as f:
            pins = json.load(f)
    except (OSError, ValueError):
        unverified.append("no hashes from the last publish of Seal (reader-pins.json)")
        return []
    published = pins.get("published", "1970-01-01T00:00:00+00:00")
    if state.get("pins_published") != published:
        state["pins_before"] = state.get("pins_sites") or {}
        state["pins_sites"] = pins.get("sites", {})
        state["pins_published"] = published
    # The publish before as this watch saw it, and the last few publishes
    # the Mac sent with the newest (previous), each for six hours after the
    # newest: two publishes minutes apart leave the one between in neither
    # place otherwise.
    recent = now() - parse_time(published) < 6 * 3600
    befores = ([state.get("pins_before", {})] if recent else []) + \
              [p.get("sites", {}) for p in pins.get("previous", []) if recent and isinstance(p, dict)]
    problems, waiting = [], []
    for host, files in sorted(pins.get("sites", {}).items()):
        differ = []
        for name, digest in sorted(files.items()):
            try:
                body = fetch(f"https://{host}/{name}")[0]
            except (OSError, urllib.error.URLError):
                unverified.append(f"{host}/{name} could not be fetched")
                continue
            got = hashlib.sha256(body).hexdigest()
            if got == digest:
                continue
            if any(got == b.get(host, {}).get(name) for b in befores):
                waiting.append(f"{host}/{name}")
            else:
                differ.append(name)
        if differ:
            problems.append(f"{host} serves files other than the last publishes from the owner's Mac: {', '.join(differ[:8])}")
    if waiting:
        notes.append(f"GitHub Pages still serves the publish before for {len(waiting)} file(s)")
    return problems


def attempt(what, empty, check, *args):
    """A check that breaks (a timeout of dig or openssl, an answer of an
    unexpected shape) is a check not done: unverified, not the end of the run."""
    try:
        return check(*args)
    except Exception as e:
        unverified.append(f"{what}: the check failed ({type(e).__name__})")
        return empty


def check_all(ds_required):
    problems, ds_seen = [], {}
    for domain, (host, repo) in READERS.items():
        found, seen = attempt(f"{domain} DNS", ([], []), check_dns, domain, ds_required.get(domain, False))
        problems += found
        ds_seen[domain] = seen
        problems += attempt(f"{host} certificates", [], check_certificates, host)
        problems += attempt(f"{host} files", [], check_files, host, repo)
        problems += attempt(f"{host}/.well-known/webauthn", [], check_webauthn, host)
    return problems, ds_seen


# ---- On the host.
def write_public(path, text):
    new = path + ".new"
    with open(new, "w") as f:
        f.write(text)
    os.chmod(new, 0o644)
    os.replace(new, path)


def tell_postmasters(problems, keys_wrong=False):
    try:
        with open("/etc/rspamd/local.d/known_token") as f:
            token = f.read().strip()
    except OSError:
        token = ""
    if problems:
        subject = "Seal check: 1 problem" if len(problems) == 1 else f"Seal check: {len(problems)} problems"
        text = ("The check of Seal found:\n\n" + "".join(f"- {p}\n" for p in problems) +
                ("\nA key problem means that people get a key other than ours, or none, from our server: until it clears, check "
                 "fingerprints only against seal.<domain>/keys.html.\n" if keys_wrong else "") +
                "\nUntil this clears, the webmail opens no encrypted message and adds no key by itself; each message offers "
                "Open anyway. Look at the domain's registrar (REG.RU), deSEC and the GitHub repositories legal-machines/reader "
                "and legal-machines/reader2 before opening encrypted mail. This note repeats once a day while a problem lasts.\n")
    else:
        subject = "Seal: all clear again"
        text = "The Seal check finds nothing wrong again. The webmail opens encrypted messages as before.\n"
    for domain in READERS:
        message = (f"From: Mail server <postmaster@{domain}>\r\nTo: <postmaster@{domain}>\r\nSubject: {subject}\r\n"
                   f"Date: {email_date()}\r\nAuto-Submitted: auto-generated\r\n" + (f"X-Known-Sender: {token}\r\n" if token else "") +
                   "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n" + text.replace("\n", "\r\n"))
        try:
            with smtplib.SMTP("127.0.0.1", 25, timeout=20) as smtp:
                smtp.sendmail(f"postmaster@{domain}", [f"postmaster@{domain}"], message.encode())
        except (OSError, smtplib.SMTPException) as e:
            print(f"reader-watch: the note to postmaster@{domain} was not sent: {type(e).__name__}", file=sys.stderr)


def email_date():
    import email.utils
    return email.utils.formatdate()


def run_server():
    try:
        with open(STATE) as f:
            state = json.load(f)
    except (OSError, ValueError):
        state = {}
    ds_ever = state.get("ds", {})
    problems, ds_seen = check_all({d: bool(ds_ever.get(d)) for d in READERS})
    problems += attempt("the last publish's hashes", [], check_pins, state)
    # Our keys against GitHub's copy, never against one kept here.
    key_problems = []
    try:
        wanted = fetch_json(KEYS_URL)
    except (OSError, ValueError, urllib.error.URLError) as e:
        unverified.append(f"keys.json could not be read from GitHub ({type(e).__name__}): keys not checked")
    else:
        key_problems = attempt("our public keys", [], check_keys, wanted)
        problems += key_problems
    for domain, seen in ds_seen.items():
        if seen:
            ds_ever[domain] = sorted(set(ds_ever.get(domain, [])) | set(seen))
    # The watcher at GitHub, which sees this server from outside.
    # A run checks once, every 10 minutes (cron-job.org starts it), and fails
    # on a problem, or, at its step Verified, on a check it could not do. A
    # run cancelled while waiting its turn says nothing; three hours without
    # a finished check means the watch itself was stopped.
    try:
        runs = fetch_json(WATCH_RUNS).get("workflow_runs", [])
        done = [r for r in runs if r.get("status") == "completed" and r.get("conclusion") in ("success", "failure")]
        if done and done[0].get("conclusion") == "failure":
            if github_unverified(done[0]):
                unverified.append(f"the watcher at GitHub could not do every check: {done[0].get('html_url', '')}")
            else:
                problems.append(f"the watcher at GitHub reports a problem: {done[0].get('html_url', '')}")
        last = max((parse_time(r.get("updated_at") or r.get("created_at")) for r in done), default=None)
        if last is None or now() - last >= 3 * 3600:
            problems.append("the watcher at GitHub has finished no check for three hours: https://github.com/legal-machines/reader/actions/workflows/watch.yml")
    except (OSError, ValueError, KeyError, TypeError, AttributeError, urllib.error.URLError) as e:
        unverified.append(f"the runs of the watcher at GitHub could not be read ({type(e).__name__})")
    old = state.get("problems", [])
    since = state.get("since") if problems and old else (iso(now()) if problems else None)
    # The same problems are told once a day, not on every run: a link that
    # changes with each run at GitHub does not make a problem new.
    same = lambda ps: sorted(re.sub(r"https://\S+", "", p) for p in ps)
    told = state.get("told")
    due = same(problems) != same(old) or (problems and (not told or now() - parse_time(told) >= 86400))
    if due:
        told = iso(now())
    # problems (ALARM) alone stop the webmail opening encrypted mail; the
    # state, and since when checks could not be done, are there to be shown.
    result = outcome(problems)
    unverified_since = (state.get("unverified_since") or iso(now())) if result == "UNVERIFIED" else None
    write_public(ALERT, json.dumps({"problems": problems, "since": since, "checked": iso(now()),
                                    "state": result, "unverified": unverified, "unverified_since": unverified_since}))
    write_public(STATE, json.dumps({"ds": ds_ever, "problems": problems, "since": since, "notes": notes, "checked": iso(now()), "told": told,
                                    "state": result, "unverified": unverified, "unverified_since": unverified_since,
                                    **{k: state[k] for k in ("pins_published", "pins_sites", "pins_before") if k in state}}))
    if due:
        tell_postmasters(problems, bool(key_problems))
    for line in problems:
        print("PROBLEM", line)
    for line in unverified:
        print("UNVERIFIED", line)
    for line in notes:
        print("note", line)
    print("state", result)


# ---- In GitHub Actions, and for it.
def github_unverified(run):
    """Whether a failed run of the watcher at GitHub failed only at its step
    Verified (watch.yml): a check it could not do, not a problem it found.
    Anything else, or jobs that cannot be read, is a problem as before."""
    try:
        jobs = fetch_json(f"https://api.github.com/repos/legal-machines/reader/actions/runs/{int(run['id'])}/jobs").get("jobs", [])
        failed = [s.get("name") for j in jobs for s in j.get("steps", []) if s.get("conclusion") == "failure"]
        return failed == ["Verified"]
    except (OSError, ValueError, KeyError, TypeError, AttributeError, urllib.error.URLError):
        return False


def run_github(path):
    """Exits 0 (OK), 1 (ALARM) or 3 (UNVERIFIED): watch.yml fails the run on
    either, at a step of its own."""
    with open(path) as f:
        expected = json.load(f)
    problems, _ = check_all(expected.get("ds_required", {}))
    problems += attempt("the webmail's files", [], check_mail, expected)
    keys = os.path.join(os.path.dirname(os.path.abspath(path)), "keys.json")
    if os.path.exists(keys):
        problems += attempt("our public keys", [], lambda: check_keys(read_json(keys)))
    else:
        unverified.append("no keys.json beside the expected file: keys not checked")
    result = outcome(problems)
    for line in notes:
        print(f"note: {line}")
    for line in unverified:
        print(f"::warning::not verified: {line}")
    for line in problems:
        print(f"::error::{line}")
    print(f"state: {result}")
    sys.exit(EXIT[result])


def run_expected():
    out = {"updated": iso(now()), "mail": {}, "ds_required": {}}
    for site in MAIL_SITES:
        want = {path: hashlib.sha256(fetch(site + path)[0]).hexdigest() for path in MAIL_FILES}
        want["csp"] = fetch(site + "/login")[1].get("Content-Security-Policy", "")
        out["mail"][site] = want
    for domain in READERS:
        servers = registry_servers(domain)
        out["ds_required"][domain] = bool(servers and records(servers[0], domain, "DS"))
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode == "server":
        run_server()
    elif mode == "github" and len(sys.argv) > 2:
        run_github(sys.argv[2])
    elif mode == "expected":
        run_expected()
    else:
        sys.exit(__doc__)
