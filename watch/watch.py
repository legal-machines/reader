#!/usr/bin/env python3
"""Watches the Mail Reader sites (seal.legalmachines.org, seal.dzyza.com)
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
 - a reader file served other than its repository's SHA256SUMS, or (github
   mode) a webmail file other than FILE says, unless the repository or FILE
   changed in the last 20 minutes and the caches are catching up;
 - our public keys other than GitHub holds them (watch/keys.json in
   legal-machines/reader, made by its make-keys.py from the keys it
   publishes): a fingerprint on https://mail.<domain>/encryption that is not
   ours, or ours missing there, or a key for one of our addresses, served by
   the Web Key Directory (openpgpkey.<domain>) or by the guide's download
   (/encryption/key), that is not exactly our key with that address's user ID
   alone, or no key at all. Both are asked by the WKD hash of the address's
   local part, so the watch knows no addresses. The host's own run reads
   keys.json from GitHub, never from this server.
A check that cannot run (the network, an API's limit) is a note, not a problem.
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
WATCH_RUNS = "https://api.github.com/repos/legal-machines/reader/actions/workflows/watch.yml/runs?per_page=5"
KEYS_URL = "https://raw.githubusercontent.com/legal-machines/reader/main/watch/keys.json"
ZBASE32 = "ybndrfg8ejkmcpqxot1uwisza345h769"

notes = []


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
        notes.append(f"{domain}: the registry's name servers could not be found")
        return problems, seen
    ns = set()
    for server in servers:
        ns = {r.lower() for r in records(server, domain, "NS")}
        if ns == NAMESERVERS:
            break
    if not ns:
        notes.append(f"{domain}: the registry did not answer for NS")
    elif ns != NAMESERVERS:
        problems.append(f"{domain} is delegated to {', '.join(sorted(ns))} at its registry, not to deSEC")
    ds_list, answered = ds_at_registry(domain, servers)
    ds = [ds_parts(r) for r in ds_list]
    seen = [" ".join(map(str, d)) for d in ds]
    if ds:
        keys = [k for k in records("ns1.desec.io", domain, "DNSKEY") if k.split()[0] == "257"]
        if not keys:
            notes.append(f"{domain}: deSEC did not answer for DNSKEY")
        else:
            wanted = {ds_from_key(domain, k, d[2]) for k in keys for d in ds if d[2] in (1, 2, 4)}
            if not any(d in wanted for d in ds):
                problems.append(f"the DS of {domain} at its registry does not match deSEC's key")
    elif ds_required and answered:
        problems.append(f"the DS of {domain} at its registry is gone (DNSSEC is off for it)")
    elif ds_required:
        notes.append(f"{domain}: the registry did not answer for DS")
    # The reader, and the Web Key Directory (other people's apps take our keys
    # from it), are GitHub Pages sites.
    for host in (READERS[domain][0], f"openpgpkey.{domain}"):
        cname = [c.lower() for c in records("ns1.desec.io", host, "CNAME")]
        if not cname and not records("ns1.desec.io", host, "A"):
            notes.append(f"{host}: deSEC did not answer")
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
    except (OSError, ValueError, urllib.error.URLError) as e:
        notes.append(f"{host}: the CT logs could not be read ({type(e).__name__})")
        return problems
    recent = [i for i in issuances if now() - parse_time(i["not_before"]) < CERT_RECENT]
    if not recent:
        return problems
    key = served_key(host)
    if key is None:
        notes.append(f"{host}: GitHub Pages did not answer")
        return problems
    for i in recent:
        if i.get("pubkey_sha256") != key and now() - parse_time(i["not_before"]) > CERT_GRACE:
            problems.append(f"a certificate for {host} was issued on {i['not_before'][:16].replace('T', ' ')} UTC "
                            f"that GitHub Pages does not serve (crt.sh/?sha256={i.get('cert_sha256', '')})")
    return problems


# ---- Files: the reader as served against its repository.
def changed_lately(repo):
    try:
        commit = fetch_json(f"https://api.github.com/repos/{repo}/commits/main")
        return now() - parse_time(commit["commit"]["committer"]["date"]) < SETTLING
    except (OSError, ValueError, KeyError, urllib.error.URLError):
        return True  # unknown: do not cry wolf on a fresh publish


def check_files(host, repo):
    try:
        sums = fetch(f"https://raw.githubusercontent.com/{repo}/main/SHA256SUMS")[0].decode()
    except (OSError, urllib.error.URLError) as e:
        notes.append(f"{repo}: SHA256SUMS could not be read ({type(e).__name__})")
        return []
    differ = []
    for line in sums.splitlines():
        if not line.strip():
            continue
        digest, name = line.split(None, 1)
        try:
            body = fetch(f"https://{host}/{name.strip()}")[0]
        except (OSError, urllib.error.URLError):
            notes.append(f"{host}/{name.strip()} could not be fetched")
            continue
        if hashlib.sha256(body).hexdigest() != digest:
            differ.append(name.strip())
    if differ and not changed_lately(repo):
        return [f"{host} serves files that differ from {repo}: {', '.join(differ)}"]
    return []


def check_mail(expected):
    """The webmail's static files and its pages' Content-Security-Policy, as
    they were right after the last deploy (watch/expected.json)."""
    if now() - parse_time(expected["updated"]) < SETTLING:
        return []
    problems = []
    for site, want in expected["mail"].items():
        for path in MAIL_FILES:
            try:
                body = fetch(site + path)[0]
            except (OSError, urllib.error.URLError):
                notes.append(f"{site}{path} could not be fetched")
                continue
            if hashlib.sha256(body).hexdigest() != want.get(path):
                problems.append(f"{site}{path} is not the file deployed on {expected['updated'][:10]}")
        try:
            csp = fetch(site + "/login")[1].get("Content-Security-Policy", "")
            if csp != want.get("csp"):
                problems.append(f"{site}/login has another Content-Security-Policy than deployed")
        except (OSError, urllib.error.URLError):
            notes.append(f"{site}/login could not be fetched")
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
            notes.append(f"{page} could not be fetched ({type(e).__name__})")
        for hu, fpr in sorted(want["wkd"].items()):
            for where, url, armored in ((f"openpgpkey.{domain}", f"https://openpgpkey.{domain}/.well-known/openpgpkey/{domain}/hu/{hu}", False),
                                        (f"mail.{domain}/encryption/key", f"https://mail.{domain}/encryption/key?hu={hu}", True)):
                try:
                    data = fetch(url)[0]
                except urllib.error.HTTPError as e:
                    if e.code == 404:
                        problems.append(f"{where} serves no key for one of our addresses (WKD hash {hu})")
                    else:
                        notes.append(f"{where} answered {e.code} for WKD hash {hu}")
                    continue
                except (OSError, urllib.error.URLError) as e:
                    notes.append(f"{where} could not be fetched for WKD hash {hu} ({type(e).__name__})")
                    continue
                wrong = key_problem(armor_body(data.decode("latin-1")) if armored else data, domain, hu, fpr, keys[fpr]["subkeys"])
                if wrong:
                    problems.append(f"{where} serves {wrong} for one of our addresses (WKD hash {hu})")
    return problems


def check_all(ds_required):
    problems, ds_seen = [], {}
    for domain, (host, repo) in READERS.items():
        found, seen = check_dns(domain, ds_required.get(domain, False))
        problems += found
        ds_seen[domain] = seen
        problems += check_certificates(host)
        problems += check_files(host, repo)
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
        subject = "Mail Reader check: 1 problem" if len(problems) == 1 else f"Mail Reader check: {len(problems)} problems"
        text = ("The check of the Mail Reader found:\n\n" + "".join(f"- {p}\n" for p in problems) +
                ("\nA key problem means that people get a key other than ours, or none, from our server: until it clears, check "
                 "fingerprints only against seal.<domain>/keys.html.\n" if keys_wrong else "") +
                "\nUntil this clears, the webmail opens no encrypted message and adds no key by itself; each message offers "
                "Open anyway. Look at the domain's registrar (REG.RU), deSEC and the GitHub repositories legal-machines/reader "
                "and legal-machines/reader2 before opening encrypted mail. This note repeats once a day while a problem lasts.\n")
    else:
        subject = "Mail Reader: all clear again"
        text = "The Mail Reader check finds nothing wrong again. The webmail opens encrypted messages as before.\n"
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
    # Our keys against GitHub's copy, never against one kept here.
    key_problems = []
    try:
        key_problems = check_keys(fetch_json(KEYS_URL))
        problems += key_problems
    except (OSError, ValueError, KeyError, urllib.error.URLError) as e:
        notes.append(f"keys.json could not be read from GitHub ({type(e).__name__})")
    for domain, seen in ds_seen.items():
        if seen:
            ds_ever[domain] = sorted(set(ds_ever.get(domain, [])) | set(seen))
    # The watcher at GitHub, which sees this server from outside.
    # Each run checks every 10 minutes for hours and ends at once, failed, on a
    # problem: a run going for a quarter of an hour has passed its checks, and
    # answers for the watch even when the last one to end had failed.
    try:
        runs = fetch_json(WATCH_RUNS).get("workflow_runs", [])
        going = [r for r in runs if r.get("status") == "in_progress" and now() - parse_time(r.get("run_started_at") or r.get("created_at")) >= 15 * 60]
        done = [r for r in runs if r.get("status") == "completed"]
        if not going and done and done[0].get("conclusion") == "failure":
            problems.append(f"the watcher at GitHub reports a problem: {done[0].get('html_url', '')}")
    except (OSError, ValueError, KeyError, urllib.error.URLError):
        pass
    old = state.get("problems", [])
    since = state.get("since") if problems and old else (iso(now()) if problems else None)
    # The same problems are told once a day, not on every run: a link that
    # changes with each run at GitHub does not make a problem new.
    same = lambda ps: sorted(re.sub(r"https://\S+", "", p) for p in ps)
    told = state.get("told")
    due = same(problems) != same(old) or (problems and (not told or now() - parse_time(told) >= 86400))
    if due:
        told = iso(now())
    write_public(ALERT, json.dumps({"problems": problems, "since": since, "checked": iso(now())}))
    write_public(STATE, json.dumps({"ds": ds_ever, "problems": problems, "since": since, "notes": notes, "checked": iso(now()), "told": told}))
    if due:
        tell_postmasters(problems, bool(key_problems))
    for line in problems:
        print("PROBLEM", line)
    for line in notes:
        print("note", line)


# ---- In GitHub Actions, and for it.
def run_github(path):
    with open(path) as f:
        expected = json.load(f)
    problems, _ = check_all(expected.get("ds_required", {}))
    problems += check_mail(expected)
    keys = os.path.join(os.path.dirname(os.path.abspath(path)), "keys.json")
    if os.path.exists(keys):
        with open(keys) as f:
            problems += check_keys(json.load(f))
    else:
        notes.append("no keys.json beside the expected file: keys not checked")
    for line in notes:
        print(f"note: {line}")
    for line in problems:
        print(f"::error::{line}")
    sys.exit(1 if problems else 0)


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
