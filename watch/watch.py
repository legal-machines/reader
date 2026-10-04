#!/usr/bin/env python3
"""Watches the Mail Reader sites (reader.legalmachines.org, reader.dzyza.com)
for signs that someone other than GitHub Pages serves them. Two places that
do not depend on each other run it: this server every 10 minutes
(mail-reader-watch.timer), and GitHub Actions in legal-machines/reader every
15 (.github/workflows/watch.yml, with watch/watch.py, a copy of this file).

  reader-watch.py server          on the host: the webmail's alert file
                                  (/var/lib/mail-status/reader-alert.json) and
                                  a note to each domain's postmaster on a change
  reader-watch.py github FILE     in GitHub Actions: the run fails, and GitHub
                                  mails the repository's owner; also checks the
                                  webmail's static files against FILE
  reader-watch.py expected        prints FILE for the webmail as deployed
                                  (scripts/watch-sync.sh, after deploy.sh)

A problem is any of these:
 - a domain's delegation at its registry is not deSEC's (NS), or its DS does
   not match deSEC's key, or a DS that was there is gone;
 - reader.<domain> at deSEC is not a CNAME to legal-machines.github.io;
 - a certificate for reader.<domain> in the Certificate Transparency logs
   (SSLMate's Cert Spotter) whose key GitHub Pages does not serve, half an
   hour after it was issued: a certificate is what someone who took the name
   would need first;
 - a reader file served other than its repository's SHA256SUMS, or (github
   mode) a webmail file other than FILE says, unless the repository or FILE
   changed in the last 20 minutes and the caches are catching up.
A check that cannot run (the network, an API's limit) is a note, not a problem.
"""
import base64
import datetime
import hashlib
import json
import os
import smtplib
import socket
import ssl
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request

READERS = {"legalmachines.org": ("reader.legalmachines.org", "legal-machines/reader"),
           "dzyza.com": ("reader.dzyza.com", "legal-machines/reader2")}
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
WATCH_RUNS = "https://api.github.com/repos/legal-machines/reader/actions/workflows/watch.yml/runs?status=completed&per_page=1"

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
    return sorted(out)[:2]


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
    ds = [ds_parts(r) for r in records(servers[0], domain, "DS")]
    seen = [" ".join(map(str, d)) for d in ds]
    if ds:
        keys = [k for k in records("ns1.desec.io", domain, "DNSKEY") if k.split()[0] == "257"]
        if not keys:
            notes.append(f"{domain}: deSEC did not answer for DNSKEY")
        else:
            wanted = {ds_from_key(domain, k, d[2]) for k in keys for d in ds if d[2] in (1, 2, 4)}
            if not any(d in wanted for d in ds):
                problems.append(f"the DS of {domain} at its registry does not match deSEC's key")
    elif ds_required:
        problems.append(f"the DS of {domain} at its registry is gone (DNSSEC is off for it)")
    host = READERS[domain][0]
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


def tell_postmasters(problems):
    try:
        with open("/etc/rspamd/local.d/known_token") as f:
            token = f.read().strip()
    except OSError:
        token = ""
    if problems:
        subject = "Mail Reader: someone else may be serving it"
        text = ("The check of the Mail Reader found:\n\n" + "".join(f"- {p}\n" for p in problems) +
                "\nUntil this clears, the webmail opens no encrypted message and adds no key by itself; each message offers "
                "Open anyway. Look at the domain's registrar (REG.RU), deSEC and the GitHub repositories legal-machines/reader "
                "and reader2 before opening encrypted mail.\n")
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
    for domain, seen in ds_seen.items():
        if seen:
            ds_ever[domain] = sorted(set(ds_ever.get(domain, [])) | set(seen))
    # The watcher at GitHub, which sees this server from outside.
    try:
        runs = fetch_json(WATCH_RUNS).get("workflow_runs", [])
        if runs and runs[0].get("conclusion") == "failure":
            problems.append(f"the watcher at GitHub reports a problem: {runs[0].get('html_url', '')}")
    except (OSError, ValueError, urllib.error.URLError):
        pass
    old = state.get("problems", [])
    since = state.get("since") if problems and old else (iso(now()) if problems else None)
    write_public(ALERT, json.dumps({"problems": problems, "since": since, "checked": iso(now())}))
    write_public(STATE, json.dumps({"ds": ds_ever, "problems": problems, "since": since, "notes": notes, "checked": iso(now())}))
    if sorted(problems) != sorted(old):
        tell_postmasters(problems)
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
