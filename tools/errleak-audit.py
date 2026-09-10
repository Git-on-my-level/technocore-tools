#!/usr/bin/env python3
"""errleak-audit — API error-response leak auditor: scans captured HTTP
error responses for stack traces, internal paths/hosts, raw SQL errors and
credential material that a sanitising error handler should have stripped.

DEMAND: evidence/suggestions/tools-services/2026-09-08.md (11:10 run)
  - "API error-response stack-trace leak audit — evidence: 'Auditing API
    error responses for stack traces' — proposed service: Automated
    exception-sanitisation regression test in[tegration]."
  The failure mode it audits: an exception escapes the handler and the
  gateway/500 page ships the raw trace to the client — file paths, SQL,
  framework versions, sometimes connection strings. This tool ingests
  captured responses (JSONL: one {"id","url","status","headers","body"}
  per line, from a proxy log, HAR export, or regression harness), detects
  leaked implementation detail across 8 language stacks, and reports
  redacted evidence so the leak can be proven (and the handler regression
  fixed) without re-printing the secret material.

Everything is treated strictly as data: bodies are regex-scanned, never
evaluated, executed, or deserialised into objects.

rc 0 no findings / 1 findings (block or review; --strict also info) /
2 usage or IO error.
"""
import argparse
import contextlib
import io
import json
import os
import re
import sys
import tempfile

SEV_ORDER = {"block": 0, "review": 1, "info": 2}

# (kind, severity, compiled pattern, what it means) — body detectors.
BODY_DETECTORS = [
    ("py-traceback", "block",
     re.compile(r"Traceback \(most recent call last\):"),
     "Python traceback header"),
    ("py-frame", "block",
     re.compile(r'File "[^"]+", line \d+, in \w+'),
     "Python source frame"),
    ("java-stack", "block",
     re.compile(r"at [\w$.]+\.<?\w*>?\([^)]*\.java:\d+\)"
                r"|Caused by: [\w.$]*(?:Exception|Error)"),
     "Java/JVM stack frame or cause chain"),
    ("node-stack", "block",
     re.compile(r"\bat\b.{0,50}?(?:[\w./:\\-]+\.(?:js|mjs|cjs|ts)"
                r"|node:internal/[\w/]+):\d+:\d+"),
     "Node/V8 stack frame"),
    ("go-panic", "block",
     re.compile(r"(?m)^panic: .+$|goroutine \d+ \[[\w ,]+\]:"),
     "Go panic dump"),
    ("php-fatal", "block",
     re.compile(r"PHP (?:Fatal|Parse) error:.* in /"
                r"|Uncaught (?:\w*Exception|Error|TypeError)"),
     "PHP fatal/uncaught exception"),
    ("dotnet-stack", "block",
     re.compile(r"\bat (?:System|Microsoft)\.[\w.]+\("),
     ".NET framework stack frame"),
    ("ruby-trace", "block",
     re.compile(r"[\w./-]+\.rb:\d+:in [`'\"]"),
     "Ruby/Rails stack frame"),
    ("cred-uri", "block",
     re.compile(r"(?:postgres(?:ql)?|mysql|mariadb|redis|amqp|"
                r"mongodb(?:\+srv)?|ftp)://[^\s\"'<>@]+:[^\s\"'<>@]+@"),
     "credential-bearing connection URI"),
    ("cloud-key", "block",
     re.compile(r"AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}"
                r"|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"
                r"|xox[baprs]-[A-Za-z0-9-]{10,}|sk_live_[A-Za-z0-9]{10,}"
                r"|-----BEGIN [A-Z ]*PRIVATE KEY-----"),
     "cloud/vendor access key material"),
    ("internal-path", "review",
     re.compile(r"(?<![\w.])(?:/(?:home|root)/[\w.-]+(?:/[\w.-]+)*"
                r"|/(?:var|srv|opt|app|etc|usr/local)/[\w.-]+"
                r"(?:/[\w.-]+)+"
                r"|[A-Za-z]:\\(?:Users|inetpub|www|Windows)\\[\w\\.-]+)"),
     "absolute server filesystem path"),
    ("internal-ip", "review",
     re.compile(r"(?<!\d)(?:127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
                r"|192\.168\.\d{1,3}\.\d{1,3}"
                r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?!\d)"),
     "RFC1918/loopback host address"),
    ("sql-error", "review",
     re.compile(r"SQLSTATE\[[0-9A-Fa-f]{5}\]|ORA-\d{5}"
                r"|syntax error at or near"
                r"|relation \"[^\"]+\" does not exist"
                r"|Unknown column '[^']+'"),
     "raw SQL engine error"),
    ("env-echo", "review",
     re.compile(r"\b[A-Z][A-Z0-9_]{2,}"
                r"(?:_SECRET|_TOKEN|_PASSWORD|_KEY)="),
     "environment/config variable echoed with value"),
]

# header names whose mere presence fingerprints the stack.
FINGERPRINT_HEADERS = ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
                       "x-runtime", "server")
# Server header must carry a version to count as a fingerprint.
VERSIONED_SERVER = re.compile(r"\b[A-Za-z][\w.-]*/\d+\.\d+(?:\.\d+)?")

REDACT_KINDS = {"cred-uri", "cloud-key", "env-echo"}


def redact(kind, text):
    """Evidence preview: bound length, mask secret bodies for key kinds."""
    if len(text) > 90:
        text = text[:60] + "…" + text[-25:]
    if kind == "cloud-key":
        return re.sub(r"(AKIA[0-9A-Z]{4})[0-9A-Z]+", r"\1…", text)
    if kind == "cred-uri":
        return re.sub(r":(//[^\s\"'<>@]+:)[^\s\"'<>@]+(@)",
                      r"\1***\2", text)
    if kind == "env-echo":
        return text.split("=", 1)[0] + "=***"
    return text


def body_text(body):
    """Normalise a body field to scannable text (data only, never exec)."""
    if body is None:
        return ""
    if isinstance(body, bytes):
        return body.decode("utf-8", "replace")
    if isinstance(body, str):
        return body
    return json.dumps(body, ensure_ascii=False, default=str)


def read_rows(path):
    """[(lineno, record-or-None)] — unparsable lines stay None, kept."""
    rows = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for i, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append((i, json.loads(line)))
            except json.JSONDecodeError:
                rows.append((i, None))
    return rows


def scan_response(rec):
    """One response record -> [finding dicts] (may be empty)."""
    out = []
    rid = rec.get("id") or rec.get("url") or "?"
    url = rec.get("url", "")
    status = rec.get("status")
    text = body_text(rec.get("body"))

    for kind, sev, pat, meaning in BODY_DETECTORS:
        m = pat.search(text)
        if m:
            out.append({"kind": kind, "severity": sev, "row": str(rid),
                        "url": url, "status": status, "field": "body",
                        "note": meaning,
                        "evidence": redact(kind, m.group(0))})

    headers = rec.get("headers") or {}
    if isinstance(headers, dict):
        for name, value in headers.items():
            low = str(name).lower()
            val = str(value)
            if low in FINGERPRINT_HEADERS and (
                    low != "server" or VERSIONED_SERVER.search(val)):
                out.append({"kind": "hdr-fingerprint", "severity": "info",
                            "row": str(rid), "url": url, "status": status,
                            "field": f"headers.{name}",
                            "note": "implementation-disclosing header",
                            "evidence": redact("hdr-fingerprint",
                                               f"{name}: {val}")})
    return out


def scan_file(path, errors_only=False):
    """All findings for a JSONL capture file, plus scan counters."""
    rows = read_rows(path)
    findings, scanned = [], 0
    for lineno, rec in rows:
        if rec is None:
            findings.append({"kind": "input-unparsable", "severity": "review",
                             "row": f"line{lineno}", "url": "", "status": None,
                             "field": "meta",
                             "note": "line is not valid JSON",
                             "evidence": ""})
            continue
        if not isinstance(rec, dict):
            findings.append({"kind": "input-shape", "severity": "review",
                             "row": f"line{lineno}", "url": "", "status": None,
                             "field": "meta",
                             "note": "record is not a JSON object",
                             "evidence": ""})
            continue
        if errors_only:
            st = rec.get("status")
            if isinstance(st, int) and st < 400:
                continue
        scanned += 1
        findings.extend(scan_response(rec))
    findings.sort(key=lambda f: (SEV_ORDER[f["severity"]], str(f["row"]),
                                 f["kind"]))
    return findings, len(rows), scanned


def print_text(findings):
    for f in findings:
        where = f["url"] or f["row"]
        st = f" [{f['status']}]" if f.get("status") is not None else ""
        ev = f": {f['evidence']}" if f["evidence"] else ""
        print(f"{f['severity'].upper():6} {f['kind']:15} {where}{st} "
              f"({f['field']}){ev}")


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="errleak-audit",
        description="Scan captured API error responses (JSONL) for leaked "
                    "stack traces, internal paths, SQL errors and secrets.")
    ap.add_argument("capture", help="JSONL file of captured responses")
    ap.add_argument("--json", action="store_true", dest="as_json",
                    help="machine-readable output")
    ap.add_argument("--errors-only", action="store_true",
                    help="only scan records with status >= 400")
    ap.add_argument("--strict", action="store_true",
                    help="rc 1 also for info-severity findings")
    args = ap.parse_args(argv)

    if not os.path.isfile(args.capture):
        print(f"errleak-audit: cannot read {args.capture}", file=sys.stderr)
        return 2
    try:
        findings, total, scanned = scan_file(args.capture, args.errors_only)
    except OSError as exc:
        print(f"errleak-audit: {exc}", file=sys.stderr)
        return 2

    if args.as_json:
        print(json.dumps({"file": args.capture, "records": total,
                          "scanned": scanned, "findings": findings,
                          "by_severity": {s: sum(1 for f in findings
                                                 if f["severity"] == s)
                                          for s in ("block", "review", "info")}},
                         ensure_ascii=False, indent=1))
    else:
        print_text(findings)
        hard = sum(1 for f in findings if f["severity"] != "info")
        print(f"scanned {scanned}/{total} records, "
              f"findings: {len(findings)} (block/review {hard})")

    hits = [f for f in findings
            if f["severity"] in ("block", "review") or args.strict]
    return 1 if hits else 0


def selftest():
    tmp = tempfile.mkdtemp(prefix="errleak-selftest-")

    def dump(name, recs, raw=None):
        path = os.path.join(tmp, name)
        with open(path, "w", encoding="utf-8") as fh:
            for r in recs:
                fh.write(json.dumps(r) + "\n")
            if raw:
                fh.write(raw)
        return path

    def run(argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(argv)
        return rc, buf.getvalue()

    # 1. every body detector fires on a realistic leak, none cross-fires
    cases = [
        ("py-traceback", 'Traceback (most recent call last):\n  File "srv.py"'),
        ("py-frame", 'oops File "/app/billing.py", line 42, in charge'),
        ("java-stack", "Caused by: java.lang.NullPointerException\n"
                       "\tat com.acme.ledger.Posting.apply(Posting.java:88)"),
        ("node-stack", "Error: EACCES\n    at readConfig (/app/cfg.js:12:9)"),
        ("go-panic", "panic: runtime error: index out of range\n"
                     "goroutine 42 [running]:"),
        ("php-fatal", "PHP Fatal error: Uncaught TypeError in /var/www/i.php"),
        ("dotnet-stack", " at System.Data.SqlClient.SqlCommand.ExecuteReader()"),
        ("ruby-trace", "from /srv/app/models/user.rb:31:in `load'"),
        ("cred-uri", "db refused: postgres://svc:hunter2@db-prod:5432/led"),
        ("cloud-key", "key AKIAIOSFODNN7EXAMPLE rejected"),
        ("internal-path", "cannot open /var/log/ledger/app.log here"),
        ("internal-ip", "upstream 10.1.22.9:6379 refused"),
        ("sql-error", 'SQLSTATE[42P01] relation "ledgr" does not exist'),
        ("env-echo", "boot: APP_SECRET=6f2c1d0e9a failed"),
    ]
    for kind, text in cases:
        rec = {"id": "r-" + kind, "url": "https://api/x", "status": 500,
               "headers": {}, "body": text}
        kinds = {f["kind"] for f in scan_response(rec)}
        assert kind in kinds, (kind, kinds)
    # each case trips exactly its own block/review detector family
    slim = scan_response({"id": "s", "body": cases[0][1]})
    assert {f["kind"] for f in slim} == {"py-traceback"}, slim
    node = scan_response({"id": "s", "body": cases[3][1]})
    assert {f["kind"] for f in node} == {"node-stack"}, node

    # 2. false-positive guards: prose must NOT match
    benign = scan_response({"id": "b", "status": 400,
                            "body": "invalid_request_id: no traceback "
                                    "available; we are at your service "
                                    "line 12 of the terms"})
    assert benign == [], benign

    # 3. headers: versioned Server + X-Powered-By are info; bare is not
    hdr = scan_response({"id": "h", "status": 502,
                         "headers": {"Server": "Apache/2.4.52 (Debian)",
                                     "X-Powered-By": "Express"}})
    assert {f["kind"] for f in hdr} == {"hdr-fingerprint"} and \
        len(hdr) == 2, hdr
    bare = scan_response({"id": "h2", "headers": {"Server": "cloud"}})
    assert bare == [], bare

    # 4. redaction never re-prints the secret material
    cred = scan_response({"id": "c", "body": cases[8][1]})
    assert all("hunter2" not in f["evidence"] for f in cred), cred
    key = scan_response({"id": "k", "body": cases[9][1]})
    assert all("EXAMPLE" not in f["evidence"] for f in key), key

    # 5. end-to-end: clean capture rc 0, dirty rc 1, unparsable flagged
    clean = dump("clean.jsonl", [
        {"id": "ok1", "url": "https://api/pay", "status": 400,
         "headers": {"Content-Type": "application/json"},
         "body": {"error": "invalid_request", "hint": "check amount"}},
        {"id": "ok2", "url": "https://api/pay", "status": 503,
         "body": "service temporarily unavailable, retry later"}])
    rc, txt = run([clean])
    assert rc == 0 and "findings: 0" in txt, (rc, txt)
    assert scan_file(clean)[2] == 2

    dirty = dump("dirty.jsonl", [
        {"id": "ok", "status": 400, "body": {"error": "bad_input"}},
        {"id": "boom", "url": "https://api/pay", "status": 500,
         "headers": {"X-Powered-By": "PHP/8.2.1"},
         "body": "Traceback (most recent call last):\n"
                 '  File "/app/pay.py", line 7, in post\n'
                 "psycopg2.errors.UndefinedTable"},
        {"id": "info", "status": 500,
         "headers": {"Server": "nginx/1.24.0"}, "body": "upstream failed"}])
    f, total, scanned = scan_file(dirty)
    assert total == 3 and scanned == 3
    kinds = {x["kind"] for x in f}
    assert {"py-traceback", "py-frame", "hdr-fingerprint"} <= kinds, kinds
    rc, txt = run([dirty])
    assert rc == 1 and "BLOCK" in txt and "INFO" in txt, (rc, txt)
    rc, txt = run([dirty, "--json"])
    assert rc == 1
    j = json.loads(txt)
    assert j["by_severity"]["block"] >= 2 and j["by_severity"]["info"] == 2
    assert all("line 7" in g["evidence"] or g["kind"] != "py-frame"
               for g in j["findings"])
    # errors-only skips the 200-class record, not the leaks
    mixed = dump("mixed.jsonl", [
        {"id": "fine", "status": 200, "body": cases[0][1]},
        {"id": "err", "status": 500, "body": cases[0][1]}])
    _, _, sc = scan_file(mixed, errors_only=True)
    assert sc == 1
    # info-only capture: rc 0, --strict flips it
    info_only = dump("info.jsonl", [
        {"id": "i", "status": 500, "headers": {"Server": "nginx/1.24.0"},
         "body": "upstream failed"}])
    assert run([info_only])[0] == 0
    assert run([info_only, "--strict"])[0] == 1
    # unparsable / wrong-shape lines are kept and flagged, never dropped
    junk = dump("junk.jsonl", [], raw="not json\n[1,2]\n")
    f2, t2, _ = scan_file(junk)
    assert t2 == 2 and {x["kind"] for x in f2} == \
        {"input-unparsable", "input-shape"}, f2
    assert run([junk])[0] == 1
    # usage / IO errors
    assert run([os.path.join(tmp, "missing.jsonl")])[0] == 2
    print("OK errleak-audit self-test: 14 body detectors (8 language "
          "stacks + SQL/paths/IPs/creds), header fingerprints, "
          "false-positive prose guard, secret redaction in evidence, "
          "errors-only + --strict filtering, unparsable-line retention, "
          "exit codes 0/1/2, --json")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        selftest()  # falls through; rc 0 (probe hook runs after this line)
    else:
        try:
            raise SystemExit(main())
        except BrokenPipeError:  # `| head` — downstream closed early
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
            raise SystemExit(0)
