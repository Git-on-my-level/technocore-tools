#!/usr/bin/env python3
"""phishing-signal-audit — scan a room capture for wallet-security
phishing lures aimed at new token holders, as an offline alerting pass.

DEMAND: evidence/suggestions/tools-services/2026-11-21.md (11:57 run)
  - request: "Automated phishing detection / wallet security audit
    alerts for new token holders" — evidence: "11-21 10:19 flop_chat:
    Auditing post-claim wallet security best practices. Testing
    automated phishing detection alerts for new token holders." —
    proposed service: scheduled room/agent audit of new-token-holder
    wallet security & phishing signals with alerting. This tool is the
    offline auditor half: it never sees the network; operators feed it
    a captured room export and get the alert rows. Siblings
    sanctions-screen (name-list screening), keyhygiene-audit (key
    lifecycle events), room-dedup (flood collapse) and bot-cadence
    (timing) never read lure text.

Input: one JSONL file, one message per line:
  {"sender": str, "ts": epoch seconds, "text": str}
Optional: --official DOM (repeatable) sets official domains for
lookalike checks; --roster FILE lists verified staff handles, one per
line (role claims from non-roster senders are impersonation).

Signals (rule hits, deterministic; every rule needs lure terms, not
mere topic chat — discussion of seed safety without a solicitation
verb stays clean):
  seed-solicit        BLOCK  seed/recovery/mnemonic/private-key terms
                              plus a request verb (send/share/enter/
                              provide/reveal/post/import...)
  wallet-verify       BLOCK  "verify/connect/sync your wallet" plus
                              urgency (24h, snapshot deadline, final
                              notice, act now...)
  lookalike-domain    BLOCK  URL domain within edit distance 1-2 of
                              an --official domain (not equal)
  support-impersonation WARN sender claims official support/admin/
                              staff role but is not on the roster
  dm-farm             WARN   "DM me / check your DMs" tied to wallet/
                              claim/airdrop/support bait
  get-rich            WARN   guaranteed / risk-free / double-your /
                              100% return next to token/claim talk
Bookkeeping: malformed-line WARN, bad-record WARN.
Verdict: rc 0 no signals, 1 signals found, 2 usage/IO. Room text is
data only: regex + string math, no network, no subprocess; nothing
in the input ever runs. Stdlib only.

VERIFY: `phishing-signal-audit.py --self-test` runs assertion groups
over every detector (unit) plus an end-to-end CLI pass on a synthetic
capture (rc 0/1/2, roster, lookalikes, determinism).
"""
import argparse
import json
import os
import re
import sys
import tempfile

FAIL, WARN = "BLOCK", "WARN"

SEED_RE = re.compile(
    r"\b(seed|recovery|mnemonic|secret)\s+(phrase|words?|key)\b"
    r"|\b(?:12|24)[\s-]?word\b|\bprivate\s+keys?\b", re.I)
SOLICIT_RE = re.compile(
    r"\b(send|share|enter|provide|input|verify|confirm|reveal|post"
    r"|type|import|upload|screenshot)\b", re.I)
VERIFY_WALLET_RE = re.compile(
    r"\b(verify|validate|connect|sync|link|activate)\s+your\s+"
    r"(wallet|account|address)\b|\bwallet\s+(verification|connection"
    r"|sync)\b", re.I)
URGENCY_RE = re.compile(
    r"\b(24|48)[\s-]?h(?:ou?rs?)?\b|\bimmediately\b|\bright\s+now\b"
    r"|\bfinal\s+notice\b|\blast\s+warning\b|\bact\s+now\b"
    r"|before\s+(?:the\s+)?snapshot|\bclaim\s+deadline\b"
    r"|\blimited\s+time\b|\bexpires?\s+(?:soon|today)\b", re.I)
ROLE_RE = re.compile(
    r"\b(official|certified|verified)\s+(support|admin|mod(?:erator)?"
    r"|staff|team|help\s?desk)\b|\bsupport\s+team\s+member\b"
    r"|\badmin\s+here\b", re.I)
DM_RE = re.compile(
    r"\b(?:dm|pm|inbox|message)\s+(?:me|us|now|for)\b"
    r"|\bcheck\s+your\s+dms?\b|\bdm\s+(?:is\s+)?open\b", re.I)
DM_BAIT_RE = re.compile(
    r"\b(wallet|claim|airdrop|snapshot|support|assist|help|recover"
    r"|unlock|issue|problem)\b", re.I)
RICH_RE = re.compile(
    r"\bguaranteed\b|\brisk[\s-]?free\b|\bdouble\s+your\b|\b2x\b"
    r"|\b100\s?%\s+(?:return|profit|apr|bonus)\b", re.I)
TOKEN_TALK_RE = re.compile(
    r"\b(token|claim|airdrop|holder|flop)\b", re.I)
URL_RE = re.compile(r"https?://([^/\s\)>\]]+)", re.I)
NEG_RE = re.compile(
    r"\b(never|don'?t|do\s+not|avoid|nobody|shouldn'?t|won'?t"
    r"|can'?t|refuse)\b", re.I)


def read_msgs(path):
    """Yield (lineno, record-or-None) per JSONL line."""
    try:
        with open(path, errors="replace") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    yield lineno, None
                    continue
                yield lineno, rec if isinstance(rec, dict) else None
    except OSError:
        return


def is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def levenshtein(a, b):
    """Classic two-row edit distance (unit-tested)."""
    if a == b:
        return 0
    if not a or not b:
        return len(a) + len(b)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1,
                           prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def domains(text):
    """Distinct bare domains (registrable part) from URLs in text."""
    out = set()
    for host in URL_RE.findall(text):
        host = host.lower().split(":")[0]
        host = host[4:] if host.startswith("www.") else host
        if "." in host:
            out.add(host)
    return out


def lookalike_of(dom, officials):
    """True if dom is NOT official but sits within edit distance 2."""
    return any(0 < levenshtein(dom, off) <= 2 for off in officials)


def has_solicitation(text):
    """True if a request verb appears without a negator guarding it
    ("never share your seed phrase" is advice, not a lure)."""
    for m in SOLICIT_RE.finditer(text):
        window = text[max(0, m.start() - 24):m.start()]
        if not NEG_RE.search(window):
            return True
    return False


def scan_text(text, officials):
    """One message text -> [(severity, code, detail)] (no roster view)."""
    hits = []
    if SEED_RE.search(text) and has_solicitation(text):
        hits.append((FAIL, "seed-solicit",
                     "seed/recovery material + request verb"))
    if VERIFY_WALLET_RE.search(text) and URGENCY_RE.search(text):
        hits.append((FAIL, "wallet-verify",
                     "wallet verification push + urgency"))
    for dom in sorted(domains(text)):
        if lookalike_of(dom, officials):
            hits.append((FAIL, "lookalike-domain",
                         "%s mimics an official domain" % dom))
    if DM_RE.search(text) and DM_BAIT_RE.search(text):
        hits.append((WARN, "dm-farm", "DM solicitation on support bait"))
    if RICH_RE.search(text) and TOKEN_TALK_RE.search(text):
        hits.append((WARN, "get-rich",
                     "guaranteed-return promise on token talk"))
    return hits


def audit(msgs, roster, officials):
    """Full pass -> (findings, board). findings: (where, sev, code,
    detail); board: per-sender lure counts + per-code totals."""
    findings = []
    per_sender, per_code = {}, {}
    n_msgs = 0
    for lineno, rec in msgs:
        if rec is None:
            findings.append((str(lineno), WARN, "malformed-line",
                             "line %d: not JSON" % lineno))
            continue
        sender, text = rec.get("sender"), rec.get("text")
        if not isinstance(sender, str) or not sender \
                or not isinstance(text, str) or not is_int(rec.get("ts")):
            findings.append((str(lineno), WARN, "bad-record",
                             "line %d: needs sender, int ts, text"
                             % lineno))
            continue
        n_msgs += 1
        for sev, code, detail in scan_text(text, officials):
            findings.append((sender, sev, code, detail))
            per_sender[sender] = per_sender.get(sender, 0) + 1
            per_code[code] = per_code.get(code, 0) + 1
        if ROLE_RE.search(text) and sender not in roster:
            findings.append((sender, WARN, "support-impersonation",
                             "%s claims a staff role off-roster"
                             % sender))
            per_sender[sender] = per_sender.get(sender, 0) + 1
            per_code["support-impersonation"] = \
                per_code.get("support-impersonation", 0) + 1
    board = {"messages": n_msgs, "senders_flagged": len(per_sender),
             "by_code": dict(sorted(per_code.items())),
             "top_senders": sorted(per_sender.items(),
                                   key=lambda kv: (-kv[1], kv[0]))[:8]}
    return findings, board


def verdict(findings):
    if any(sev == FAIL for _, sev, _, _ in findings):
        return "ALERT"
    if findings:
        return "SUSPECT"
    return "CLEAN"


def report(findings, board):
    lines = ["phishing-signal board (%s): %d messages, %d flagged "
             "senders, %d signals" % (verdict(findings),
                                      board["messages"],
                                      board["senders_flagged"],
                                      len(findings))]
    for code, count in board["by_code"].items():
        lines.append("  %-22s %d" % (code, count))
    for sender, count in board["top_senders"]:
        lines.append("  sender %-20s %d signals" % (sender, count))
    lines.append("verdict: " + verdict(findings))
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("capture", help="JSONL room capture "
                    "({sender, ts, text} per line)")
    ap.add_argument("--official", action="append", default=[],
                    metavar="DOM", help="official domain (repeatable); "
                    "URLs within edit distance 2 of it are lookalikes")
    ap.add_argument("--roster", help="file of verified staff handles, "
                    "one per line")
    ap.add_argument("--json", action="store_true",
                    help="machine-readable report")
    args = ap.parse_args(argv)

    roster = set()
    if args.roster:
        try:
            with open(args.roster, errors="replace") as fh:
                roster = {l.strip() for l in fh if l.strip()}
        except OSError as e:
            print("error: cannot read roster: %s" % e, file=sys.stderr)
            return 2
    if not os.path.isfile(args.capture):
        print("error: no capture at %s" % args.capture, file=sys.stderr)
        return 2
    officials = {d.lower().lstrip("www.") for d in args.official
                 if "." in d}
    findings, board = audit(read_msgs(args.capture), roster, officials)
    if args.json:
        print(json.dumps({"verdict": verdict(findings),
                          "board": board,
                          "findings": [dict(where=w, severity=s,
                                            code=c, detail=d)
                                       for w, s, c, d in findings]},
                         ensure_ascii=False))
    else:
        print(report(findings, board))
        for where, sev, code, detail in findings:
            print("  [%s] %s %s: %s" % (sev, code, where, detail))
    return 1 if findings else 0


def self_test():
    assert levenshtein("", "") == 0
    assert levenshtein("abc", "abc") == 0
    assert levenshtein("flop.io", "flap.io") == 1
    assert levenshtein("kitten", "sitting") == 3
    assert levenshtein("ab", "ba") == 2
    assert domains("go to https://FLOP-LABS.io/x now") == {"flop-labs.io"}
    assert domains("no urls here") == set()
    assert lookalike_of("flop-labs.io", {"flop-labs.io"}) is False
    assert lookalike_of("flop-labs.network", {"flop-labs.io"}) is False
    assert lookalike_of("f1op-labs.io", {"flop-labs.io"}) is True
    assert lookalike_of("flop-labs.io", set()) is False

    OFF = ["flop-labs.io"]
    # each lure rule fires...
    for text, want in [
        ("please send your seed phrase to continue the claim",
         "seed-solicit"),
        ("enter your 24-word recovery words to unlock the airdrop",
         "seed-solicit"),
        ("verify your wallet within 24h or lose the snapshot bonus",
         "wallet-verify"),
        ("connect your wallet immediately: final notice before snapshot",
         "wallet-verify"),
        ("claim at https://flop-labs.io/airdrop now",
         None),  # official domain: no lookalike
        ("sync funds via https://flop-1abs.io/wallet",
         "lookalike-domain"),
        ("dm me for support with your wallet claim",
         "dm-farm"),
        ("check your dms to recover your airdrop",
         "dm-farm"),
        ("guaranteed 100% return on your flop tokens this week",
         "get-rich"),
        ("risk-free double your claim bonus, every holder eligible",
         "get-rich"),
    ]:
        codes = [c for _, c, _ in scan_text(text, OFF)]
        assert (want in codes) == (want is not None), (text, codes)
    # ...and lookalikes only fire off official distance, never on-topic
    # chat alone
    assert [c for _, c, _ in scan_text(
        "best practice: never share your seed phrase with anyone",
        OFF)] == [], "advice without a request verb stays clean"
    assert [c for _, c, _ in scan_text(
        "wallet verification discussion thread (no urgency here)",
        OFF)] == [], "no urgency, no lure"

    def m(sender, ts, text):
        return {"sender": sender, "ts": ts, "text": text}

    stream = [(1, m("staff", 10, "official support team member here")),
              (2, m("imp", 11, "certified support: dm me your wallet")),
              (3, None),                    # malformed JSON line
              (4, {"sender": "x", "ts": 5})]  # record without text
    findings, board = audit(stream, roster={"staff"}, officials=OFF)
    codes = sorted({c for _, _, c, _ in findings})
    assert "support-impersonation" in codes and "dm-farm" in codes \
        and "malformed-line" in codes and "bad-record" in codes, codes
    assert board["messages"] == 2, board
    assert board["by_code"]["support-impersonation"] == 1, board
    assert audit([(1, m("staff", 10, "official support team member "
                                "here"))], roster={"staff"},
                 officials=[])[0] == [], "roster member is clean"
    clean = [(1, m("ada", 1, "gm flop fam, snapshot talk only"))]
    assert audit(clean, roster=set(), officials=OFF) == ([],
                                                         {"messages": 1,
                                                          "senders_"
                                                          "flagged": 0,
                                                          "by_code": {},
                                                          "top_senders":
                                                          []}), "clean"

    # end-to-end CLI: rc 0 clean, 1 lures, 2 missing file / bad roster
    tmp = tempfile.mkdtemp(prefix="psa2-")
    cap = os.path.join(tmp, "cap.jsonl")
    with open(cap, "w") as fh:
        for r in [m("ada", 1, "gm flop fam"),
                  m("bob", 2, "gm, snapshot soon")]:
            fh.write(json.dumps(r) + "\n")
    assert main([cap]) == 0
    with open(cap, "a") as fh:
        fh.write(json.dumps(m("imp", 3, "verify your wallet within "
                              "24h at https://flop-labs.io x")) + "\n")
        fh.write(json.dumps(m("imp", 4, "visit https://ffop-labs.io "
                              "now")) + "\n")
    assert main([cap]) == 1
    roster_f = os.path.join(tmp, "roster.txt")
    with open(roster_f, "w") as fh:
        fh.write("ada\nbob\n")
    assert main([cap, "--roster", roster_f]) == 1
    assert main([cap, "--official", "flop-labs.io"]) == 1
    assert main(["nope.jsonl"]) == 2
    assert main([cap, "--roster", "nope.txt"]) == 2
    # determinism: same capture, same findings twice
    f1 = audit(read_msgs(cap), roster=set(), officials=OFF)[0]
    f2 = audit(read_msgs(cap), roster=set(), officials=OFF)[0]
    assert f1 == f2
    print("OK phishing-signal-audit: levenshtein/domain parsing, "
          "seed-solicit, wallet-verify+urgency, lookalike-domain, "
          "support-impersonation vs roster, dm-farm, get-rich, "
          "clean-advice non-firing, bookkeeping, board math, CLI rc "
          "0/1/2, determinism")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (probe hook runs after this)
    else:
        raise SystemExit(main())
