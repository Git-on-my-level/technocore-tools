#!/usr/bin/env python3
"""gateway-config-audit — audit edge-gateway TLS termination and SNI
logging configuration posture from captured setting records.

DEMAND: evidence/suggestions/tools-services/ (file citations below)
  - "Define the review and approval gate that a gateway that terminates TLS but logs no SNI should be under"
  - "Describe how a gateway that terminates TLS but logs no SNI should separate configuration from code"
  - "Describe the artifact that a gateway that terminates TLS but logs no SNI should produce for reproducible packaging and release"
  - "List the minimum permissions a gateway that terminates TLS but logs no SNI should have"
  Scope: one captured gateway-config JSONL export, a record per line:
    {"gateway","ts","setting":"tls_terminates"|"sni_logging"|"config_source"|
    "permissions"|"approval_gate"|"release_artifact","value"} with value
    types tls_terminates/sni_logging bool, config_source "repo"|"image"|
    "inline", permissions list of strings, approval_gate {"required":bool,
    "owners":int}, release_artifact {"digest":str,"reproducible":bool}.
    A gateway that terminates TLS but logs no SNI fails the posture gate
    outright and must show separated config, minimum permissions, an
    approval gate with owners, and a reproducible release artifact;
    conflicting declarations of one setting block any conclusion.
    Records are data only: plain JSON parsing, no network, no subprocess,
    nothing is executed. rc 0 clean, 1 findings, 2 usage/IO. Stdlib only.
"""
import argparse
import json
import sys

SETTINGS = ("tls_terminates", "sni_logging", "config_source", "permissions",
            "approval_gate", "release_artifact")
MIN_PERMISSIONS = frozenset(("tls:terminate", "route:forward", "log:write"))
CONFIG_IN_CODE = ("inline", "image")     # config baked into code or image
VALUE_SHAPES = {"tls_terminates": bool, "sni_logging": bool,
                "config_source": str, "permissions": list,
                "approval_gate": dict, "release_artifact": dict}


def load_jsonl(path):
    """Read a JSONL capture -> (records, bad_line_numbers)."""
    records, bad = [], []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                bad.append(n)
                continue
            if isinstance(rec, dict):
                records.append(rec)
            else:
                bad.append(n)
    return records, bad


def _f(sev, kind, origin, detail):
    """One finding in the shared family shape."""
    return {"severity": sev, "kind": kind, "origin": origin, "detail": detail}


def current_values(records):
    """gateway -> {setting: value} using the last declaration of each
    (gateway, setting) pair; re-declaring a setting updates posture."""
    cur = {}
    for rec in records:
        gw, st = rec.get("gateway"), rec.get("setting")
        if isinstance(gw, str) and gw and isinstance(st, str) and st:
            cur.setdefault(gw, {})[st] = rec.get("value")
    return cur


def terminating(records):
    """Gateways whose current tls_terminates value is exactly True."""
    return {gw for gw, cfg in current_values(records).items()
            if cfg.get("tls_terminates") is True}


def no_sni_gateways(records):
    """Gateways that terminate TLS but do not log SNI (false or absent) —
    the population the posture cascade below applies to."""
    return {gw for gw, cfg in current_values(records).items()
            if cfg.get("tls_terminates") is True
            and cfg.get("sni_logging") is not True}


def sni_findings(records):
    """A gateway that terminates TLS but logs no SNI fails the gate: it
    hides the hostname dimension of the traffic it decrypts."""
    out = []
    for gw in no_sni_gateways(records):
        out.append(_f("BLOCK", "no-sni-logging", gw,
                      "terminates TLS with sni_logging=%r — this gateway "
                      "must sit under a review and approval gate"
                      % current_values(records)[gw].get("sni_logging")))
    return out


def separation_findings(records):
    """Configuration must be separated from code: an inline or image
    config_source on a no-SNI gateway bakes configuration into the
    shipped thing itself; a missing config_source is only a gap."""
    out = []
    hot = no_sni_gateways(records)
    for gw, cfg in current_values(records).items():
        if gw not in terminating(records):
            continue
        src = cfg.get("config_source")
        if "config_source" not in cfg:
            out.append(_f("WARN", "config-source-missing", gw,
                          "tls-terminating gateway declares no config_source"))
        elif gw in hot and src in CONFIG_IN_CODE:
            out.append(_f("BLOCK", "config-not-separated", gw,
                          "config_source=%r keeps configuration inside the "
                          "code/image; declare it from a repo" % (src,)))
    return out


def permission_findings(records):
    """Minimum permissions only: {"tls:terminate","route:forward",
    "log:write"} — each permission beyond that set widens the blast
    radius of a gateway that already hides SNI."""
    out = []
    hot = no_sni_gateways(records)
    for gw, cfg in current_values(records).items():
        if gw not in terminating(records):
            continue
        perms = cfg.get("permissions")
        if "permissions" not in cfg or not isinstance(perms, list):
            out.append(_f("WARN", "permissions-missing", gw,
                          "tls-terminating gateway declares no permissions "
                          "list"))
            continue
        for p in sorted({p for p in perms if isinstance(p, str)}):
            if gw in hot and p not in MIN_PERMISSIONS:
                out.append(_f("WARN", "permission-beyond-minimum", gw,
                              "permission %r is beyond the minimal set %s"
                              % (p, sorted(MIN_PERMISSIONS))))
    return out


def gate_findings(records):
    """The review/approval gate: a no-SNI gateway needs required=True and
    at least one owning reviewer; an undeclared gate is only a gap."""
    out = []
    hot = no_sni_gateways(records)
    for gw, cfg in current_values(records).items():
        if gw not in terminating(records):
            continue
        gate = cfg.get("approval_gate")
        if "approval_gate" not in cfg or not isinstance(gate, dict):
            out.append(_f("WARN", "approval-gate-missing", gw,
                          "tls-terminating gateway declares no approval "
                          "gate"))
            continue
        if gw in hot and (gate.get("required") is not True
                          or not gate.get("owners")):
            out.append(_f("BLOCK", "approval-gate-open", gw,
                          "approval_gate required=%r owners=%r — no review "
                          "gate owns this no-SNI gateway"
                          % (gate.get("required"), gate.get("owners"))))
    return out


def artifact_findings(records):
    """Release artifact: a no-SNI gateway must ship a digest-pinned,
    reproducibly built artifact; missing digest or irreproducible builds
    only warn (the gateway already blocks above)."""
    out = []
    hot = no_sni_gateways(records)
    for gw, cfg in current_values(records).items():
        if gw not in terminating(records):
            continue
        art = cfg.get("release_artifact")
        if "release_artifact" not in cfg or not isinstance(art, dict):
            out.append(_f("WARN", "release-artifact-missing", gw,
                          "tls-terminating gateway declares no release "
                          "artifact"))
            continue
        if gw in hot:
            digest = art.get("digest")
            if not isinstance(digest, str) or not digest.strip():
                out.append(_f("WARN", "artifact-no-digest", gw,
                              "release artifact carries no digest to pin"))
            if art.get("reproducible") is not True:
                out.append(_f("WARN", "artifact-not-reproducible", gw,
                              "release artifact is not reproducible — "
                              "packaging cannot be re-verified"))
    return out


def conflict_findings(records):
    """Same gateway+setting declared twice with different values is a
    conflicting capture: posture cannot be concluded from it."""
    out = []
    seen = {}                          # (gateway, setting) -> value signature
    for rec in records:
        gw, st = rec.get("gateway"), rec.get("setting")
        if not (isinstance(gw, str) and gw and isinstance(st, str) and st):
            continue
        sig = json.dumps(rec.get("value"), sort_keys=True, ensure_ascii=False)
        prev = seen.get((gw, st))
        if prev is not None and prev != sig:
            out.append(_f("BLOCK", "conflicting-values", gw,
                          "setting %s declared with conflicting values: %s "
                          "vs %s" % (st, prev, sig)))
        else:
            seen[(gw, st)] = sig
    return out


def audit(path):
    """Load the capture and concatenate every check's findings."""
    records, bad = load_jsonl(path)
    findings = []
    for n in bad:
        findings.append(_f("WARN", "malformed-line", "line:%d" % n,
                           "line is not a JSON object; record skipped"))
    for rec in records:
        st = rec.get("setting")
        if st not in SETTINGS:
            findings.append(_f("WARN", "unknown-setting", rec.get("gateway"),
                               "setting %r is not part of the posture "
                               "capture vocabulary" % (st,)))
        elif not isinstance(rec.get("value"), VALUE_SHAPES[st]):
            findings.append(_f("WARN", "bad-value-shape", rec.get("gateway"),
                               "setting %s value %r does not match its "
                               "expected type" % (st, rec.get("value"))))
    for check in (sni_findings, separation_findings, permission_findings,
                  gate_findings, artifact_findings, conflict_findings):
        findings.extend(check(records))
    return findings


def render(findings):
    """Print one human line per finding; return severity counts."""
    counts = {}
    for x in findings:
        sev = x.get("severity", "WARN")
        counts[sev] = counts.get(sev, 0) + 1
        print("%-5s %-26s %s: %s"
              % (sev, x["kind"], x.get("origin"), x["detail"]))
    return counts


def main(argv=None):
    """CLI: one capture path; --json emits machine-readable findings."""
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("file", help="captured gateway-config JSONL export")
    ap.add_argument("--json", action="store_true",
                    help="emit one JSON object with all findings")
    args = ap.parse_args(argv)
    try:
        findings = audit(args.file)
    except OSError as e:
        print("cannot read %s: %s" % (args.file, e), file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps({"findings": findings}, ensure_ascii=False))
    else:
        counts = render(findings)
        print("%d finding(s): %s" % (
            len(findings),
            ", ".join("%s=%d" % kv for kv in sorted(counts.items())) or "clean"))
    return 1 if findings else 0


def self_test():
    import io
    import os
    import tempfile
    from contextlib import redirect_stderr, redirect_stdout

    def gset(gw, setting, value):
        return {"gateway": gw, "ts": "2026-09-30T10:00:00Z",
                "setting": setting, "value": value}

    def kinds(f):
        return [x["kind"] for x in f]

    paths = []

    def capture(recs, raw=""):
        fh = tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False,
                                         encoding="utf-8")
        for r in recs:
            fh.write(json.dumps(r) + "\n")
        if raw:
            fh.write(raw)
        fh.close()
        paths.append(fh.name)
        return fh.name

    try:
        # --- the no-SNI cascade: one gateway failing all five postures
        worst = [gset("edge-a", "tls_terminates", True),
                 gset("edge-a", "sni_logging", False),
                 gset("edge-a", "config_source", "inline"),
                 gset("edge-a", "permissions",
                      ["tls:terminate", "route:forward", "log:write",
                       "net:raw"]),
                 gset("edge-a", "approval_gate",
                      {"required": False, "owners": 0}),
                 gset("edge-a", "release_artifact",
                      {"digest": "", "reproducible": False})]
        f = sni_findings(worst)
        assert kinds(f) == ["no-sni-logging"] and f[0]["severity"] == "BLOCK"
        assert kinds(separation_findings(worst)) == ["config-not-separated"]
        f = permission_findings(worst)
        assert kinds(f) == ["permission-beyond-minimum"] and "net:raw" in f[0]["detail"]
        assert kinds(gate_findings(worst)) == ["approval-gate-open"]
        assert sorted(kinds(artifact_findings(worst))) == \
            ["artifact-no-digest", "artifact-not-reproducible"]
        assert no_sni_gateways(worst) == {"edge-a"}
        # --- a fully compliant gateway passes every check
        good = [gset("edge-b", "tls_terminates", True),
                gset("edge-b", "sni_logging", True),
                gset("edge-b", "config_source", "repo"),
                gset("edge-b", "permissions",
                     ["tls:terminate", "route:forward", "log:write"]),
                gset("edge-b", "approval_gate",
                     {"required": True, "owners": 2}),
                gset("edge-b", "release_artifact",
                     {"digest": "sha256:4f2a", "reproducible": True})]
        for check in (sni_findings, separation_findings, permission_findings,
                      gate_findings, artifact_findings, conflict_findings):
            assert check(good) == [], check.__name__
        # --- sni_logging merely absent still trips the no-SNI gate
        absent = [gset("edge-c", "tls_terminates", True),
                  gset("edge-c", "approval_gate", {"required": True, "owners": 3})]
        assert kinds(sni_findings(absent)) == ["no-sni-logging"]
        # --- non-terminating gateway: no posture findings at all
        idle = [gset("edge-d", "sni_logging", False)]
        assert sni_findings(idle) == [] and gate_findings(idle) == []
        # --- missing settings on a terminating gateway warn per key
        f = separation_findings(absent)
        assert kinds(f) == ["config-source-missing"]
        assert kinds(permission_findings(absent)) == ["permissions-missing"]
        assert kinds(artifact_findings(absent)) == ["release-artifact-missing"]
        # --- every extra permission warns on its own
        wide = [gset("edge-e", "tls_terminates", True),
                gset("edge-e", "sni_logging", False),
                gset("edge-e", "permissions",
                     ["tls:terminate", "dns:resolve", "fs:read", "fs:read"])]
        assert kinds(permission_findings(wide)) == \
            ["permission-beyond-minimum", "permission-beyond-minimum"]
        # --- conflicting re-declarations block; identical ones do not
        flip = [gset("edge-f", "tls_terminates", True),
                gset("edge-f", "tls_terminates", False)]
        f = conflict_findings(flip)
        assert kinds(f) == ["conflicting-values"] and f[0]["severity"] == "BLOCK"
        assert conflict_findings(good + good) == []
        assert sni_findings(flip) == []     # last value wins for posture
        # --- unknown setting and bad value shape surface through audit
        f = audit(capture([gset("edge-g", "mtu", 1500),
                           gset("edge-g", "tls_terminates", "yes")], raw="}\n"))
        assert sorted(kinds(f)) >= ["bad-value-shape", "malformed-line",
                                    "unknown-setting"]
        # --- CLI rc contract: 0 clean, 1 findings, 2 unreadable path
        p_good, p_bad = capture(good), capture(worst)
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            rc = (main([p_good]), main([p_bad]), main(["/no/such/cfg.jsonl"]))
        assert rc == (0, 1, 2), rc
    finally:
        for p in paths:
            try:
                os.unlink(p)
            except OSError:
                pass
    print("self-test OK (no-SNI cascade x5, compliant gateway, absent "
          "sni/multiple settings, extra permissions, conflicting "
          "re-declaration, shape/unknown/malformed, CLI rc 0/1/2)")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (probe hook runs after this)
    else:
        raise SystemExit(main())
