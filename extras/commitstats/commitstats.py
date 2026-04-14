#!/usr/bin/env python3
"""
commitstats.py - Per-committer/maintainer activity stats for the VPP repo.

Reads INFO.yaml (committers), MAINTAINERS (directories + maintainers), then
scans git history over a configurable window and reports, for each tracked
person, the number of authored commits ("gerrits"), the number of commits
they merged for others ("merges"), and the timestamps of the most recent
activity of each kind.

Identity matching handles the fact that contributors often use multiple
addresses over time: we seed identities from INFO.yaml/MAINTAINERS, then
expand them using name+email evidence from Author, Committer, and
Signed-off-by trailers.
"""

import argparse
import collections
import os
import re
import subprocess
import sys
import unicodedata
from datetime import datetime, timezone


REPO_DEFAULT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def norm_name(name):
    if not name:
        return ""
    nfkd = unicodedata.normalize("NFKD", name)
    stripped = "".join(c for c in nfkd if not unicodedata.combining(c))
    return re.sub(r"\s+", " ", stripped.strip().lower())


def norm_email(email):
    return (email or "").strip().lower()


# --------------------------------------------------------------------------
# INFO.yaml parser (minimal — avoids PyYAML dependency).


def _strip_quotes(s):
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "'\"":
        return s[1:-1]
    return s


def parse_info_yaml(path):
    """Return list of {name, email} dicts from the 'committers:' section.

    Hand parser (no PyYAML dep). Handles YAML anchors `&name` and merge
    references `<<: *name` as used by INFO.yaml to reuse the project_lead
    entry inside committers.
    """
    with open(path, encoding="utf-8") as f:
        lines = [ln.rstrip("\n") for ln in f]

    kv_re = re.compile(r"^(\s*)([A-Za-z_][\w-]*):\s*(.*)$")
    anchor_re = re.compile(r"^&(\S+)\s*(.*)$")
    ref_re = re.compile(r"^\*(\S+)\s*$")
    merge_re = re.compile(r"^<<:\s*\*(\S+)\s*$")

    anchors = {}

    def indent(ln):
        return len(ln) - len(ln.lstrip(" "))

    def collect_block(start, base_indent):
        """Collect `key: value` pairs at indent > base_indent."""
        out = {}
        i = start
        while i < len(lines):
            ln = lines[i]
            if not ln.strip() or ln.lstrip().startswith("#"):
                i += 1
                continue
            if indent(ln) <= base_indent:
                break
            m = kv_re.match(ln)
            if m:
                out[m.group(2)] = _strip_quotes(m.group(3))
            i += 1
        return out, i

    # Pass 1: capture every top-level key that declares an anchor.
    i = 0
    while i < len(lines):
        ln = lines[i]
        m = kv_re.match(ln)
        if m and indent(ln) == 0:
            val = m.group(3).strip()
            am = anchor_re.match(val)
            if am:
                name = am.group(1)
                body = am.group(2).strip()
                if body:
                    # Inline scalar / mapping — rare in this file.
                    anchors[name] = {"_value": _strip_quotes(body)}
                    i += 1
                    continue
                block, i = collect_block(i + 1, 0)
                anchors[name] = block
                continue
        i += 1

    # Pass 2: extract committers list.
    committers = []
    i = 0
    while i < len(lines):
        ln = lines[i]
        m = kv_re.match(ln)
        if m and indent(ln) == 0 and m.group(2) == "committers":
            i += 1
            break
        i += 1

    current = None

    def flush():
        nonlocal current
        if current and current.get("name") and current.get("email"):
            committers.append(current)
        current = None

    while i < len(lines):
        ln = lines[i]
        if not ln.strip() or ln.lstrip().startswith("#"):
            i += 1
            continue
        if indent(ln) == 0:
            break  # left the committers: block
        stripped = ln.strip()

        if stripped.startswith("- "):
            flush()
            current = {}
            rest = stripped[2:].strip()
            mm = merge_re.match(rest)
            if mm:
                current.update(anchors.get(mm.group(1), {}))
            else:
                m = kv_re.match(" " + rest)  # reuse kv regex
                if m:
                    current[m.group(2)] = _strip_quotes(m.group(3))
        elif current is not None:
            mm = merge_re.match(stripped)
            if mm:
                for k, v in anchors.get(mm.group(1), {}).items():
                    current.setdefault(k, v)
            else:
                m = kv_re.match(ln)
                if m:
                    current[m.group(2)] = _strip_quotes(m.group(3))
        i += 1
    flush()

    return committers


# --------------------------------------------------------------------------
# MAINTAINERS parser.


def parse_maintainers(path):
    """Return list of {section, ident, dirs, maintainers:[(name,email)]}."""
    sections = []
    current = None
    started = False

    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.rstrip("\n")
            if not started:
                if line.strip().startswith("-----"):
                    started = True
                continue
            if not line.strip():
                if current and (current["maintainers"] or current["dirs"]):
                    sections.append(current)
                current = None
                continue
            if current is None:
                current = {
                    "section": line.strip(),
                    "ident": "",
                    "dirs": [],
                    "maintainers": [],
                }
                continue

            m = re.match(r"^([A-Z]):\s*(.*)$", line)
            if not m:
                continue
            tag, value = m.group(1), m.group(2).strip()
            if tag == "I":
                current["ident"] = value
            elif tag == "M":
                em = re.match(r"^(.*?)\s*<([^>]+)>\s*$", value)
                if em:
                    current["maintainers"].append(
                        (em.group(1).strip(), em.group(2).strip())
                    )
                else:
                    current["maintainers"].append((value, ""))
            elif tag == "F":
                current["dirs"].append(value)

    if current and (current["maintainers"] or current["dirs"]):
        sections.append(current)
    return sections


# --------------------------------------------------------------------------
# Identity registry.


class Person:
    __slots__ = (
        "canonical",
        "names",
        "emails",
        "dirs",
        "gerrits",
        "last_gerrit",
        "merges",
        "last_merge",
        "from_info",
        "from_maintainers",
    )

    def __init__(self, canonical):
        self.canonical = canonical
        self.names = set()
        self.emails = set()
        self.dirs = set()
        self.gerrits = 0
        self.last_gerrit = 0
        self.merges = 0
        self.last_merge = 0
        self.from_info = False
        self.from_maintainers = False


class Registry:
    def __init__(self):
        self.people = []
        self.by_email = {}
        self.by_name = {}

    def _lookup(self, name, email):
        e = norm_email(email)
        n = norm_name(name)
        if e and e in self.by_email:
            return self.by_email[e]
        if n and n in self.by_name:
            return self.by_name[n]
        return None

    def add(self, name, email, *, from_info=False, from_maintainers=False, dirs=()):
        p = self._lookup(name, email)
        if p is None:
            p = Person(name.strip() or email)
            self.people.append(p)
        if name:
            p.names.add(name.strip())
            self.by_name.setdefault(norm_name(name), p)
        if email:
            p.emails.add(email.strip())
            self.by_email.setdefault(norm_email(email), p)
        if from_info:
            p.from_info = True
        if from_maintainers:
            p.from_maintainers = True
        p.dirs.update(dirs)
        return p

    def merge_identity(self, name, email):
        """Associate an observed (name,email) with an existing person,
        creating a new one only if nothing matches."""
        return self.add(name, email)

    def lookup(self, name, email):
        return self._lookup(name, email)


# --------------------------------------------------------------------------
# Git log ingestion.

GIT_FMT = "%H%x1f%an%x1f%ae%x1f%cn%x1f%ce%x1f%at%x1f%ct%x1f%(trailers:key=Signed-off-by,only=true,unfold=true)%x1e"

SOB_RE = re.compile(r"Signed-off-by:\s*(.*?)\s*<([^>]+)>", re.IGNORECASE)


def read_git_log(repo, since_days):
    cmd = [
        "git",
        "-C",
        repo,
        "log",
        f"--since={since_days} days ago",
        f"--pretty=format:{GIT_FMT}",
    ]
    out = subprocess.check_output(cmd, text=True, errors="replace")
    records = out.split("\x1e")
    for rec in records:
        rec = rec.strip("\n")
        if not rec:
            continue
        parts = rec.split("\x1f")
        if len(parts) < 8:
            continue
        sha, an, ae, cn, ce, at, ct, trailers = parts[:8]
        sobs = [(m.group(1), m.group(2)) for m in SOB_RE.finditer(trailers)]
        yield {
            "sha": sha,
            "author_name": an,
            "author_email": ae,
            "author_time": int(at),
            "committer_name": cn,
            "committer_email": ce,
            "committer_time": int(ct),
            "sobs": sobs,
        }


# --------------------------------------------------------------------------
# Reporting.


def fmt_ts(ts):
    if not ts:
        return "-"
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")


def print_table(rows, headers):
    widths = [len(h) for h in headers]
    for r in rows:
        for i, cell in enumerate(r):
            widths[i] = max(widths[i], len(str(cell)))
    fmt = "  ".join("{:<" + str(w) + "}" for w in widths)
    print(fmt.format(*headers))
    print(fmt.format(*["-" * w for w in widths]))
    for r in rows:
        print(fmt.format(*[str(c) for c in r]))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", default=REPO_DEFAULT, help="path to VPP repo")
    ap.add_argument(
        "--days", type=int, default=730, help="look back N days (default: 730)"
    )
    ap.add_argument(
        "--all",
        action="store_true",
        help="also list contributors not in INFO.yaml/MAINTAINERS",
    )
    ap.add_argument(
        "--min-activity",
        type=int,
        default=1,
        help="hide tracked people with fewer than N total commits+merges",
    )
    ap.add_argument(
        "--committer-cutoff",
        type=int,
        default=None,
        metavar="DAYS",
        help="list INFO.yaml committers inactive for at least DAYS",
    )
    ap.add_argument(
        "--maintainer-cutoff",
        type=int,
        default=None,
        metavar="DAYS",
        help="list MAINTAINERS entries inactive for at least DAYS",
    )
    args = ap.parse_args()

    # Widen the scan window if a cutoff asks for a longer look-back than --days,
    # otherwise we can't distinguish "last active 800 days ago" from "never".
    effective_days = max(
        args.days,
        args.committer_cutoff or 0,
        args.maintainer_cutoff or 0,
    )

    info_path = os.path.join(args.repo, "INFO.yaml")
    maint_path = os.path.join(args.repo, "MAINTAINERS")
    if not os.path.exists(info_path) or not os.path.exists(maint_path):
        sys.exit(f"Cannot find INFO.yaml / MAINTAINERS under {args.repo}")

    reg = Registry()

    for c in parse_info_yaml(info_path):
        reg.add(c["name"], c["email"], from_info=True)

    sections = parse_maintainers(maint_path)
    for s in sections:
        for mn, me in s["maintainers"]:
            if not is_real_maintainer(mn, me):
                continue
            reg.add(mn, me, from_maintainers=True, dirs=s["dirs"])

    # First pass: register every (name,email) we observe. reg.add merges
    # into an existing Person when the name OR email already maps to one,
    # so multi-email identities (e.g. Pim's @ipng.ch and @ipng.nl, Damjan's
    # three addresses) collapse together via name-index hits.
    records = list(read_git_log(args.repo, effective_days))
    for rec in records:
        for n, e in [
            (rec["author_name"], rec["author_email"]),
            (rec["committer_name"], rec["committer_email"]),
        ] + rec["sobs"]:
            if n or e:
                reg.add(n, e)

    # Aggregate. A commit counts as a "merge" for the committer only when
    # the committer resolves to a *different* Person than the author AND
    # that person is an INFO.yaml committer. Git's Committer field tracks
    # "last person to run git commit[--amend]", not "who pressed Submit in
    # gerrit", so for rebase-then-handoff workflows a non-committer ends up
    # in the committer slot. Only INFO.yaml committers can actually merge
    # via gerrit, so we credit merges to them only.
    for rec in records:
        ap = reg.lookup(rec["author_name"], rec["author_email"])
        if ap is None:
            ap = reg.add(rec["author_name"], rec["author_email"])
        ap.gerrits += 1
        if rec["author_time"] > ap.last_gerrit:
            ap.last_gerrit = rec["author_time"]

        cp = reg.lookup(rec["committer_name"], rec["committer_email"])
        if cp is None:
            cp = reg.add(rec["committer_name"], rec["committer_email"])
        if cp is not ap and cp.from_info:
            cp.merges += 1
            if rec["committer_time"] > cp.last_merge:
                cp.last_merge = rec["committer_time"]

    total_commits = len(records)
    total_merges = sum(
        1
        for r in records
        if (
            (cp := reg.lookup(r["committer_name"], r["committer_email"])) is not None
            and cp.from_info
            and cp is not reg.lookup(r["author_name"], r["author_email"])
        )
    )

    print(f"Repo:      {args.repo}")
    print(f"Window:    last {effective_days} days")
    print(f"Commits:   {total_commits}")
    print(f"Merges:    {total_merges}  (author != committer)")
    print(f"Sections:  {len(sections)} in MAINTAINERS")
    print()

    def row(p):
        emails = ", ".join(sorted(p.emails)[:3])
        if len(p.emails) > 3:
            emails += f" (+{len(p.emails) - 3})"
        tag = []
        if p.from_info:
            tag.append("C")
        if p.from_maintainers:
            tag.append("M")
        return [
            "".join(tag) or "-",
            p.canonical,
            emails,
            p.gerrits,
            fmt_ts(p.last_gerrit),
            p.merges,
            fmt_ts(p.last_merge),
        ]

    tracked = [p for p in reg.people if p.from_info or p.from_maintainers]
    tracked = [p for p in tracked if (p.gerrits + p.merges) >= args.min_activity]
    tracked.sort(key=lambda p: max(p.last_gerrit, p.last_merge), reverse=True)

    print("Committers (C) and Maintainers (M):")
    print_table(
        [row(p) for p in tracked],
        ["Tag", "Name", "Emails", "Gerrits", "Last Gerrit", "Merges", "Last Merge"],
    )

    if args.all:
        others = [
            p
            for p in reg.people
            if not (p.from_info or p.from_maintainers)
            and (p.gerrits + p.merges) >= args.min_activity
        ]
        others.sort(key=lambda p: p.gerrits + p.merges, reverse=True)
        print()
        print(f"Other contributors ({len(others)}):")
        print_table(
            [row(p) for p in others],
            ["Tag", "Name", "Emails", "Gerrits", "Last Gerrit", "Merges", "Last Merge"],
        )

    now = int(datetime.now(tz=timezone.utc).timestamp())

    def stale_report(label, predicate, cutoff_days):
        cutoff_ts = now - cutoff_days * 86400
        hits = []
        for p in reg.people:
            if not predicate(p):
                continue
            last = max(p.last_gerrit, p.last_merge)
            if last == 0 or last < cutoff_ts:
                hits.append((p, last))
        hits.sort(key=lambda x: x[1])  # oldest first; zeros at the top
        print()
        print(f"{label} inactive for ≥ {cutoff_days} days ({len(hits)}):")
        if not hits:
            print("  (none)")
            return
        rows = []
        for p, last in hits:
            if last == 0:
                age = "never"
            else:
                age = f"{(now - last) // 86400}d"
            rows.append(
                [
                    p.canonical,
                    ", ".join(sorted(p.emails)[:2]),
                    fmt_ts(last) if last else "-",
                    age,
                    p.gerrits,
                    p.merges,
                ]
            )
        print_table(
            rows,
            ["Name", "Emails", "Last Activity", "Age", "Gerrits", "Merges"],
        )

    if args.committer_cutoff is not None:
        stale_report(
            "INFO.yaml committers",
            lambda p: p.from_info,
            args.committer_cutoff,
        )
    if args.maintainer_cutoff is not None:
        stale_report(
            "MAINTAINERS entries",
            lambda p: p.from_maintainers,
            args.maintainer_cutoff,
        )

    print()
    print("Maintainer → directories (from MAINTAINERS):")
    by_person = collections.defaultdict(set)
    for s in sections:
        for mn, me in s["maintainers"]:
            if not is_real_maintainer(mn, me):
                continue
            p = reg.lookup(mn, me)
            if p:
                by_person[p.canonical].update(s["dirs"])
    for name in sorted(by_person):
        dirs = sorted(by_person[name])
        print(f"  {name}")
        for d in dirs:
            print(f"      {d}")


def is_real_maintainer(name, email):
    """Filter MAINTAINERS placeholder entries (unmaintained, mailing lists)."""
    if not name:
        return False
    low = name.lower()
    if low.startswith("n/a"):
        return False
    if "mailing list" in low or low.startswith("community"):
        return False
    if "lists.fd.io" in (email or "").lower() or "lists.fd.io" in low:
        return False
    return True


if __name__ == "__main__":
    main()
