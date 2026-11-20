#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2026 Cisco Systems, Inc.

"""Build and serve the VPP Sphinx documentation (used by docs/Makefile).

Usage:
  docs.py build ...   build HTML docs
  docs.py spell ...   spell-check the docs
  docs.py serve ...   serve built docs over HTTP

Layout and inputs come from docs/docs.json; all build output lives under
--out-dir:
  src/              copy of the docs sources
  src/_generated/   siphons and rendered includes
  html/             sphinx output (and its .doctrees cache)
"""

import argparse
import datetime
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

# This file lives in <ws>/docs/; everything else is described by the shared
# config file below.
WS_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = "docs/docs.json"


def run(cmd, **kw):
    print("+", " ".join(str(c) for c in cmd), flush=True)
    subprocess.run([str(c) for c in cmd], check=True, **kw)


def walk(ws, rel):
    """Everything below ws/rel in directory order, symlinks not followed
    (what "find" does)."""
    with os.scandir(ws / rel) as it:
        entries = list(it)
    for e in entries:
        r = e.name if rel == "." else f"{rel}/{e.name}"
        yield r, e
        if e.is_dir(follow_symlinks=False):
            yield from walk(ws, r)


def siphon_inputs(a):
    """Source files fed to the siphons. The order matters for the generated
    documents, and a file is listed once per input directory containing it."""
    ws = a.ws_root
    md_dirs = set()
    for root in a.siphon_md_scan:
        for rel, e in walk(ws, root):
            if e.name.endswith(".md"):
                md_dirs.add(os.path.dirname(rel))
    files = []
    for d in sorted(md_dirs) + a.siphon_dir:
        if not (ws / d).is_dir():
            sys.exit(f"docs: input path '{d}' does not exist")
        for rel, e in walk(ws, d):
            if not e.is_file(follow_symlinks=False):
                continue
            if not e.name.endswith((".c", ".h", ".dox")):
                continue
            if any(rel.startswith(x) for x in a.siphon_exclude):
                continue
            files.append(rel)
    return files


def feature_files(ws):
    return [f"./{rel}" for rel, e in walk(ws, ".") if e.name == "FEATURE.yaml"]


def stat_sig(p):
    st = p.stat()
    return [st.st_mtime_ns, st.st_size]


def hash_files(ws, rels):
    h = hashlib.sha256()
    for rel in sorted(rels):
        try:
            sig = stat_sig(ws / rel)
        except OSError:
            continue
        h.update(f"{rel}\0{sig[0]}\0{sig[1]}\n".encode())
    return h.hexdigest()


def copy_if_changed(src, dst):
    """Copy only when content differs, so Sphinx sees no spurious change."""
    if dst.exists() and dst.read_bytes() == src.read_bytes():
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dst)


def template(path, repl):
    s = path.read_text()
    n = s
    for k, v in repl.items():
        n = n.replace(k, v)
    if n != s:
        path.write_text(n)


def sync_sources(a, src, stamp):
    """Copy the docs sources into src/ (symlinks resolved): everything the
    first time, afterwards only what changed since the previous run."""
    skip = {Path(__file__).resolve(), a.config.resolve()}
    since = stamp.stat().st_mtime_ns if stamp.exists() else None
    start = out_time(stamp.parent)
    for root, dirs, files in os.walk(a.docs_dir, followlinks=True):
        root = Path(root)
        dirs[:] = [
            d for d in dirs if d != "__pycache__" and (since is None or d != "_scripts")
        ]
        dst_dir = src / root.relative_to(a.docs_dir)
        dst_dir.mkdir(parents=True, exist_ok=True)
        for name in files:
            p = root / name
            if not p.is_file() or p.resolve() in skip:
                continue
            if since is None or p.stat().st_mtime_ns > since:
                dst = dst_dir / name
                dst.unlink(missing_ok=True)
                shutil.copy(p, dst)
    stamp.touch()
    os.utime(stamp, ns=(start, start))


def out_time(d):
    """Current time as seen by the file system holding d."""
    probe = d / ".now"
    probe.touch()
    t = probe.stat().st_mtime_ns
    probe.unlink()
    return t


def apply_templates(a, src):
    version = subprocess.run(
        [a.version_script], check=True, capture_output=True, text=True
    ).stdout.strip()
    template(
        src / "index.rst",
        {
            "__VPP_VERSION__": version,
            "__BUILT_ON__": datetime.date.today().strftime("%d %B %Y"),
        },
    )
    for p in src.rglob("*"):
        if p.suffix in (".rst", ".md") and p.is_file():
            if b"__REPOSITORY_URL__" in p.read_bytes():
                template(p, {"__REPOSITORY_URL__": a.repo_url})


def generate(a, py, env, src):
    """Run the siphons / feature list / includes into the source tree."""
    ws = a.ws_root
    gen = src / "_generated"
    frag = gen / "fragments"
    if gen.exists():
        shutil.rmtree(gen)
    frag.mkdir(parents=True)

    lst = frag / "files"
    lst.write_text("".join(f"{f}\n" for f in siphon_inputs(a)))
    run(
        [py, a.scripts_dir / "siphon-generate", f"--output={frag}", f"@{lst}"],
        cwd=ws,
        env=env,
    )
    for s in a.siphon_type:
        d = gen / f"{s}.rst.dir"
        d.mkdir()
        run(
            [
                py,
                a.scripts_dir / "siphon-process",
                f"--type={s}",
                "--format=markdown",
                f"--repolink={a.repo_url}/",
                f"--outdir={d}",
                f"--output={gen / (s + '.rst')}",
                frag / f"{s}.siphon",
            ],
            cwd=ws,
            env=env,
        )
    # the command reference is built from the "clicmd" siphon
    cli = src / a.cli_dir
    copy_if_changed(gen / "clicmd.rst", cli / "index.rst")
    for f in (gen / "clicmd.rst.dir").rglob("*"):
        if f.is_file():
            copy_if_changed(f, cli / "clis" / f.relative_to(gen / "clicmd.rst.dir"))

    inc = src / a.includes_dir
    inc.mkdir(parents=True, exist_ok=True)
    run([py, a.scripts_dir / "includes_renderer.py", ws, inc], env=env)


def feature_list(a, py, src):
    fl = subprocess.run(
        [py, a.fts_script, "--markdown", "--repolink", a.repo_url],
        cwd=a.ws_root,
        input="".join(f"{f}\n" for f in feature_files(a.ws_root)),
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    dst = src / a.featurelist
    if not dst.exists() or dst.read_text() != fl:
        dst.write_text(fl)


def load_config(ws, out_dir, config=None):
    """Shared docs configuration (docs/docs.json); this is the one
    place that knows the docs source layout."""
    cfg_file = config or ws / DEFAULT_CONFIG
    raw = json.loads(cfg_file.read_text())
    a = argparse.Namespace(ws_root=ws, out_dir=out_dir, config=cfg_file)
    for k in ("docs_dir", "scripts_dir", "version_script", "fts_script"):
        setattr(a, k, (ws / raw[k]).resolve())
    for k in (
        "repo_url",
        "siphon_type",
        "siphon_dir",
        "siphon_md_scan",
        "siphon_exclude",
        "cli_dir",
        "featurelist",
        "includes_dir",
    ):
        setattr(a, k, raw[k])
    return a


def common_args(prog):
    ap = argparse.ArgumentParser(prog=prog)
    ap.add_argument(
        "--ws-root",
        type=Path,
        default=WS_ROOT,
        help="source tree root (default: derived from this file)",
    )
    ap.add_argument(
        "--out-dir", required=True, type=Path, help="all build output goes here"
    )
    ap.add_argument(
        "--config", type=Path, help=f"config file (default: <ws-root>/{DEFAULT_CONFIG})"
    )
    return ap


def parse_build_args(argv, prog):
    ap = common_args(prog)
    ap.add_argument(
        "--venv",
        required=True,
        type=Path,
        help="python virtualenv with sphinx and the docs "
        "requirements, created by the caller",
    )
    ap.add_argument("--repo-url", help="repository URL used for source links")
    ap.add_argument(
        "--sphinx-opts", default="--keep-going -n -W", help="sphinx-build options"
    )
    a = ap.parse_args(argv)
    cfg = load_config(
        a.ws_root.resolve(), a.out_dir.resolve(), a.config and a.config.resolve()
    )
    cfg.venv = a.venv.resolve()
    cfg.sphinx_opts = a.sphinx_opts.split()
    cfg.repo_url = a.repo_url or cfg.repo_url
    return cfg


def sphinx(a, builder):
    """Prepare the source tree and run one sphinx builder on it."""
    out = a.out_dir
    src = out / "src"
    sphinx_build = a.venv / "bin" / "sphinx-build"
    if not sphinx_build.exists():
        sys.exit(
            f"docs: {sphinx_build} not found, the virtualenv {a.venv} "
            "needs the docs requirements installed"
        )
    out.mkdir(parents=True, exist_ok=True)
    py = a.venv / "bin" / "python3"
    env = dict(os.environ, PATH=f"{a.venv / 'bin'}:{os.environ['PATH']}")

    # 1. copy edited docs files into the Sphinx source tree
    sync_sources(a, src, out / ".docsrc.sync.ok")

    # 2. regenerate siphons etc. only if their inputs changed
    ws = a.ws_root
    gen_inputs = siphon_inputs(a) + feature_files(ws)
    gen_inputs += [
        str(p.relative_to(ws))
        for p in a.scripts_dir.rglob("*")
        if p.is_file() and "__pycache__" not in p.parts
    ]
    gen_inputs += [
        str(a.fts_script.relative_to(ws)),
        str(a.config.relative_to(ws)),
        str(Path(__file__).resolve().relative_to(ws)),
    ]
    gen_fp = hash_files(ws, set(gen_inputs)) + a.repo_url
    gen_stamp = src / "_generated" / ".siphon.done"
    fresh = (
        gen_stamp.exists()
        and gen_stamp.read_text() == gen_fp
        and (src / a.cli_dir / "index.rst").exists()
    )
    if not fresh:
        generate(a, py, env, src)
    apply_templates(a, src)
    if not fresh:
        feature_list(a, py, src)
        gen_stamp.write_text(gen_fp)
    else:
        print("Generated docs are up to date")

    # 3. sphinx (incremental). Run from the docs directory: conf.py calls
    #    `git describe` and the spelling extension accepts git author names as
    #    words, both relative to the cwd
    run(
        [sphinx_build, *a.sphinx_opts, "-b", builder, src, out / "html"],
        env=env,
        cwd=a.docs_dir,
    )


def build(argv):
    sphinx(parse_build_args(argv, "docs.py build"), "html")


def spell(argv):
    sphinx(parse_build_args(argv, "docs.py spell"), "spelling")


def changed_pages(ws, docs_dir, html, base):
    """HTML pages for docs/ sources changed (incl. uncommitted) since base."""

    def git(*args):
        return subprocess.run(
            ["git", "-C", ws, *args], capture_output=True, text=True
        ).stdout.split()

    docs_rel = docs_dir.resolve().relative_to(ws.resolve())
    mb = git("merge-base", base, "HEAD")
    if not mb:
        return []
    names = set(git("diff", "--name-only", "--diff-filter=d", mb[0]))
    names |= set(git("ls-files", "--others", "--exclude-standard"))
    pages = []
    for n in sorted(names):
        p = Path(n)
        if not p.is_relative_to(docs_rel) or p.suffix not in (".rst", ".md"):
            continue
        page = p.relative_to(docs_rel).with_suffix(".html")
        if (html / page).exists():
            pages.append(page)
    return pages


def link(url):
    if not sys.stdout.isatty():
        return url
    return f"\033]8;;{url}\033\\\033[1;4;36m{url}\033[0m" f"\033]8;;\033\\"


def serve(argv):
    import functools
    import http.server
    import socket

    ap = common_args("docs.py serve")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--addr", default="", help="bind address (default: all)")
    ap.add_argument(
        "--base", default="origin/master", help="list docs changed since this ref"
    )
    a = ap.parse_args(argv)
    cfg = load_config(
        a.ws_root.resolve(), a.out_dir.resolve(), a.config and a.config.resolve()
    )
    html = cfg.out_dir / "html"

    host = a.addr or socket.getfqdn()
    url = f"http://{host}:{a.port}/"
    print(f"Serving docs (Ctrl-C to stop):\n{link(url)}")
    pages = changed_pages(cfg.ws_root, cfg.docs_dir, html, a.base)
    if pages:
        print(f"\nChanged since {a.base}:")
        for page in pages:
            print(f"  {link(url + str(page))}")
    print(flush=True)

    class QuietHandler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *args):
            pass  # no per-request (or bad-request) noise

    handler = functools.partial(QuietHandler, directory=str(html))
    try:
        with http.server.ThreadingHTTPServer((a.addr, a.port), handler) as srv:
            srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


def main():
    cmds = {"build": build, "spell": spell, "serve": serve}
    if len(sys.argv) < 2 or sys.argv[1] not in cmds:
        sys.exit(f"usage: {sys.argv[0]} {{{','.join(cmds)}}} ...")
    return cmds[sys.argv[1]](sys.argv[2:])


if __name__ == "__main__":
    sys.exit(main())
