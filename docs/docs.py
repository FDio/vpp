#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2026 Cisco Systems, Inc.

"""Build and serve the VPP Sphinx documentation (used by "ninja docs" via
cmake/docs.cmake and by docs/Makefile).

Usage:
  docs.py build ...   build HTML docs and spell-check them
  docs.py serve ...   serve built docs over HTTP

Layout and inputs come from docs/docs.json, shared by the cmake and
make front ends; all build output lives under --out-dir:
  src/    mirror of the docs sources plus generated content
  html/   rendered HTML
  spelling/, doctrees*/, *.stamp, sources.json   caches
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


def git_files(ws, *args):
    """Tracked and untracked-but-not-ignored files, relative to ws."""
    out = subprocess.run(
        [
            "git",
            "-C",
            ws,
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
            "--",
            *args,
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return [f for f in out.split("\0") if f and (ws / f).exists()]


def siphon_inputs(a):
    ws = a.ws_root
    dirs = set(a.siphon_dir)
    for root in a.siphon_md_scan:
        for md in (ws / root).rglob("*.md"):
            dirs.add(str(md.parent.relative_to(ws)))
    files = []
    for d in sorted(dirs):
        base = ws / d
        if not base.is_dir():
            continue
        for p in sorted(base.rglob("*")):
            rel = str(p.relative_to(ws))
            if not p.is_file() or p.suffix not in (".c", ".h", ".dox"):
                continue
            if any(rel.startswith(e) for e in a.siphon_exclude):
                continue
            files.append(rel)
    return list(dict.fromkeys(files))


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


def sync_sources(a, src, repl, manifest_file):
    """Incrementally mirror the docs sources into src/ (symlinks resolved).

    Only files whose stat changed since the last sync are copied (and
    re-templated), so Sphinx only re-reads what you edited.  Files ignored
    by git (stray build output, local virtualenvs) are never mirrored.
    """
    ws = a.ws_root
    old = json.loads(manifest_file.read_text()) if manifest_file.exists() else {}
    new = {}
    for f in git_files(ws, str(a.docs_dir.relative_to(ws))):
        p = ws / f
        if (
            "__pycache__" in p.parts
            or not p.is_file()
            or p.resolve() in (Path(__file__).resolve(), a.config.resolve())
        ):
            continue
        r = str(p.relative_to(a.docs_dir))
        new[r] = stat_sig(p)
        dst = src / r
        if old.get(r) != new[r] or not dst.exists():
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.unlink(missing_ok=True)
            shutil.copyfile(p, dst)
            if dst.suffix in (".rst", ".md"):
                template(dst, repl)
    for r in old.keys() - new.keys():
        (src / r).unlink(missing_ok=True)
    manifest_file.write_text(json.dumps(new))


def generate(a, py, env, out, src):
    """Run the siphons / feature list / includes into the source tree."""
    ws = a.ws_root
    gen = out / "generated"
    frag = gen / "fragments"
    if gen.exists():
        shutil.rmtree(gen)
    frag.mkdir(parents=True)

    files = "\n".join(git_files(ws, "*FEATURE.yaml")) + "\n"
    fl = subprocess.run(
        [py, a.fts_script, "--markdown", "--repolink", a.repo_url],
        cwd=ws,
        input=files,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    fl_tmp = gen / "featurelist.md"
    fl_tmp.write_text(fl)
    copy_if_changed(fl_tmp, src / a.featurelist)

    lst = frag / "files"
    lst.write_text("\n".join(siphon_inputs(a)) + "\n")
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

    inc = gen / "includes"
    inc.mkdir()
    run([py, a.scripts_dir / "includes_renderer.py", ws, inc], env=env)
    for f in inc.iterdir():
        copy_if_changed(f, src / a.includes_dir / f.name)


def load_config(ws, out_dir, config=None):
    """Shared docs configuration (docs/docs.json); this is the one
    place that knows the docs source layout, for cmake and make alike."""
    cfg_file = config or ws / DEFAULT_CONFIG
    raw = json.loads(cfg_file.read_text())
    a = argparse.Namespace(ws_root=ws, out_dir=out_dir, config=cfg_file)
    for k in ("docs_dir", "scripts_dir", "version_script", "fts_script", "wordlist"):
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
    a = ap.parse_args(argv)
    cfg = load_config(
        a.ws_root.resolve(), a.out_dir.resolve(), a.config and a.config.resolve()
    )
    cfg.venv = a.venv.resolve()
    return cfg


def build(argv):
    a = parse_build_args(argv, "docs.py build")
    out = a.out_dir
    src = out / "src"
    sphinx_build = a.venv / "bin" / "sphinx-build"
    if not sphinx_build.exists():
        sys.exit(
            f"docs: {sphinx_build} not found, the virtualenv {a.venv} "
            "needs the docs requirements installed"
        )
    out.mkdir(parents=True, exist_ok=True)
    # keep git from seeing the build output, without a .gitignore entry
    (out / ".gitignore").write_text("*\n")
    py = a.venv / "bin" / "python3"
    env = dict(os.environ, PATH=f"{a.venv / 'bin'}:{os.environ['PATH']}")

    version = subprocess.run(
        [a.version_script], check=True, capture_output=True, text=True
    ).stdout.strip()
    repl = {
        "__VPP_VERSION__": version,
        "__BUILT_ON__": datetime.date.today().strftime("%d %B %Y"),
        "__REPOSITORY_URL__": a.repo_url,
    }

    # 1. mirror edited docs files into the Sphinx source tree
    sync_sources(a, src, repl, out / "sources.json")

    # 2. regenerate siphons etc. only if their inputs changed
    ws = a.ws_root
    gen_inputs = siphon_inputs(a) + git_files(ws, "*FEATURE.yaml")
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
    gen_fp = hash_files(ws, gen_inputs)
    gen_stamp = out / "generated.stamp"
    if (
        not gen_stamp.exists()
        or gen_stamp.read_text() != gen_fp
        or not (src / a.cli_dir / "index.rst").exists()
    ):
        gen_stamp.unlink(missing_ok=True)
        generate(a, py, env, out, src)
        gen_stamp.write_text(gen_fp)
    else:
        print("Generated docs are up to date")

    # 3. sphinx html (incremental)
    sphinx = [sphinx_build, "--keep-going", "-n", "-W"]
    # run from the source tree: conf.py calls `git describe` and the spelling
    # extension accepts git author names as words, both relative to the cwd
    run(
        sphinx + ["-d", out / "doctrees", "-b", "html", src, out / "html"],
        env=env,
        cwd=a.ws_root,
    )

    # 4. spell check (fails the build). The spelling builder only reports on
    #    documents Sphinx re-reads, so drop its cache whenever the check fails
    #    (otherwise a rerun would pass) or the word list changes (Sphinx does
    #    not track it).
    cache = out / "doctrees-spelling"
    wl_stamp = out / "wordlist.stamp"
    wl_sig = json.dumps(stat_sig(a.wordlist)) if a.wordlist.exists() else ""
    if not wl_stamp.exists() or wl_stamp.read_text() != wl_sig:
        shutil.rmtree(cache, ignore_errors=True)
    try:
        run(
            sphinx + ["-d", cache, "-b", "spelling", src, out / "spelling"],
            env=env,
            cwd=a.ws_root,
        )
    except subprocess.CalledProcessError:
        shutil.rmtree(cache, ignore_errors=True)
        wl_stamp.unlink(missing_ok=True)
        raise SystemExit("docs: spelling check failed")
    wl_stamp.write_text(wl_sig)


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
    cmds = {"build": build, "serve": serve}
    if len(sys.argv) < 2 or sys.argv[1] not in cmds:
        sys.exit(f"usage: {sys.argv[0]} {{{','.join(cmds)}}} ...")
    return cmds[sys.argv[1]](sys.argv[2:])


if __name__ == "__main__":
    sys.exit(main())
