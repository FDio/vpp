#!/usr/bin/env python3
# Copyright 2026 Rubicon Communications, LLC.
# SPDX-License-Identifier: Apache-2.0

"""Expand compact [packet hex: ...] markers in VPP test log files.

During test execution, logger.debug() calls emit a compact one-liner with
packet.summary() and raw hex bytes instead of the full hexdump + show() output.
This script expands those markers back to full scapy output.

Usage:
    # Expand a single log file (copies original to raw.log.txt first):
    expand_ppp.py /tmp/vpp-unittest-TestFoo/log.txt

    # Auto-discover and expand all log.txt files under /tmp:
    expand_ppp.py --discover [--basedir /tmp]

    # Use N parallel workers (default: number of CPUs):
    expand_ppp.py --discover --workers 4

The original log.txt is preserved as raw.log.txt before expansion.
If raw.log.txt already exists, the file is skipped (already expanded).
"""

import argparse
import glob
import os
import re
import shutil
import sys
import time
import warnings
from concurrent.futures import ProcessPoolExecutor, as_completed

# Pre-import scapy in the parent so forked workers inherit it via copy-on-write
# instead of paying the import cost (and resident memory) once per worker.
with warnings.catch_warnings():
    warnings.filterwarnings(
        "ignore",
        message="TripleDES has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.TripleDES and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.",
    )
    from scapy.all import conf as _scapy_conf
    from scapy.utils import hexdump as _hexdump

# Build the class lookup once at module load.
_SCAPY_CLASSES = {}
for _module_classes in _scapy_conf.layers.ldict.values():
    for _cls in _module_classes:
        _SCAPY_CLASSES[_cls.__name__] = _cls

# Regex matching the compact hex marker format:
#   [packet hex: __class__.__name__=ClassName: deadbeef...]
HEX_MARKER_RE = re.compile(
    r"^(\s*)\[packet hex: __class__\.__name__=(\w+): ([0-9a-f]+)\]\s*$"
)
_PROBE = b"[packet hex: __class__.__name__="


def expand_line(line):
    """Expand a single line if it contains a hex marker, otherwise return as-is.

    Returns a string (possibly multi-line) with the expansion.
    """
    m = HEX_MARKER_RE.match(line)
    if not m:
        return line

    indent, class_name, hex_bytes = m.groups()

    cls = _SCAPY_CLASSES.get(class_name)
    if cls is None:
        return (
            f"{indent}[packet hex: UNKNOWN CLASS {class_name} — cannot expand]\n{line}"
        )

    try:
        pkt = cls(bytes.fromhex(hex_bytes))
    except Exception as e:
        return f"{indent}[packet hex: DECODE ERROR ({e}) — cannot expand]\n{line}"

    return f"{_hexdump(pkt, dump=True)}\n\n{pkt.show(dump=True)}\n"


def _has_marker(log_path, chunk_size=1 << 16):
    """Chunked binary scan for the marker probe — avoids loading the full file."""
    overlap = len(_PROBE) - 1
    with open(log_path, "rb") as f:
        prev = b""
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                return False
            if _PROBE in prev + chunk:
                return True
            prev = chunk[-overlap:] if len(chunk) >= overlap else chunk


def expand_file(log_path):
    """Expand all hex markers in a single log file.

    Streams line-by-line: read input, write expanded content to a temp file,
    atomically replace. Original is preserved as raw.log.txt first so a crash
    mid-write leaves a recoverable copy alongside the unmodified log.
    Returns (path, n_expanded, error_msg).
    """
    raw_path = os.path.join(os.path.dirname(log_path), "raw.log.txt")

    if os.path.exists(raw_path):
        return (log_path, 0, "skipped — raw.log.txt already exists")

    try:
        if not _has_marker(log_path):
            return (log_path, 0, "no markers found")
    except OSError as e:
        return (log_path, 0, f"read error: {e}")

    try:
        shutil.copy2(log_path, raw_path)
    except OSError as e:
        return (log_path, 0, f"cannot create raw.log.txt: {e}")

    tmp_path = log_path + ".expanding"
    n_expanded = 0
    try:
        with open(raw_path, "r", errors="replace") as fin, open(tmp_path, "w") as fout:
            for line in fin:
                result = expand_line(line)
                if result is not line:  # identity check — was expanded
                    n_expanded += 1
                fout.write(result)
        os.replace(tmp_path, log_path)
    except OSError as e:
        if os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        if os.path.exists(raw_path):
            try:
                os.unlink(raw_path)
            except OSError:
                pass
        return (log_path, 0, f"write error: {e}")

    return (log_path, n_expanded, None)


def discover_log_files(basedir="/tmp"):
    """Find all log.txt files in vpp-unittest-* directories."""
    pattern = os.path.join(basedir, "vpp-unittest-*/log.txt")
    return sorted(glob.glob(pattern))


def main():
    start_time = time.time()
    parser = argparse.ArgumentParser(
        description="Expand [packet hex: ...] markers in VPP test log files."
    )
    parser.add_argument(
        "files",
        nargs="*",
        help="Log files to expand. If --discover is used, these are ignored.",
    )
    parser.add_argument(
        "--discover",
        action="store_true",
        help="Auto-discover log.txt files in vpp-unittest-* dirs under --basedir.",
    )
    parser.add_argument(
        "--basedir",
        default="/tmp",
        help="Base directory for --discover (default: /tmp).",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=None,
        help="Number of parallel workers (default: number of CPUs).",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress per-file output.",
    )
    args = parser.parse_args()

    if args.discover:
        files = discover_log_files(args.basedir)
        if not files:
            print(f"No log.txt files found under {args.basedir}/vpp-unittest-*/")
            return 0
    elif args.files:
        files = args.files
    else:
        parser.print_help()
        return 1

    workers = args.workers or os.cpu_count() or 1
    print(
        f"Expanding scapy hexdump(s) in {len(files)} log file(s) with (up to) {workers} worker(s)...",
        end="",
    )

    results = []
    if len(files) == 1:
        results.append(expand_file(files[0]))
    else:
        with ProcessPoolExecutor(max_workers=workers) as ex:
            futures = {ex.submit(expand_file, f): f for f in files}
            for fut in as_completed(futures):
                f = futures[fut]
                try:
                    results.append(fut.result())
                except Exception as e:
                    results.append((f, 0, f"worker error: {type(e).__name__}: {e}"))

    # Report results
    total_expanded = 0
    for path, n_expanded, error in results:
        name = os.path.basename(os.path.dirname(path))
        if error:
            if not args.quiet:
                print(f"  {name:<40} {error}")
        elif n_expanded:
            if not args.quiet:
                print(f"  {name:<40} expanded {n_expanded} markers")
            total_expanded += n_expanded

    print(
        f"done. {total_expanded} instances across {sum(1 for _, n, e in results if n > 0 and e is None)} files expanded in {time.time() - start_time:.2f} seconds."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
