# Copyright 2026 Rubicon Communications, LLC.
# SPDX-License-Identifier: Apache-2.0

#!/usr/bin/env python3
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
import multiprocessing
import os
import re
import shutil
import sys
import time
import warnings

# Regex matching the compact hex marker format:
#   [packet hex: __class__.__name__=ClassName: deadbeef...]
HEX_MARKER_RE = re.compile(
    r"^(\s*)\[packet hex: __class__\.__name__=(\w+): ([0-9a-f]+)\]\s*$"
)


def expand_line(line, scapy_classes):
    """Expand a single line if it contains a hex marker, otherwise return as-is.

    Returns a string (possibly multi-line) with the expansion.
    """
    m = HEX_MARKER_RE.match(line)
    if not m:
        return line

    indent, class_name, hex_bytes = m.groups()

    cls = scapy_classes.get(class_name)
    if cls is None:
        # Unknown class — leave the marker intact with a warning
        return (
            f"{indent}[packet hex: UNKNOWN CLASS {class_name} — cannot expand]\n{line}"
        )

    try:
        pkt = cls(bytes.fromhex(hex_bytes))
    except Exception as e:
        return f"{indent}[packet hex: DECODE ERROR ({e}) — cannot expand]\n{line}"

    from scapy.utils import hexdump

    return f"{hexdump(pkt, dump=True)}\n\n{pkt.show(dump=True)}\n"


def expand_file(log_path):
    """Expand all hex markers in a single log file.

    Copies original to raw.log.txt, then writes expanded content to log.txt.
    Returns (path, n_expanded, error_msg) tuple.
    """
    raw_path = os.path.join(os.path.dirname(log_path), "raw.log.txt")

    # Skip if already expanded
    if os.path.exists(raw_path):
        return (log_path, 0, "skipped — raw.log.txt already exists")

    # Quick check: does the file contain any markers at all?
    try:
        with open(log_path, "r", errors="replace") as f:
            content = f.read()
    except (IOError, OSError) as e:
        return (log_path, 0, f"read error: {e}")

    if "[packet hex: __class__.__name__=" not in content:
        return (log_path, 0, "no markers found")

    # Import scapy (expensive, but done once per worker process)
    try:
        with warnings.catch_warnings():
            warnings.filterwarnings(
                "ignore",
                message="TripleDES has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.TripleDES and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.",
            )
            from scapy.all import conf as scapy_conf

        # Build a lookup dict of all known scapy classes
        # ldict maps module names -> lists of Packet subclasses
        scapy_classes = {}
        for module_classes in scapy_conf.layers.ldict.values():
            for cls in module_classes:
                scapy_classes[cls.__name__] = cls
    except ImportError as e:
        return (log_path, 0, f"scapy import error: {e}")

    # Preserve original
    try:
        shutil.copy2(log_path, raw_path)
    except (IOError, OSError) as e:
        return (log_path, 0, f"cannot create raw.log.txt: {e}")

    # Expand markers
    n_expanded = 0
    lines = content.splitlines(True)
    expanded_lines = []
    for line in lines:
        result = expand_line(line, scapy_classes)
        if result is not line:  # identity check — was expanded
            n_expanded += 1
        expanded_lines.append(result)

    # Write expanded content atomically
    tmp_path = log_path + ".expanding"
    try:
        with open(tmp_path, "w") as f:
            f.writelines(expanded_lines)
        os.replace(tmp_path, log_path)
    except (IOError, OSError) as e:
        # Clean up temp file on error, restore original
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        if os.path.exists(raw_path):
            os.replace(raw_path, log_path)
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
        help="Suppress output.",
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

    print(
        f"Expanding scapy hexdump(s) in {len(files)} log file(s) with (up to) {args.workers or os.cpu_count()} worker(s)...",
        end="",
    )

    if len(files) == 1:
        # No need for multiprocessing overhead with a single file
        results = [expand_file(files[0])]
    else:
        with multiprocessing.Pool(processes=args.workers) as pool:
            results = pool.map(expand_file, files)

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
