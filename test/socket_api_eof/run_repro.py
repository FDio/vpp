#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Cisco and/or its affiliates.

"""Exercise VPP's Unix API EOF handling with stale errno injected by LD_PRELOAD.

Exit 0 when VPP does not spin after client EOF. Run this against an unpatched
build to reproduce the failure, then against the fix.
"""

import argparse
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time


def cpu_seconds(pid):
    # Fields 14 and 15 in /proc/PID/stat, after the parenthesized comm field.
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")


def wait_for(path, proc, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"VPP exited early with status {proc.returncode}")
        if path.exists():
            return
        time.sleep(0.02)
    raise RuntimeError(f"timed out waiting for {path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build", type=Path, help="VPP build directory")
    parser.add_argument("shim", type=Path, help="compiled LD_PRELOAD shared library")
    args = parser.parse_args()
    build = args.build.resolve()
    shim = args.shim.resolve()
    with tempfile.TemporaryDirectory(prefix="vpp-eof-") as temp:
        root = Path(temp)
        api = root / "api.sock"
        marker = root / "injected"
        config = root / "startup.conf"
        config.write_text(
            f"unix {{ nodaemon runtime-dir {root} cli-listen {root / 'cli.sock'} }}\n"
            f"api-segment {{ prefix eof-{os.getpid()} }}\n"
            f"socksvr {{ socket-name {api} }}\n"
            "plugins { plugin default { disable } }\n"
        )
        env = os.environ.copy()
        lib = build / "lib" / "x86_64-linux-gnu"
        env["LD_LIBRARY_PATH"] = f"{lib}:{env.get('LD_LIBRARY_PATH', '')}"
        env["LD_PRELOAD"] = str(shim)
        env["VPP_EOF_INJECT_PATH"] = str(api)
        env["VPP_EOF_INJECT_MARKER"] = str(marker)
        log_path = root / "vpp.log"
        with log_path.open("w+") as log:
            proc = subprocess.Popen(
                [str(build / "bin" / "vpp"), "-c", str(config)],
                stdout=log,
                stderr=subprocess.STDOUT,
                env=env,
            )
            try:
                try:
                    wait_for(api, proc)
                    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    client.connect(str(api))
                    client.close()
                    wait_for(marker, proc)
                    start_cpu = cpu_seconds(proc.pid)
                    start_time = time.monotonic()
                    time.sleep(2)
                    elapsed = time.monotonic() - start_time
                    cpu_rate = (cpu_seconds(proc.pid) - start_cpu) / elapsed
                    print(f"injected={marker.exists()} cpu_cores={cpu_rate:.3f}")
                    if cpu_rate >= 0.25:
                        raise RuntimeError("VPP main thread spins after API socket EOF")
                    print("PASS: EOF handled despite stale EAGAIN")
                except Exception:
                    log.flush()
                    print(log_path)
                    print(Path(log_path).read_text()[-4000:])
                    raise
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()


if __name__ == "__main__":
    main()
