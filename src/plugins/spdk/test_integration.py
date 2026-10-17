#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Cisco and/or its affiliates.
"""Opt-in Linux integration test using only a private TAP and Malloc bdev.

Requires root, fio, nvme-cli, the nvme_tcp module, and SPDK rpc.py. No physical
interface or disk is used. Results are retained in the requested new directory.
"""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid


def command(args, timeout=30):
    result = subprocess.run(
        [str(value) for value in args], capture_output=True, text=True, timeout=timeout
    )
    if result.returncode:
        raise RuntimeError(f"{args}: {result.stdout}\n{result.stderr}")
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vpp", required=True, type=Path)
    parser.add_argument("--vppctl", required=True, type=Path)
    parser.add_argument("--plugins", required=True, type=Path)
    parser.add_argument("--rpc", required=True, type=Path)
    parser.add_argument("--results", required=True, type=Path)
    parser.add_argument("--main-core", default=0, type=int)
    parser.add_argument("--worker", default=1, type=int)
    parser.add_argument("--cycles", default=3, type=int)
    parser.add_argument("--main-heap-size", default="1g")
    parser.add_argument("--mtu", default=1500, choices=(1500, 9000), type=int)
    parser.add_argument("--deferred-rx-max-segs", type=int)
    parser.add_argument("--expect-mixed-rx", action="store_true")
    parser.add_argument(
        "--rx-mode",
        choices=("baseline", "direct", "copied", "pressure"),
        default="baseline",
    )
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("run as root in an isolated Linux test environment")
    if args.cycles < 1 or args.main_core == args.worker:
        parser.error("positive cycle count and distinct main/worker CPUs required")
    if args.deferred_rx_max_segs is not None and args.deferred_rx_max_segs < 1:
        parser.error("positive deferred RX segment limit required")
    if args.expect_mixed_rx and args.rx_mode != "direct":
        parser.error("mixed RX validation requires direct mode")
    for executable in (args.vpp, args.vppctl, args.rpc):
        if not executable.is_file():
            parser.error(f"missing file: {executable}")
    subnet = "198.18.16.0/30"
    if json.loads(command(["ip", "-j", "route", "show", "exact", subnet])):
        parser.error(f"test subnet already has a route: {subnet}")
    args.results.mkdir(parents=True, exist_ok=False)
    tag = uuid.uuid4().hex[:8]
    tap = "spdk" + tag
    nqn = "nqn.2026-10.io.vpp:integration-" + tag
    cli_socket = args.results / "cli.sock"
    rpc_socket = args.results / "rpc.sock"
    if len(str(cli_socket)) >= 100 or len(str(rpc_socket)) >= 100:
        parser.error("results path is too long for Unix-domain socket paths")
    command(["modprobe", "nvme_tcp"])
    log = (args.results / "vpp.log").open("w")
    process = subprocess.Popen(
        [
            str(args.vpp),
            "unix",
            "{",
            "nodaemon",
            "runtime-dir",
            str(args.results),
            "cli-listen",
            str(cli_socket),
            "}",
            "api-segment",
            "{",
            "prefix",
            tag,
            "}",
            "statseg",
            "{",
            "socket-name",
            str(args.results / "stats.sock"),
            "size",
            "4m",
            "}",
            "memory",
            "{",
            "main-heap-size",
            args.main_heap_size,
            "}",
            "cpu",
            "{",
            "main-core",
            str(args.main_core),
            "corelist-workers",
            str(args.worker),
            "}",
            "buffers",
            "{",
            "buffers-per-numa",
            "4096",
            "default",
            "data-size",
            "2048",
            "}",
            "tcp",
            "{",
            "mtu",
            str(args.mtu),
            "}",
            "session",
            "{",
            "enable",
            *(
                ["deferred-rx-max-segs", str(args.deferred_rx_max_segs)]
                if args.deferred_rx_max_segs is not None
                else []
            ),
            "}",
            "plugins",
            "{",
            "path",
            str(args.plugins),
            "plugin",
            "default",
            "{",
            "disable",
            "}",
            "plugin",
            "spdk_plugin.so",
            "{",
            "enable",
            "}",
            "plugin",
            "tap_plugin.so",
            "{",
            "enable",
            "}",
            "plugin",
            "ping_plugin.so",
            "{",
            "enable",
            "}",
            "plugin",
            "unittest_plugin.so",
            "{",
            "enable",
            "}",
            "}",
        ],
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    connected = False
    report = {
        "nqn": nqn,
        "tap": tap,
        "rx_mode": args.rx_mode,
        "mtu": args.mtu,
        "deferred_rx_max_segs": args.deferred_rx_max_segs,
        "cycles": [],
        "cleanup_errors": [],
    }

    def cli(*words):
        output = command([args.vppctl, "-s", cli_socket, *words])
        if re.search(
            r"unknown input|unknown command|failed:|not found|Invalid|cannot", output
        ):
            raise RuntimeError(output)
        return output

    def wait_state(fragment):
        for _ in range(80):
            if process.poll() is not None:
                raise RuntimeError("isolated VPP exited; inspect vpp.log")
            if cli_socket.exists():
                state = cli("show", "spdk")
                if fragment in state:
                    return state
            time.sleep(0.1)
        raise TimeoutError(f"SPDK did not reach {fragment}")

    def rpc(*words):
        return command([sys.executable, args.rpc, "-s", rpc_socket, *words])

    try:
        wait_state("SPDK app: stopped")
        if args.rx_mode != "baseline":
            cli(
                "test", "spdk", "direct-rx", "off" if args.rx_mode == "copied" else "on"
            )
            cli(
                "test",
                "spdk",
                "rx-loan-limit",
                "1" if args.rx_mode == "pressure" else "256m",
            )
        # Security options must fail startup, never silently use plaintext TCP.
        for option, value in (("tls_version", 13), ("enable_ktls", True)):
            config = args.results / f"reject-{option}.json"
            config.write_text(
                json.dumps(
                    {
                        "subsystems": [
                            {
                                "subsystem": "sock",
                                "config": [
                                    {
                                        "method": "sock_impl_set_options",
                                        "params": {"impl_name": "vpp", option: value},
                                    }
                                ],
                            }
                        ]
                    }
                )
            )
            command(
                [
                    args.vppctl,
                    "-s",
                    cli_socket,
                    "spdk",
                    "app",
                    "start",
                    "name",
                    "reject_tls",
                    "json",
                    config,
                    "no-pci",
                    "reactor-mask",
                    f"[{args.worker}]",
                ]
            )
            rejected = wait_state("SPDK app: stopped")
            if "SPDK threads: 0" not in rejected or "last rc: 0" in rejected:
                raise RuntimeError(
                    "unsupported TLS configuration was not cleanly rejected"
                )
            (args.results / f"rejected-{option}.txt").write_text(rejected)
        report["unsupported_tls_rejected"] = True
        if args.deferred_rx_max_segs is None:
            fifo = cli("test", "svm", "fifo", "all")
            (args.results / "fifo-all.txt").write_text(fifo)
            if "SUCCESS" not in fifo:
                raise RuntimeError("FIFO test failed")
            report["fifo_tests"] = "passed"
        else:
            # The deferred FIFO tests require the default retained-segment limit.
            report["fifo_tests"] = "not run: custom deferred RX segment limit"
        interface = cli(
            "create",
            "tap",
            "id",
            "16",
            "host-if-name",
            tap,
            "host-ip4-addr",
            "198.18.16.1/30",
            "no-gso",
        ).strip()
        if not re.fullmatch(r"tap\d+", interface):
            raise RuntimeError(f"unexpected new TAP interface: {interface}")
        cli("set", "interface", "ip", "address", interface, "198.18.16.2/30")
        cli("set", "interface", "mtu", str(args.mtu), interface)
        cli("set", "interface", "state", interface, "up")
        command(["ip", "link", "set", tap, "mtu", str(args.mtu), "up"])
        command(["ping", "-I", tap, "-c", "2", "-W", "2", "198.18.16.2"])
        for cycle in range(1, args.cycles + 1):
            cli(
                "spdk",
                "app",
                "start",
                "name",
                "integration",
                "rpc",
                str(rpc_socket),
                "no-pci",
                "reactor-mask",
                f"[{args.worker}]",
            )
            running = wait_state("framework: started")
            (args.results / f"running-{cycle}.txt").write_text(running)
            (args.results / f"memory-before-{cycle}.txt").write_text(
                cli("show", "memory", "main-heap")
            )
            try:
                rpc("bdev_malloc_create", "64", "4096", "-b", "IntegrationMalloc")
            except RuntimeError:
                (args.results / f"memory-failed-{cycle}.txt").write_text(
                    cli("show", "memory", "main-heap")
                )
                raise
            rpc("nvmf_create_transport", "-t", "TCP", "-m", "4")
            rpc("nvmf_create_subsystem", nqn, "-a")
            rpc("nvmf_subsystem_add_ns", nqn, "IntegrationMalloc")
            rpc(
                "nvmf_subsystem_add_listener",
                nqn,
                "-t",
                "tcp",
                "-a",
                "198.18.16.2",
                "-s",
                "44216",
                "-S",
                "vpp",
            )
            bdevs = json.loads(rpc("bdev_get_bdevs", "-b", "IntegrationMalloc"))
            if len(bdevs) != 1 or bdevs[0]["product_name"] != "Malloc disk":
                raise RuntimeError(
                    "refusing anything other than the private Malloc bdev"
                )
            connected = True
            command(
                [
                    "nvme",
                    "connect",
                    "-t",
                    "tcp",
                    "-a",
                    "198.18.16.2",
                    "-s",
                    "44216",
                    "-n",
                    nqn,
                    "-i",
                    "1",
                    "-Q",
                    "32",
                    "-D",
                ]
            )
            devices = []
            for _ in range(50):
                devices = [
                    p.parent.parent.name
                    for p in Path("/sys/block").glob("nvme*n*/device/subsysnqn")
                    if p.read_text().strip() == nqn and "c" not in p.parent.parent.name
                ]
                if len(devices) == 1:
                    break
                time.sleep(0.1)
            if len(devices) != 1:
                raise RuntimeError(f"unexpected namespace discovery: {devices}")
            for block_size in ("4k", "128k"):
                output = args.results / f"fio-{cycle}-{block_size}.json"
                command(
                    [
                        "fio",
                        "--name=integrity",
                        "--filename=/dev/" + devices[0],
                        "--ioengine=libaio",
                        "--direct=1",
                        "--rw=write",
                        "--bs=" + block_size,
                        "--size=32m",
                        "--iodepth=8",
                        "--verify=crc32c",
                        "--do_verify=1",
                        "--verify_fatal=1",
                        "--output-format=json",
                        "--output=" + str(output),
                    ],
                    90,
                )
                jobs = json.loads(output.read_text())["jobs"]
                if not jobs or any(job["error"] for job in jobs):
                    raise RuntimeError("fio integrity check failed")
                if any(
                    job["read"]["io_bytes"] != 32 * 1024 * 1024
                    or job["write"]["io_bytes"] != 32 * 1024 * 1024
                    for job in jobs
                ):
                    raise RuntimeError(
                        "fio did not write and verify the full test range"
                    )
            stats = rpc("nvmf_get_stats")
            (args.results / f"nvmf-{cycle}.json").write_text(stats)
            (args.results / f"interface-{cycle}.txt").write_text(
                cli("show", "interface", interface)
            )
            (args.results / f"errors-{cycle}.txt").write_text(cli("show", "errors"))
            if args.rx_mode != "baseline":
                state = cli("show", "spdk")
                (args.results / f"rx-state-{cycle}.txt").write_text(state)
                matches = re.findall(
                    r"recv-next direct segments (\d+) bytes (\d+) releases (\d+); "
                    r"copied segments (\d+) bytes (\d+)",
                    state,
                )
                if not matches:
                    raise RuntimeError("missing RX counters")
                direct_bytes = sum(int(m[1]) for m in matches)
                copied_bytes = sum(int(m[4]) for m in matches)
                fifo_read_bytes = sum(
                    int(x) for x in re.findall(r"; rx calls \d+ bytes (\d+)", state)
                )
                fallbacks = sum(
                    int(x) for x in re.findall(r"limit-fallbacks (\d+)", state)
                )
                if args.rx_mode == "direct" and not direct_bytes:
                    raise RuntimeError("RX direct mode did not deliver direct bytes")
                if args.expect_mixed_rx and not copied_bytes:
                    raise RuntimeError("RX did not exercise FIFO-owned copied segments")
                # With direct RX disabled, the backend has no memory domain;
                # SPDK uses ordinary recv/readv rather than recv_next.
                if args.rx_mode == "copied" and (
                    direct_bytes or not (copied_bytes or fifo_read_bytes)
                ):
                    raise RuntimeError("copied control did not use copied socket reads")
                if args.rx_mode == "pressure" and (direct_bytes or not copied_bytes):
                    raise RuntimeError(
                        "copied/pressure control did not use the copied path"
                    )
                if args.rx_mode == "pressure" and not fallbacks:
                    raise RuntimeError(
                        "pressure control did not exercise the loan-limit fallback"
                    )
                report.setdefault("rx_counters", []).append(
                    {
                        "cycle": cycle,
                        "direct_bytes": direct_bytes,
                        "copied_bytes": copied_bytes,
                        "fifo_read_bytes": fifo_read_bytes,
                        "limit_fallbacks": fallbacks,
                    }
                )
            command(["nvme", "disconnect", "-n", nqn])
            connected = False
            if args.rx_mode != "baseline":
                for _ in range(80):
                    state = cli("show", "spdk")
                    refs = re.findall(
                        r"rx loans current refs (\d+) buffers (\d+)", state
                    )
                    if all(int(a) == int(b) == 0 for a, b in refs):
                        break
                    time.sleep(0.1)
                else:
                    raise RuntimeError("RX loans did not drain after disconnect")
                (args.results / f"rx-drained-{cycle}.txt").write_text(state)
            cli("spdk", "app", "stop")
            stopped = wait_state("SPDK app: stopped")
            if "SPDK threads: 0" not in stopped or "last rc: 0" not in stopped:
                raise RuntimeError("SPDK did not stop cleanly")
            (args.results / f"stopped-{cycle}.txt").write_text(stopped)
            (args.results / f"memory-stopped-{cycle}.txt").write_text(
                cli("show", "memory", "main-heap")
            )
            report["cycles"].append(
                {"cycle": cycle, "integrity_4k": "PASS", "integrity_128k": "PASS"}
            )
            print(
                f"cycle {cycle}: 4K/128K write/read CRC verification and disconnect/stop PASS",
                flush=True,
            )
    finally:
        if connected:
            try:
                command(["nvme", "disconnect", "-n", nqn])
            except Exception as error:
                report["cleanup_errors"].append(str(error))
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
            report["cleanup_errors"].append("VPP required SIGKILL")
        log.close()
        if (
            subprocess.run(["ip", "link", "show", tap], capture_output=True).returncode
            == 0
        ):
            report["cleanup_errors"].append("private TAP survived VPP exit")
        (args.results / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        if report["cleanup_errors"]:
            raise RuntimeError(report["cleanup_errors"])
    print(
        f"PASS: SPDK integration integrity/lifecycle, RX mode {args.rx_mode}",
        flush=True,
    )


if __name__ == "__main__":
    main()
