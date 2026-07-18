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
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("run as root in an isolated Linux test environment")
    if args.cycles < 1 or args.main_core == args.worker:
        parser.error("positive cycle count and distinct main/worker CPUs required")
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
            "512m",
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
            "session",
            "{",
            "enable",
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
    report = {"nqn": nqn, "tap": tap, "cycles": [], "cleanup_errors": []}

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
        fifo = cli("test", "svm", "fifo", "all")
        if "SUCCESS" not in fifo:
            raise RuntimeError("FIFO test failed")
        (args.results / "fifo-all.txt").write_text(fifo)
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
        cli("set", "interface", "state", interface, "up")
        command(["ip", "link", "set", tap, "up"])
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
            rpc("bdev_malloc_create", "64", "4096", "-b", "IntegrationMalloc")
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
            command(["nvme", "disconnect", "-n", nqn])
            connected = False
            cli("spdk", "app", "stop")
            stopped = wait_state("SPDK app: stopped")
            if "SPDK threads: 0" not in stopped or "last rc: 0" not in stopped:
                raise RuntimeError("SPDK did not stop cleanly")
            (args.results / f"stopped-{cycle}.txt").write_text(stopped)
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
    print("PASS: SPDK integration with unpatched upstream and copied RX/TX", flush=True)


if __name__ == "__main__":
    main()
