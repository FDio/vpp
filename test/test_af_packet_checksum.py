# SPDX-License-Identifier: Apache-2.0

from copy import deepcopy
import json
import re
import select
import subprocess
import sys
import unittest

from config import config
from framework import VppTestCase
from vm_test_config import test_config
from vm_vpp_interfaces import TestVPPInterfacesQemu

SERVER = r"""
import hashlib, json, socket, sys
family = socket.AF_INET if sys.argv[1] == '4' else socket.AF_INET6
with socket.socket(family, socket.SOCK_STREAM) as listener:
    listener.settimeout(8)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((sys.argv[2], int(sys.argv[3])))
    listener.listen(1)
    print('ready', flush=True)
    with listener.accept()[0] as connection:
        connection.settimeout(8)
        digest, count = hashlib.sha256(), 0
        while True:
            data = connection.recv(65536)
            if not data:
                break
            count += len(data)
            digest.update(data)
        result = {'bytes': count, 'sha256': digest.hexdigest()}
        connection.sendall(json.dumps(result).encode())
        connection.shutdown(socket.SHUT_WR)
        print(json.dumps(result), flush=True)
"""


CLIENT = r"""
import hashlib, json, socket, sys
family = socket.AF_INET if sys.argv[1] == '4' else socket.AF_INET6
payload = bytes(range(256)) * 4096 + b'last partial block'
with socket.socket(family, socket.SOCK_STREAM) as connection:
    connection.settimeout(8)
    connection.connect((sys.argv[2], int(sys.argv[3])))
    connection.sendall(payload)
    connection.shutdown(socket.SHUT_WR)
    reply = bytearray()
    while True:
        data = connection.recv(4096)
        if not data:
            break
        reply.extend(data)
result = json.loads(reply)
assert result == {'bytes': len(payload), 'sha256': hashlib.sha256(payload).hexdigest()}, result
print(json.dumps(result))
"""


@unittest.skipIf(config.skip_netns_tests, "netns not available or disabled from cli")
class TestAfPacketChecksum(TestVPPInterfacesQemu, VppTestCase):
    """AF_PACKET checksum offload through software GSO and TX fallback."""

    vpp_worker_count = 1

    def tearDown(self):
        try:
            TestVPPInterfacesQemu.tearDown(self)
        finally:
            VppTestCase.tearDown(self)

    def command(self, args, **kwargs):
        return subprocess.run(
            args, check=True, capture_output=True, text=True, timeout=12, **kwargs
        )

    def create_af_packet(self, version, host_if_name, enable_gso=0):
        client = host_if_name == self.iprf_client_host_interface_on_vpp
        namespace = self.client_namespace if client else self.server_namespace
        endpoint = (
            self.iprf_client_host_interface_on_linux
            if client
            else self.iprf_server_host_interface_on_linux
        )
        gso = "on" if client and self.source_gso else "off"
        tx_checksum = client or self.tx_checksum
        tx = "on" if tx_checksum else "off"
        for namespace_name, interface in [("", host_if_name), (namespace, endpoint)]:
            prefix = ["ip", "netns", "exec", namespace_name] if namespace_name else []
            self.command(
                prefix
                + [
                    "ethtool",
                    "-K",
                    interface,
                    "rx",
                    "on",
                    "tx",
                    tx,
                    "sg",
                    "on",
                    "tso",
                    gso,
                    "gso",
                    gso,
                    "gro",
                    "off",
                    "lro",
                    "off",
                ]
            )
            actual = self.command(prefix + ["ethtool", "-k", interface]).stdout
            features = dict(re.findall(r"^([^\s:]+): (on|off)", actual, re.M))
            for feature in ["rx-checksumming", "scatter-gather"]:
                self.assertEqual(features[feature], "on")
            self.assertEqual(features["tx-checksumming"], tx)
            for feature in ["tcp-segmentation-offload", "generic-segmentation-offload"]:
                self.assertEqual(features[feature], gso)
            self.assertEqual(features["generic-receive-offload"], "off")
        reply = self.vapi.af_packet_create_v3(
            host_if_name=host_if_name,
            use_random_hw_addr=True,
            flags=(3 if tx_checksum else 1) | (8 if version == 2 else 0),
            mode=1,
            num_rx_queues=1,
            num_tx_queues=2,
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=reply.sw_if_index, enable_disable=1
        )
        self.vapi.sw_interface_set_flags(sw_if_index=reply.sw_if_index, flags=1)
        hardware = self.vapi.cli(f"show hardware-interfaces host-{host_if_name}")
        self.logger.debug(hardware)
        self.assertEqual("cksum-gso-enabled" in hardware, tx_checksum)
        return reply.sw_if_index

    def checksum_counters(self):
        result = {}
        for role, namespace in [
            ("client", self.client_namespace),
            ("server", self.server_namespace),
        ]:
            values = {}
            for name in ["snmp", "netstat"]:
                lines = self.command(
                    ["ip", "netns", "exec", namespace, "cat", "/proc/net/" + name]
                ).stdout.splitlines()
                self.assertEqual(len(lines) % 2, 0)
                for index in range(0, len(lines), 2):
                    keys, raw = lines[index].split(), lines[index + 1].split()
                    self.assertEqual(keys[0], raw[0])
                    self.assertEqual(len(keys), len(raw))
                    values.update(
                        {
                            keys[0] + key: int(value)
                            for key, value in zip(keys[1:], raw[1:])
                        }
                    )
            if self.ip_version == 6:
                raw = self.command(
                    ["ip", "netns", "exec", namespace, "cat", "/proc/net/snmp6"]
                ).stdout
                values.update(
                    {
                        key: int(value)
                        for key, value in (line.split() for line in raw.splitlines())
                    }
                )
            keys = [
                "Tcp:InErrs",
                "Ip:InHdrErrors" if self.ip_version == 4 else "Ip6InHdrErrors",
            ]
            keys += [
                key
                for key in ["IpExt:InCsumErrors", "Tcp:InCsumErrors"]
                if key in values
            ]
            result[role] = {key: values[key] for key in keys}
        return result

    def run_checksum_case(self, version, ip_version, source_gso, tx_checksum):
        self.source_gso, self.ip_version = source_gso, ip_version
        self.tx_checksum = tx_checksum
        topology = deepcopy(
            next(row for row in test_config["tests"] if row["id"] == 15)
        )
        topology["client_if_version"] = topology["server_if_version"] = version
        # Zero makes the topology helper disable Linux checksum offloads.
        topology["client_if_gso"] = topology["server_if_gso"] = 1
        self.setUpTestToplogy(topology, ip_version)
        self.assertTrue(
            self.set_interfaces_mtu(
                mtu=1500,
                ip_version=ip_version,
                vpp_interfaces=self.vpp_interfaces,
                linux_interfaces=self.linux_interfaces,
            )
        )
        self.vapi.cli("clear trace")
        self.vapi.cli("trace add af-packet-input 128")
        helpers = self.helper_affinity()
        self.assertGreaterEqual(len(helpers), 2)
        address = (
            self.server_ip4_address if ip_version == 4 else self.server_ip6_address
        )
        arguments = [str(ip_version), address, "5055"]
        server = subprocess.Popen(
            [
                "ip",
                "netns",
                "exec",
                self.server_namespace,
                "taskset",
                "-c",
                str(helpers[-1]),
                sys.executable,
                "-u",
                "-c",
                SERVER,
                *arguments,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            self.assertTrue(
                select.select([server.stdout], [], [], 5)[0], "Server not ready"
            )
            self.assertEqual(server.stdout.readline().strip(), "ready")
            before = self.checksum_counters()
            completed = self.command(
                [
                    "ip",
                    "netns",
                    "exec",
                    self.client_namespace,
                    "taskset",
                    "-c",
                    str(helpers[0]),
                    sys.executable,
                    "-c",
                    CLIENT,
                    *arguments,
                ]
            )
            stdout, stderr = server.communicate(timeout=10)
            self.assertEqual(server.returncode, 0, stderr)
            self.assertEqual(json.loads(completed.stdout), json.loads(stdout))
            after = self.checksum_counters()
            for role, counters in before.items():
                for key, value in counters.items():
                    self.assertEqual(after[role][key] - value, 0, (role, key))
            trace = self.vapi.cli("show trace max 128")
            records = re.findall(
                r"(?ms)^\d+:\d+:\d+:\d+: af-packet-input\n(.*?)"
                r"(?=^\d+:\d+:\d+:\d+: |\Z)",
                trace,
            )
            headers = [
                (int(flags, 16), int(kind, 16) & 0x7F)
                for record in records
                for flags, kind in re.findall(
                    r"flags 0x([0-9a-fA-F]+) gso_type 0x([0-9a-fA-F]+)", record
                )
            ]
            expected_type = (1 if ip_version == 4 else 4) if source_gso else 0
            self.assertTrue(
                any(flags & 1 and kind == expected_type for flags, kind in headers),
                "Expected NEEDS_CSUM TCP packet did not reach AF_PACKET",
            )
            if source_gso:
                self.assertIn(f"gso-ip{ip_version}", trace)
            else:
                self.assertEqual({kind for _, kind in headers}, {0})
        finally:
            if server.poll() is None:
                server.kill()
                server.communicate(timeout=5)


def make_case(version, ip_version, source_gso, tx_checksum):
    def case(self):
        self.run_checksum_case(version, ip_version, source_gso, tx_checksum)

    case.__doc__ = (
        f"AF_PACKET v{version} IPv{ip_version} TCP GSO {int(source_gso)} "
        f"TX checksum offload {int(tx_checksum)}"
    )
    return case


for version in [2, 3]:
    for ip_version in [4, 6]:
        for source_gso in [False, True]:
            for tx_checksum in [True, False]:
                suffix = "" if tx_checksum else "_tx_off"
                setattr(
                    TestAfPacketChecksum,
                    f"test_v{version}_ip{ip_version}_gso{int(source_gso)}{suffix}",
                    make_case(version, ip_version, source_gso, tx_checksum),
                )
