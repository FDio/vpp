import os
import subprocess
import time

from scapy.plist import PacketList
from scapy.utils import rdpcap, wrpcap

from util import UnexpectedPacketError
from vpp_pg_interface import CaptureMismatchError, CaptureTimeoutError


class HostInterface:
    """Wraps a Linux host interface (in a netns) with a pg_-style API
    for packet capture and injection using scapy internally.

    All temporary pcap files are managed internally and cleaned up after use.
    """

    @property
    def test(self):
        return self._test

    @property
    def ifname(self):
        return self._ifname

    def __str__(self):
        return self._ifname

    def __init__(self, test, ns_name, ifname):
        self._test = test
        self._ns = ns_name
        self._ifname = ifname
        self._sniffer_proc = None
        self._sniffer_pcap = ""
        self._sniffer_ready = ""
        self._stream_pkts = []
        self._capture_active = False

    def _ip_netns_cmd(self, script, *args):
        return ["ip", "netns", "exec", self._ns, "python3", "-c", script, *args]

    def _remove_file(self, path):
        if path and os.path.isfile(path):
            try:
                os.remove(path)
            except OSError:
                pass

    def _read_pcap(self, path, filter_out_fn=None):
        try:
            pkts = rdpcap(path)
        except Exception:
            pkts = PacketList()
        if filter_out_fn:
            pkts = PacketList([p for p in pkts if not filter_out_fn(p)])
        return pkts

    def enable_capture(self, timeout=10):
        """Start the sniffer on the host interface.

        Blocks until the sniffer is ready or *timeout* seconds elapse.
        If a capture is already active it is restarted (disable + enable).
        """
        self.disable_capture()
        self._sniffer_pcap = "%s/%s_sniffer_%s.pcap" % (
            self.test.tempdir,
            self._ifname,
            id(self),
        )
        self._sniffer_ready = "%s/%s_ready_%s" % (
            self.test.tempdir,
            self._ifname,
            id(self),
        )
        script = (
            "from scapy.all import *; "
            "sniff(iface='%s', store=0, "
            "prn=lambda p: wrpcap('%s', p, append=True), "
            "started_callback=lambda: open('%s', 'w').close(), "
            "timeout=%d)"
        ) % (self._ifname, self._sniffer_pcap, self._sniffer_ready, timeout)
        self._sniffer_proc = subprocess.Popen(
            self._ip_netns_cmd(script),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid,
        )
        self._capture_active = True
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._sniffer_proc.poll() is not None:
                self.disable_capture()
                raise RuntimeError(
                    "Sniffer on %s exited prematurely (rc=%d)"
                    % (self._ifname, self._sniffer_proc.returncode)
                )
            if os.path.isfile(self._sniffer_ready):
                break
            time.sleep(0.05)
        if not os.path.isfile(self._sniffer_ready):
            self.disable_capture()
            raise RuntimeError(
                "Sniffer on %s did not start within %d seconds"
                % (self._ifname, timeout)
            )

    def disable_capture(self):
        """Kill the sniffer process and clean up temporary files."""
        self._capture_active = False
        if self._sniffer_proc is not None:
            try:
                self._sniffer_proc.terminate()
                self._sniffer_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._sniffer_proc.kill()
                self._sniffer_proc.wait()
            except ProcessLookupError:
                pass
            self._sniffer_proc = None
        self._remove_file(self._sniffer_ready)
        self._remove_file(self._sniffer_pcap)
        self._sniffer_pcap = ""
        self._sniffer_ready = ""

    def get_capture(
        self, expected_count=None, remark=None, timeout=2, filter_out_fn=None
    ):
        """Get captured packets.

        Stops the sniffer, reads the internal pcap, and returns packets.

        :param expected_count: expected number of packets; raises if the
                               actual count differs
        :param remark: optional label for debug/error messages
        :param timeout: how long to wait for packets
        :param filter_out_fn: filter applied to each packet; packets for
                              which the filter returns True are removed
        :returns: filtered PacketList with exactly *expected_count* packets
        :raises CaptureTimeoutError: if no (or too few) packets arrive
        :raises CaptureMismatchError: if more packets arrive than expected
        """
        name = "%s (%s)" % (self._ifname, remark) if remark else self._ifname
        pcap = self._sniffer_pcap
        if not pcap:
            if expected_count == 0:
                return PacketList()
            raise CaptureTimeoutError("No capture active on %s" % name)
        deadline = time.time() + timeout
        last_pkts = PacketList()
        while time.time() < deadline:
            if os.path.isfile(pcap):
                last_pkts = self._read_pcap(pcap, filter_out_fn)
                if expected_count is None or len(last_pkts) == expected_count:
                    self.disable_capture()
                    return last_pkts
                if len(last_pkts) > expected_count:
                    break
            time.sleep(0.05)
        self.disable_capture()
        if expected_count is None:
            return last_pkts
        if len(last_pkts) > 0 and expected_count == 0:
            raise UnexpectedPacketError(
                last_pkts[0],
                "Unexpected packets captured on %s" % name,
            )
        if len(last_pkts) > expected_count:
            raise CaptureMismatchError(
                "Captured %d packets, expected %d on %s"
                % (len(last_pkts), expected_count, name)
            )
        raise CaptureTimeoutError(
            "Captured %d packets, expected %d on %s (timeout %ss)"
            % (len(last_pkts), expected_count, name, timeout)
        )

    def add_stream(self, pkts):
        if not isinstance(pkts, list):
            pkts = [pkts]
        self._stream_pkts.extend(pkts)

    def start(self):
        """Inject queued stream packets into the host interface."""
        if not self._stream_pkts:
            return
        in_pcap = "%s/%s_inject_%s.pcap" % (self.test.tempdir, self._ifname, id(self))
        wrpcap(in_pcap, self._stream_pkts)
        self._stream_pkts = []
        script = (
            "import sys; from scapy.all import *; "
            "sendp(rdpcap(sys.argv[1]), iface='%s')"
        ) % self._ifname
        subprocess.run(
            self._ip_netns_cmd(script, in_pcap),
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def wait_for_packet(self, filter_fn=None, timeout=2):
        """Wait for and return the first packet matching *filter_fn*.

        :raises CaptureTimeoutError: if no packet arrives within timeout
        """
        if not self._sniffer_pcap:
            raise CaptureTimeoutError("No capture active on %s" % self._ifname)
        deadline = time.time() + timeout
        while time.time() < deadline:
            if os.path.isfile(self._sniffer_pcap):
                pkts = self._read_pcap(self._sniffer_pcap)
                for p in pkts:
                    if filter_fn is None or filter_fn(p):
                        return p
            time.sleep(0.05)
        raise CaptureTimeoutError(
            "Packet didn't arrive on %s within %ds" % (self._ifname, timeout)
        )
