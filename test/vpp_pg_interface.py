import os
import socket
from socket import inet_pton, inet_ntop
import struct
import time
from traceback import format_exc, format_stack

from config import config
import scapy.compat
from scapy.utils import wrpcap, rdpcap, PcapReader
from scapy.plist import PacketList
from vpp_interface import VppInterface
from vpp_papi import VppEnum

from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet6 import IPv6, ICMPv6ND_NS, ICMPv6ND_NA,\
    ICMPv6NDOptSrcLLAddr, ICMPv6NDOptDstLLAddr, ICMPv6ND_RA, RouterAlert, \
    IPv6ExtHdrHopByHop
from util import ppp, ppc
from scapy.utils6 import in6_getnsma, in6_getnsmac, in6_ismaddr


class CaptureTimeoutError(Exception):
    """ Exception raised if capture or packet doesn't appear within timeout """
    pass


def is_ipv6_misc(p):
    """ Is packet one of uninteresting IPv6 broadcasts? """
    if p.haslayer(ICMPv6ND_RA):
        if in6_ismaddr(p[IPv6].dst):
            return True
    if p.haslayer(IPv6ExtHdrHopByHop):
        for o in p[IPv6ExtHdrHopByHop].options:
            if isinstance(o, RouterAlert):
                return True
    return False


class VppPGInterface(VppInterface):
    """
    VPP packet-generator interface
    """

    @property
    def pg_index(self):
        """packet-generator interface index assigned by VPP"""
        return self._pg_index

    @property
    def gso_enabled(self):
        """gso enabled on packet-generator interface"""
        if self._gso_enabled == 0:
            return "gso-disabled"
        return "gso-enabled"

    @property
    def gso_size(self):
        """gso size on packet-generator interface"""
        return self._gso_size

    @property
    def coalesce_is_enabled(self):
        """coalesce enabled on packet-generator interface"""
        if self._coalesce_enabled == 0:
            return "coalesce-disabled"
        return "coalesce-enabled"

    @property
    def out_path(self):
        """pcap file path - captured packets"""
        return self._out_path

    def get_in_path(self, worker):
        """ pcap file path - injected packets"""
        if worker is not None:
            return "%s/pg%u_wrk%u_in.pcap" % (self.test.tempdir, self.pg_index,
                                              worker)
        return "%s/pg%u_in.pcap" % (self.test.tempdir, self.pg_index)

    @property
    def capture_cli(self):
        """CLI string to start capture on this interface"""
        return self._capture_cli

    def get_cap_name(self, worker=None):
        """return capture name for this interface and given worker"""
        if worker is not None:
            return self._cap_name + "-worker%d" % worker
        return self._cap_name

    def get_input_cli(self, nb_replays=None, worker=None):
        """return CLI string to load the injected packets"""
        input_cli = "packet-generator new pcap %s source pg%u name %s" % (
            self.get_in_path(worker), self.pg_index, self.get_cap_name(worker))
        if nb_replays is not None:
            return "%s limit %d" % (input_cli, nb_replays)
        if worker is not None:
            return "%s worker %d" % (input_cli, worker)
        return input_cli

    @property
    def in_history_counter(self):
        """Self-incrementing counter used when renaming old pcap files"""
        v = self._in_history_counter
        self._in_history_counter += 1
        return v

    @property
    def out_history_counter(self):
        """Self-incrementing counter used when renaming old pcap files"""
        v = self._out_history_counter
        self._out_history_counter += 1
        return v

    def __init__(self, test, pg_index, gso, gso_size, mode):
        """ Create VPP packet-generator interface """
        super().__init__(test)

        r = test.vapi.pg_create_interface_v2(pg_index, gso, gso_size, mode)
        self.set_sw_if_index(r.sw_if_index)

        self._in_history_counter = 0
        self._out_history_counter = 0
        self._out_assert_counter = 0
        self._pg_index = pg_index
        self._gso_enabled = gso
        self._gso_size = gso_size
        self._coalesce_enabled = 0
        self._out_file = "pg%u_out.pcap" % self.pg_index
        self._out_path = self.test.tempdir + "/" + self._out_file
        self._capture_cli = "packet-generator capture pg%u pcap %s" % (
            self.pg_index, self.out_path)
        self._cap_name = "pcap%u-sw_if_index-%s" % (
            self.pg_index, self.sw_if_index)

    def handle_old_pcap_file(self, path, counter):
        filename = os.path.basename(path)

        if not config.keep_pcaps:
            try:
                self.test.logger.debug(f"Removing {path}")
                os.remove(path)
            except OSError:
                self.test.logger.debug(f"OSError: Could not remove {path}")
            return

        # keep
        try:

            if os.path.isfile(path):
                name = "%s/history.[timestamp:%f].[%s-counter:%04d].%s" % \
                    (self.test.tempdir,
                     time.time(),
                     self.name,
                     counter,
                     filename)
                self.test.logger.debug("Renaming %s->%s" % (path, name))
                os.rename(path, name)
        except OSError:
            self.test.logger.debug("OSError: Could not rename %s %s" %
                                   (path, filename))

    def enable_capture(self):
        """ Enable capture on this packet-generator interface
            of at most n packets.
            If n < 0, this is no limit
        """
        # disable the capture to flush the capture
        self.disable_capture()
        self.handle_old_pcap_file(self.out_path, self.out_history_counter)
        # FIXME this should be an API, but no such exists atm
        self.test.vapi.cli(self.capture_cli)
        self._pcap_reader = None

    def disable_capture(self):
        self.test.vapi.cli("%s disable" % self.capture_cli)

    def coalesce_enable(self):
        """ Enable packet coalesce on this packet-generator interface"""
        self._coalesce_enabled = 1
        self.test.vapi.pg_interface_enable_disable_coalesce(self.sw_if_index,
                                                            1)

    def coalesce_disable(self):
        """ Disable packet coalesce on this packet-generator interface"""
        self._coalesce_enabled = 0
        self.test.vapi.pg_interface_enable_disable_coalesce(self.sw_if_index,
                                                            0)

    def add_stream(self, pkts, nb_replays=None, worker=None):
        """
        Add a stream of packets to this packet-generator

        :param pkts: iterable packets

        """
        wrpcap(self.get_in_path(worker), pkts)
        self.test.register_pcap(self, worker)
        # FIXME this should be an API, but no such exists atm
        self.test.vapi.cli(self.get_input_cli(nb_replays, worker))

    def generate_debug_aid(self, kind):
        """ Create a hardlink to the out file with a counter and a file
        containing stack trace to ease debugging in case of multiple capture
        files present. """
        self.test.logger.debug("Generating debug aid for %s on %s" %
                               (kind, self._name))
        link_path, stack_path = ["%s/debug_%s_%s_%s.%s" %
                                 (self.test.tempdir, self._name,
                                  self._out_assert_counter, kind, suffix)
                                 for suffix in ["pcap", "stack"]
                                 ]
        os.link(self.out_path, link_path)
        with open(stack_path, "w") as f:
            f.writelines(format_stack())
        self._out_assert_counter += 1

    def _get_capture(self, timeout, filter_out_fn=is_ipv6_misc):
        """ Helper method to get capture and filter it """
        try:
            if not self.wait_for_capture_file(timeout):
                return None
            output = rdpcap(self.out_path)
            self.test.logger.debug("Capture has %s packets" % len(output.res))
        except:
            self.test.logger.debug("Exception in scapy.rdpcap (%s): %s" %
                                   (self.out_path, format_exc()))
            return None
        before = len(output.res)
        if filter_out_fn:
            output.res = [p for p in output.res if not filter_out_fn(p)]
        removed = before - len(output.res)
        if removed:
            self.test.logger.debug(
                "Filtered out %s packets from capture (returning %s)" %
                (removed, len(output.res)))
        return output

    def get_capture(self, expected_count=None, remark=None, timeout=1,
                    filter_out_fn=is_ipv6_misc):
        """ Get captured packets

        :param expected_count: expected number of packets to capture, if None,
                               then self.test.packet_count_for_dst_pg_idx is
                               used to lookup the expected count
        :param remark: remark printed into debug logs
        :param timeout: how long to wait for packets
        :param filter_out_fn: filter applied to each packet, packets for which
                              the filter returns True are removed from capture
        :returns: iterable packets
        """
        remaining_time = timeout
        capture = None
        name = self.name if remark is None else "%s (%s)" % (self.name, remark)
        based_on = "based on provided argument"
        if expected_count is None:
            expected_count = \
                self.test.get_packet_count_for_if_idx(self.sw_if_index)
            based_on = "based on stored packet_infos"
            if expected_count == 0:
                raise Exception(
                    "Internal error, expected packet count for %s is 0!" %
                    name)
        self.test.logger.debug("Expecting to capture %s (%s) packets on %s" % (
            expected_count, based_on, name))
        while remaining_time > 0:
            before = time.time()
            capture = self._get_capture(remaining_time, filter_out_fn)
            elapsed_time = time.time() - before
            if capture:
                if len(capture.res) == expected_count:
                    # bingo, got the packets we expected
                    return capture
                elif len(capture.res) > expected_count:
                    self.test.logger.error(
                        ppc("Unexpected packets captured:", capture))
                    break
                else:
                    self.test.logger.debug("Partial capture containing %s "
                                           "packets doesn't match expected "
                                           "count %s (yet?)" %
                                           (len(capture.res), expected_count))
            elif expected_count == 0:
                # bingo, got None as we expected - return empty capture
                return PacketList()
            remaining_time -= elapsed_time
        if capture:
            self.generate_debug_aid("count-mismatch")
            raise Exception("Captured packets mismatch, captured %s packets, "
                            "expected %s packets on %s" %
                            (len(capture.res), expected_count, name))
        else:
            raise Exception("No packets captured on %s" % name)

    def assert_nothing_captured(self, remark=None, filter_out_fn=is_ipv6_misc):
        """ Assert that nothing unfiltered was captured on interface

        :param remark: remark printed into debug logs
        :param filter_out_fn: filter applied to each packet, packets for which
                              the filter returns True are removed from capture
        """
        if os.path.isfile(self.out_path):
            try:
                capture = self.get_capture(
                    0, remark=remark, filter_out_fn=filter_out_fn)
                if not capture or len(capture.res) == 0:
                    # junk filtered out, we're good
                    return
            except:
                pass
            self.generate_debug_aid("empty-assert")
            if remark:
                raise AssertionError(
                    "Non-empty capture file present for interface %s (%s)" %
                    (self.name, remark))
            else:
                raise AssertionError("Capture file present for interface %s" %
                                     self.name)

    def wait_for_pg_stop(self):
        # wait till packet-generator is stopped
        # "show packet-generator" while it is still running gives this:
        # Name               Enabled        Count     Parameters
        # pcap0-sw_if_inde     Yes           64       limit 64, ...
        #
        # also have a 5-minute timeout just in case things go terribly wrong...
        deadline = time.time() + 300
        while self.test.vapi.cli('show packet-generator').find("Yes") != -1:
            self._test.sleep(0.01)  # yield
            if time.time() > deadline:
                self.test.logger.debug("Timeout waiting for pg to stop")
                break

    def wait_for_capture_file(self, timeout=1):
        """
        Wait until pcap capture file appears

        :param timeout: How long to wait for the packet (default 1s)

        :returns: True/False if the file is present or appears within timeout
        """
        self.wait_for_pg_stop()
        deadline = time.time() + timeout
        if not os.path.isfile(self.out_path):
            self.test.logger.debug("Waiting for capture file %s to appear, "
                                   "timeout is %ss" % (self.out_path, timeout))
        else:
            self.test.logger.debug("Capture file %s already exists" %
                                   self.out_path)
            return True
        while time.time() < deadline:
            if os.path.isfile(self.out_path):
                break
            self._test.sleep(0)  # yield
        if os.path.isfile(self.out_path):
            self.test.logger.debug("Capture file appeared after %fs" %
                                   (time.time() - (deadline - timeout)))
        else:
            self.test.logger.debug("Timeout - capture file still nowhere")
            return False
        return True

    def verify_enough_packet_data_in_pcap(self):
        """
        Check if enough data is available in file handled by internal pcap
        reader so that a whole packet can be read.

        :returns: True if enough data present, else False
        """
        orig_pos = self._pcap_reader.f.tell()  # save file position
        enough_data = False
        # read packet header from pcap
        packet_header_size = 16
        caplen = None
        end_pos = None
        hdr = self._pcap_reader.f.read(packet_header_size)
        if len(hdr) == packet_header_size:
            # parse the capture length - caplen
            sec, usec, caplen, wirelen = struct.unpack(
                self._pcap_reader.endian + "IIII", hdr)
            self._pcap_reader.f.seek(0, 2)  # seek to end of file
            end_pos = self._pcap_reader.f.tell()  # get position at end
            if end_pos >= orig_pos + len(hdr) + caplen:
                enough_data = True  # yay, we have enough data
        self._pcap_reader.f.seek(orig_pos, 0)  # restore original position
        return enough_data

    def wait_for_packet(self, timeout, filter_out_fn=is_ipv6_misc):
        """
        Wait for next packet captured with a timeout

        :param timeout: How long to wait for the packet

        :returns: Captured packet if no packet arrived within timeout
        :raises Exception: if no packet arrives within timeout
        """
        deadline = time.time() + timeout
        if self._pcap_reader is None:
            if not self.wait_for_capture_file(timeout):
                raise CaptureTimeoutError("Capture file %s did not appear "
                                          "within timeout" % self.out_path)
            while time.time() < deadline:
                try:
                    self._pcap_reader = PcapReader(self.out_path)
                    break
                except:
                    self.test.logger.debug(
                        "Exception in scapy.PcapReader(%s): %s" %
                        (self.out_path, format_exc()))
        if not self._pcap_reader:
            raise CaptureTimeoutError("Capture file %s did not appear within "
                                      "timeout" % self.out_path)

        poll = False
        if timeout > 0:
            self.test.logger.debug("Waiting for packet")
        else:
            poll = True
            self.test.logger.debug("Polling for packet")
        while time.time() < deadline or poll:
            if not self.verify_enough_packet_data_in_pcap():
                self._test.sleep(0)  # yield
                poll = False
                continue
            p = self._pcap_reader.recv()
            if p is not None:
                if filter_out_fn is not None and filter_out_fn(p):
                    self.test.logger.debug(
                        "Packet received after %ss was filtered out" %
                        (time.time() - (deadline - timeout)))
                else:
                    self.test.logger.debug(
                        "Packet received after %fs" %
                        (time.time() - (deadline - timeout)))
                    return p
            self._test.sleep(0)  # yield
            poll = False
        self.test.logger.debug("Timeout - no packets received")
        raise CaptureTimeoutError("Packet didn't arrive within timeout")

    def create_arp_req(self):
        """Create ARP request applicable for this interface"""
        return (Ether(dst="ff:ff:ff:ff:ff:ff", src=self.remote_mac) /
                ARP(op=ARP.who_has, pdst=self.local_ip4,
                    psrc=self.remote_ip4, hwsrc=self.remote_mac))

    def create_ndp_req(self, addr=None):
        """Create NDP - NS applicable for this interface"""
        if not addr:
            addr = self.local_ip6
        nsma = in6_getnsma(inet_pton(socket.AF_INET6, addr))
        d = inet_ntop(socket.AF_INET6, nsma)

        return (Ether(dst=in6_getnsmac(nsma)) /
                IPv6(dst=d, src=self.remote_ip6) /
                ICMPv6ND_NS(tgt=addr) /
                ICMPv6NDOptSrcLLAddr(lladdr=self.remote_mac))

    def resolve_arp(self, pg_interface=None):
        """Resolve ARP using provided packet-generator interface

        :param pg_interface: interface used to resolve, if None then this
            interface is used

        """
        if pg_interface is None:
            pg_interface = self
        self.test.logger.info("Sending ARP request for %s on port %s" %
                              (self.local_ip4, pg_interface.name))
        arp_req = self.create_arp_req()
        pg_interface.add_stream(arp_req)
        pg_interface.enable_capture()
        self.test.pg_start()
        self.test.logger.info(self.test.vapi.cli("show trace"))
        try:
            captured_packet = pg_interface.wait_for_packet(1)
        except:
            self.test.logger.info("No ARP received on port %s" %
                                  pg_interface.name)
            return
        arp_reply = captured_packet.copy()  # keep original for exception
        try:
            if arp_reply[ARP].op == ARP.is_at:
                self.test.logger.info("VPP %s MAC address is %s " %
                                      (self.name, arp_reply[ARP].hwsrc))
                self._local_mac = arp_reply[ARP].hwsrc
            else:
                self.test.logger.info("No ARP received on port %s" %
                                      pg_interface.name)
        except:
            self.test.logger.error(
                ppp("Unexpected response to ARP request:", captured_packet))
            raise

    def resolve_ndp(self, pg_interface=None, timeout=1, link_layer=False):
        """Resolve NDP using provided packet-generator interface

        :param pg_interface: interface used to resolve, if None then this
            interface is used
        :param timeout: how long to wait for response before giving up
        :param link_layer: resolve for global address if False (default)
            or for link-layer address if True

        """
        if pg_interface is None:
            pg_interface = self
        addr = self.local_ip6_ll if link_layer else self.local_ip6
        self.test.logger.info("Sending NDP request for %s on port %s" %
                              (addr, pg_interface.name))
        ndp_req = self.create_ndp_req(addr)
        pg_interface.add_stream(ndp_req)
        pg_interface.enable_capture()
        self.test.pg_start()
        now = time.time()
        deadline = now + timeout
        # Enabling IPv6 on an interface can generate more than the
        # ND reply we are looking for (namely MLD). So loop through
        # the replies to look for want we want.
        while now < deadline:
            try:
                captured_packet = pg_interface.wait_for_packet(
                    deadline - now, filter_out_fn=None)
            except:
                self.test.logger.error(
                    "Timeout while waiting for NDP response")
                raise
            ndp_reply = captured_packet.copy()  # keep original for exception
            try:
                ndp_na = ndp_reply[ICMPv6ND_NA]
                opt = ndp_na[ICMPv6NDOptDstLLAddr]
                self.test.logger.info("VPP %s MAC address is %s " %
                                      (self.name, opt.lladdr))
                self._local_mac = opt.lladdr
                self.test.logger.debug(self.test.vapi.cli("show trace"))
                # we now have the MAC we've been after
                return
            except:
                self.test.logger.info(
                    ppp("Unexpected response to NDP request:",
                        captured_packet))
            now = time.time()

        self.test.logger.debug(self.test.vapi.cli("show trace"))
        raise Exception("Timeout while waiting for NDP response")
