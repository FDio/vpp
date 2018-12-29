import os
import time
import socket
import struct
from traceback import format_exc, format_stack
from scapy.error import Scapy_Exception
from scapy.utils import wrpcap, rdpcap, PcapReader
from scapy.plist import PacketList
from vpp_interface import VppInterface
from custom_exceptions import CaptureError, CaptureTimeoutError, \
    CaptureNoPacketsError, CaptureMismatchError, CaptureUnexpectedPacketError
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet6 import IPv6, ICMPv6ND_NS, ICMPv6ND_NA, \
    ICMPv6NDOptSrcLLAddr, ICMPv6NDOptDstLLAddr, ICMPv6ND_RA, RouterAlert, \
    IPv6ExtHdrHopByHop
from util import ppp, ppc
from scapy.utils6 import in6_getnsma, in6_getnsmac, in6_ismaddr
from scapy.utils import inet_pton, inet_ntop


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
    def out_path(self):
        """pcap file path - captured packets"""
        return self._out_path

    @property
    def in_path(self):
        """ pcap file path - injected packets"""
        return self._in_path

    @property
    def capture_cli(self):
        """CLI string to start capture on this interface"""
        return self._capture_cli

    @property
    def cap_name(self):
        """capture name for this interface"""
        return self._cap_name

    @property
    def input_cli(self):
        """CLI string to load the injected packets"""
        return self._input_cli

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

    def __init__(self, test, pg_index):
        """ Create VPP packet-generator interface """
        super(VppPGInterface, self).__init__(test)

        r = test.vapi.pg_create_interface(pg_index)
        self.set_sw_if_index(r.sw_if_index)

        self._in_history_counter = 0
        self._out_history_counter = 0
        self._out_assert_counter = 0
        self._pg_index = pg_index
        self._out_file = "pg%u_out.pcap" % self.pg_index
        self._out_path = self._test.tempdir + "/" + self._out_file
        self._in_file = "pg%u_in.pcap" % self.pg_index
        self._in_path = self._test.tempdir + "/" + self._in_file
        self._capture_cli = "packet-generator capture pg%u pcap %s" % (
            self.pg_index, self.out_path)
        self._cap_name = "pcap%u" % self.sw_if_index
        self._input_cli = \
            "packet-generator new pcap %s source pg%u name %s" % (
                self.in_path, self.pg_index, self.cap_name)

    def enable_capture(self):
        """ Enable capture on this packet-generator interface
        :param self.out_path
        :param self._test.logger
        :param self._test.tempdir
        :param self.name
        :param self.out_history_counter
        :param self._out_file
        :raises OSError
        """
        try:
            _is_valid_path = os.path.isfile(self.out_path)
        except OSError as e:
            self._test.logger.debug("Invalid path %s" %
                                    self.in_path)
            raise
        else:
            if _is_valid_path:
                name = "%s/history.[timestamp:%f].[%s-counter:%04d].%s" % \
                       (self._test.tempdir,
                        time.time(),
                        self.name,
                        self.out_history_counter,
                        self._out_file)
                self._test.logger.debug("Renaming %s->%s" %
                                        (self.out_path, name))
                try:
                    os.rename(self.out_path, name)
                except OSError as e:
                    self._test.logger.debug("Unable to rename %s->%s" %
                                            (self.in_path, name))
        finally:
            # FIXME this should be an API, but no such exists atm
            self._test.vapi.cli(self.capture_cli)
            self._pcap_reader = None

    def add_stream(self, pkts):
        """
        Add a stream of packets to this packet-generator

        :param pkts: iterable packets

        """
        try:
            _is_valid_path = os.path.isfile(self.in_path)
        except OSError as e:
            self._test.logger.debug("Invalid path %s" %
                                    self.in_path)
            raise
        else:
            if _is_valid_path:
                name = "%s/history.[timestamp:%f].[%s-counter:%04d].%s" % \
                       (self._test.tempdir,
                        time.time(),
                        self.name,
                        self.in_history_counter,
                        self._in_file)
                self._test.logger.debug("Renaming %s->%s" %
                                        (self.in_path, name))
                try:
                    os.rename(self.in_path, name)
                except OSError:
                    self._test.logger.debug("Unable to rename %s->%s" %
                                            (self.in_path, name))
        finally:
            wrpcap(self.in_path, pkts)
            self._test.register_capture(self.cap_name)
            # FIXME this should be an API, but no such exists atm
            self._test.vapi.cli(self.input_cli)

    def generate_debug_aid(self, kind):
        """ Create a hardlink to the out file with a counter and a file
        containing stack trace to ease debugging in case of multiple capture
        files present. """
        self._test.logger.debug("Generating debug aid for %s on %s" %
                                (kind, self._name))
        link_path, stack_path = ["%s/debug_%s_%s_%s.%s" %
                                 (self._test.tempdir, self._name,
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
            self._test.logger.debug("Capture has %s packets" % len(output.res))
        except Scapy_Exception:
            self._test.logger.debug("Exception in scapy.rdpcap (%s): %s" %
                                    (self.out_path, format_exc()))
            return None
        before = len(output.res)
        if filter_out_fn:
            output.res = [p for p in output.res if not filter_out_fn(p)]
        removed = before - len(output.res)
        if removed:
            self._test.logger.debug(
                "Filtered out %s packets from capture (returning %s)" %
                (removed, len(output.res)))
        return output

    def get_capture(self, expected_count=None, remark=None, timeout=1,
                    filter_out_fn=is_ipv6_misc):
        """ Get captured packets

        :param expected_count: expected number of packets to capture, if None,
                               then self._test.packet_count_for_dst_pg_idx is
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
                self._test.get_packet_count_for_if_idx(self.sw_if_index)
            based_on = "based on stored packet_infos"
            if expected_count == 0:
                raise CaptureNoPacketsError(
                    "Internal error, expected packet count for %s is 0!" %
                    name)
        self._test.logger.debug(
            "Expecting to capture %s (%s) packets on %s" % (
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
                    self._test.logger.error(
                        ppc("Unexpected packets captured:", capture))
                    break
                else:
                    self._test.logger.debug("Partial capture containing %s "
                                            "packets doesn't match expected "
                                            "count %s (yet?)" %
                                            (len(capture.res), expected_count))
            elif expected_count == 0:
                # bingo, got None as we expected - return empty capture
                return PacketList()
            remaining_time -= elapsed_time
        if capture:
            self.generate_debug_aid("count-mismatch")
            raise CaptureMismatchError(
                "Captured packets mismatch, captured %s packets, "
                "expected %s packets on %s" % (len(capture.res),
                                               expected_count, name))
        else:
            raise CaptureNoPacketsError("No packets captured on %s" % name)

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
            except CaptureError as e:
                self._test.logger.debug("Capture raised CaptureError: %s", e)
            self.generate_debug_aid("empty-assert")
            if remark:
                raise AssertionError(
                    "Non-empty capture file present for interface %s (%s)" %
                    (self.name, remark))
            else:
                raise AssertionError("Capture file present for interface %s" %
                                     self.name)

    def wait_for_capture_file(self, timeout=1):
        """
        Wait until pcap capture file appears

        :param timeout: How long to wait for the packet (default 1s)

        :returns: True/False if the file is present or appears within timeout
        """
        deadline = time.time() + timeout
        if not os.path.isfile(self.out_path):
            self._test.logger.debug("Waiting for capture file %s to appear, "
                                    "timeout is %ss" % (self.out_path,
                                                        timeout))
        else:
            self._test.logger.debug("Capture file %s already exists" %
                                    self.out_path)
            return True
        while time.time() < deadline:
            if os.path.isfile(self.out_path):
                break
            time.sleep(0)  # yield
        if os.path.isfile(self.out_path):
            self._test.logger.debug("Capture file appeared after %fs" %
                                    (time.time() - (deadline - timeout)))
        else:
            self._test.logger.debug("Timeout - capture file still nowhere")
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
        :raises CaptureTimeoutError: if no packet arrives within timeout
        :raises ValueError: if self._pcap_reader
        """
        deadline = time.time() + timeout
        try:
            if self._pcap_reader is None:
                if not self.wait_for_capture_file(timeout):
                    raise CaptureTimeoutError("Capture file %s did not appear "
                                              "within timeout" % self.out_path)
                while time.time() < deadline:
                    try:
                        self._pcap_reader = PcapReader(self.out_path)
                        break
                    except Scapy_Exception:
                        self._test.logger.debug(
                            "Exception in scapy.PcapReader(%s): %s" %
                            (self.out_path, format_exc()))
        except AttributeError as e:
            raise ValueError('Hmmm... self._pcap_reader not defined...  '
                             'Was .enable_capture() called?')
        try:
            _ = self._pcap_reader
        except AttributeError:
            raise CaptureTimeoutError("Capture file %s did not appear within "
                                      "timeout" % self.out_path)

        poll = False
        if timeout > 0:
            self._test.logger.debug("Waiting %ssec for packet" % timeout)
        else:
            poll = True
            self._test.logger.debug("Polling for packet")
        while time.time() < deadline or poll:
            if not self.verify_enough_packet_data_in_pcap():
                time.sleep(0)  # yield
                poll = False
                continue
            p = self._pcap_reader.recv()
            if p is not None:
                if filter_out_fn is not None and filter_out_fn(p):
                    self._test.logger.debug(
                        "Packet received after %ss was filtered out" %
                        (time.time() - (deadline - timeout)))
                else:
                    self._test.logger.debug(
                        "Packet received after %fs" %
                        (time.time() - (deadline - timeout)))
                    return p
            time.sleep(0)  # yield
            poll = False
        self._test.logger.debug("Timeout - no packets received")
        raise CaptureTimeoutError("Packet didn't arrive within timeout %ssec"
                                  % timeout)

    def create_arp_req(self):
        """Create ARP request applicable for this interface"""
        return (Ether(dst="ff:ff:ff:ff:ff:ff", src=self.remote_mac) /
                ARP(op=ARP.who_has, pdst=self.local_ip4,
                    psrc=self.remote_ip4, hwsrc=self.remote_mac))

    def create_ndp_req(self):
        """Create NDP - NS applicable for this interface"""
        nsma = in6_getnsma(inet_pton(socket.AF_INET6, self.local_ip6))
        d = inet_ntop(socket.AF_INET6, nsma)

        return (Ether(dst=in6_getnsmac(nsma)) /
                IPv6(dst=d, src=self.remote_ip6) /
                ICMPv6ND_NS(tgt=self.local_ip6) /
                ICMPv6NDOptSrcLLAddr(lladdr=self.remote_mac))

    def resolve_arp(self, pg_interface=None):
        """Resolve ARP using provided packet-generator interface

        :param pg_interface: interface used to resolve, if None then this
            interface is used

        """
        if pg_interface is None:
            pg_interface = self

        self._test.logger.info("Sending ARP request for %s on port %s" %
                               (self.local_ip4, pg_interface.name))
        arp_req = self.create_arp_req()
        pg_interface.add_stream(arp_req)
        pg_interface.enable_capture()
        self._test.pg_start()
        self._test.logger.info(self._test.vapi.cli("show trace"))
        try:
            captured_packet = pg_interface.wait_for_packet(1)
        except CaptureTimeoutError:
            self._test.logger.info("No ARP received on port %s" %
                                   pg_interface.name)
            return
        arp_reply = captured_packet.copy()  # keep original for exception
        # Make Dot1AD packet content recognizable to scapy
        if arp_reply.type == 0x88a8:
            self._test.logger.info('Changing arp_reply type from '
                                   '0x88a8 to 0x8100.')
            arp_reply.type = 0x8100
            arp_reply = Ether(str(arp_reply))
        try:
            if arp_reply[ARP].op == ARP.is_at:
                self._test.logger.info("VPP %s MAC address is %s " %
                                       (self.name, arp_reply[ARP].hwsrc))
                self._local_mac = arp_reply[ARP].hwsrc
            else:
                self._test.logger.info("No ARP received on port %s" %
                                       pg_interface.name)
        except KeyError:
            self._test.logger.error(
                ppp("Unexpected response to ARP request:", captured_packet))
            raise CaptureUnexpectedPacketError(
                message='Captured an unexpected packet to an ARP request on '
                        'interface %(interface)s: %(packet)s',
                packet=captured_packet, interface=pg_interface)

    def resolve_ndp(self, pg_interface=None, timeout=1):
        """Resolve NDP using provided packet-generator interface

        :param pg_interface: interface used to resolve, if None then this
            interface is used
        :param timeout: how long to wait for response before giving up

        """
        if pg_interface is None:
            pg_interface = self
        self._test.logger.info("Sending NDP request for %s on port %s" %
                               (self.local_ip6, pg_interface.name))
        ndp_req = self.create_ndp_req()
        pg_interface.add_stream(ndp_req)
        pg_interface.enable_capture()
        self._test.pg_start()
        now = time.time()
        deadline = now + timeout
        # Enabling IPv6 on an interface can generate more than the
        # ND reply we are looking for (namely MLD). So loop through
        # the replies to look for want we want.
        while now < deadline:
            try:
                captured_packet = pg_interface.wait_for_packet(
                    deadline - now, filter_out_fn=None)
            except CaptureTimeoutError:
                self._test.logger.error(
                    "Timeout while waiting for NDP response")
                raise
            ndp_reply = captured_packet.copy()  # keep original for exception
            # Make Dot1AD packet content recognizable to scapy
            if ndp_reply.type == 0x88a8:
                ndp_reply.type = 0x8100
                ndp_reply = Ether(str(ndp_reply))
            try:
                ndp_na = ndp_reply[ICMPv6ND_NA]
                opt = ndp_na[ICMPv6NDOptDstLLAddr]
                self._test.logger.info("VPP %s MAC address is %s " %
                                       (self.name, opt.lladdr))
                self._local_mac = opt.lladdr
                self._test.logger.debug(self._test.vapi.cli("show trace"))
                # we now have the MAC we've been after
                return
            except IndexError:
                self._test.logger.info(
                    ppp("Unexpected response to NDP request:",
                        captured_packet))
                raise CaptureUnexpectedPacketError(
                    message='Captured an unexpected packet to an NDP request '
                            'on interface %(interface)s: %(packet)s',
                    packet=captured_packet, interface=pg_interface)
            now = time.time()

        self._test.logger.debug(self._test.vapi.cli("show trace"))
        raise CaptureTimeoutError("Timeout while waiting for NDP response")

    def __repr__(self):
        return "%s(name=%s sw_if_index=%s)" % (self.__class__.__name__,
                                               self.name,
                                               self.sw_if_index)
