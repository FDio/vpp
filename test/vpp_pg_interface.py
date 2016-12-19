import os
import time
from scapy.utils import wrpcap, rdpcap, PcapReader
from vpp_interface import VppInterface

from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet6 import IPv6, ICMPv6ND_NS, ICMPv6ND_NA,\
    ICMPv6NDOptSrcLLAddr, ICMPv6NDOptDstLLAddr, ICMPv6ND_RA, RouterAlert, \
    IPv6ExtHdrHopByHop
from util import ppp, ppc


def is_ipv6_misc(p):
    """ Is packet one of uninteresting IPv6 broadcasts? """
    if p.haslayer(ICMPv6ND_RA):
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
        r = test.vapi.pg_create_interface(pg_index)
        self._sw_if_index = r.sw_if_index

        super(VppPGInterface, self).__init__(test)

        self._in_history_counter = 0
        self._out_history_counter = 0
        self._pg_index = pg_index
        self._out_file = "pg%u_out.pcap" % self.pg_index
        self._out_path = self.test.tempdir + "/" + self._out_file
        self._in_file = "pg%u_in.pcap" % self.pg_index
        self._in_path = self.test.tempdir + "/" + self._in_file
        self._capture_cli = "packet-generator capture pg%u pcap %s" % (
            self.pg_index, self.out_path)
        self._cap_name = "pcap%u" % self.sw_if_index
        self._input_cli = "packet-generator new pcap %s source pg%u name %s" % (
            self.in_path, self.pg_index, self.cap_name)

    def enable_capture(self):
        """ Enable capture on this packet-generator interface"""
        try:
            if os.path.isfile(self.out_path):
                os.rename(self.out_path,
                          "%s/history.[timestamp:%f].[%s-counter:%04d].%s" %
                          (self.test.tempdir,
                           time.time(),
                           self.name,
                           self.out_history_counter,
                           self._out_file))
        except:
            pass
        # FIXME this should be an API, but no such exists atm
        self.test.vapi.cli(self.capture_cli)
        self._pcap_reader = None

    def add_stream(self, pkts):
        """
        Add a stream of packets to this packet-generator

        :param pkts: iterable packets

        """
        try:
            if os.path.isfile(self.in_path):
                os.rename(self.in_path,
                          "%s/history.[timestamp:%f].[%s-counter:%04d].%s" %
                          (self.test.tempdir,
                           time.time(),
                           self.name,
                           self.in_history_counter,
                           self._in_file))
        except:
            pass
        wrpcap(self.in_path, pkts)
        self.test.register_capture(self.cap_name)
        # FIXME this should be an API, but no such exists atm
        self.test.vapi.cli(self.input_cli)

    def get_capture(self, remark=None, filter_fn=is_ipv6_misc):
        """
        Get captured packets

        :param remark: remark printed into debug logs
        :param filter_fn: filter applied to each packet, packets for which
                          the filter returns True are removed from capture
        :returns: iterable packets
        """
        try:
            self.wait_for_capture_file()
            output = rdpcap(self.out_path)
            self.test.logger.debug("Capture has %s packets" % len(output.res))
        except IOError:  # TODO
            self.test.logger.debug("File %s does not exist, probably because no"
                                   " packets arrived" % self.out_path)
            if remark:
                raise Exception("No packets captured on %s(%s)" %
                                (self.name, remark))
            else:
                raise Exception("No packets captured on %s" % self.name)
        before = len(output.res)
        if filter_fn:
            output.res = [p for p in output.res if not filter_fn(p)]
        removed = len(output.res) - before
        if removed:
            self.test.logger.debug(
                "Filtered out %s packets from capture (returning %s)" %
                (removed, len(output.res)))
        return output

    def assert_nothing_captured(self, remark=None):
        if os.path.isfile(self.out_path):
            try:
                capture = self.get_capture(remark=remark)
                self.test.logger.error(
                    ppc("Unexpected packets captured:", capture))
            except:
                pass
            if remark:
                raise AssertionError(
                    "Capture file present for interface %s(%s)" %
                    (self.name, remark))
            else:
                raise AssertionError("Capture file present for interface %s" %
                                     self.name)

    def wait_for_capture_file(self, timeout=1):
        """
        Wait until pcap capture file appears

        :param timeout: How long to wait for the packet (default 1s)

        :raises Exception: if the capture file does not appear within timeout
        """
        limit = time.time() + timeout
        if not os.path.isfile(self.out_path):
            self.test.logger.debug(
                "Waiting for capture file to appear, timeout is %ss", timeout)
        else:
            self.test.logger.debug("Capture file already exists")
            return
        while time.time() < limit:
            if os.path.isfile(self.out_path):
                break
            time.sleep(0)  # yield
        if os.path.isfile(self.out_path):
            self.test.logger.debug("Capture file appeared after %fs" %
                                   (time.time() - (limit - timeout)))
        else:
            self.test.logger.debug("Timeout - capture file still nowhere")
            raise Exception("Capture file did not appear within timeout")

    def wait_for_packet(self, timeout):
        """
        Wait for next packet captured with a timeout

        :param timeout: How long to wait for the packet

        :returns: Captured packet if no packet arrived within timeout
        :raises Exception: if no packet arrives within timeout
        """
        limit = time.time() + timeout
        if self._pcap_reader is None:
            self.wait_for_capture_file(timeout)
            self._pcap_reader = PcapReader(self.out_path)

        self.test.logger.debug("Waiting for packet")
        while time.time() < limit:
            p = self._pcap_reader.recv()
            if p is not None:
                self.test.logger.debug("Packet received after %fs",
                                       (time.time() - (limit - timeout)))
                return p
            time.sleep(0)  # yield
        self.test.logger.debug("Timeout - no packets received")
        raise Exception("Packet didn't arrive within timeout")

    def create_arp_req(self):
        """Create ARP request applicable for this interface"""
        return (Ether(dst="ff:ff:ff:ff:ff:ff", src=self.remote_mac) /
                ARP(op=ARP.who_has, pdst=self.local_ip4,
                    psrc=self.remote_ip4, hwsrc=self.remote_mac))

    def create_ndp_req(self):
        """Create NDP - NS applicable for this interface"""
        return (Ether(dst="ff:ff:ff:ff:ff:ff", src=self.remote_mac) /
                IPv6(src=self.remote_ip6, dst=self.local_ip6) /
                ICMPv6ND_NS(tgt=self.local_ip6) /
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
            arp_reply = pg_interface.get_capture(filter_fn=None)
        except:
            self.test.logger.info("No ARP received on port %s" %
                                  pg_interface.name)
            return
        arp_reply = arp_reply[0]
        # Make Dot1AD packet content recognizable to scapy
        if arp_reply.type == 0x88a8:
            arp_reply.type = 0x8100
            arp_reply = Ether(str(arp_reply))
        try:
            if arp_reply[ARP].op == ARP.is_at:
                self.test.logger.info("VPP %s MAC address is %s " %
                                      (self.name, arp_reply[ARP].hwsrc))
                self._local_mac = arp_reply[ARP].hwsrc
            else:
                self.test.logger.info(
                    "No ARP received on port %s" %
                    pg_interface.name)
        except:
            self.test.logger.error(
                ppp("Unexpected response to ARP request:", arp_reply))
            raise

    def resolve_ndp(self, pg_interface=None):
        """Resolve NDP using provided packet-generator interface

        :param pg_interface: interface used to resolve, if None then this
            interface is used

        """
        if pg_interface is None:
            pg_interface = self
        self.test.logger.info("Sending NDP request for %s on port %s" %
                              (self.local_ip6, pg_interface.name))
        ndp_req = self.create_ndp_req()
        pg_interface.add_stream(ndp_req)
        pg_interface.enable_capture()
        self.test.pg_start()
        self.test.logger.info(self.test.vapi.cli("show trace"))
        replies = pg_interface.get_capture(filter_fn=None)
        if replies is None or len(replies) == 0:
            self.test.logger.info(
                "No NDP received on port %s" %
                pg_interface.name)
            return
        # Enabling IPv6 on an interface can generate more than the
        # ND reply we are looking for (namely MLD). So loop through
        # the replies to look for want we want.
        for ndp_reply in replies:
            # Make Dot1AD packet content recognizable to scapy
            if ndp_reply.type == 0x88a8:
                ndp_reply.type = 0x8100
                ndp_reply = Ether(str(ndp_reply))
            try:
                ndp_na = ndp_reply[ICMPv6ND_NA]
                opt = ndp_na[ICMPv6NDOptDstLLAddr]
                self.test.logger.info("VPP %s MAC address is %s " %
                                      (self.name, opt.lladdr))
                self._local_mac = opt.lladdr
            except:
                self.test.logger.info(
                    ppp("Unexpected response to NDP request:", ndp_reply))
        # if no packets above provided the local MAC, then this failed.
        if not hasattr(self, '_local_mac'):
            raise
