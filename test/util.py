""" test framework utilities """

import abc
import ipaddress
import logging
import socket
from socket import AF_INET6
import sys
import os.path

import scapy.compat
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment, IPv6ExtHdrRouting,\
    IPv6ExtHdrHopByHop
from scapy.packet import Raw
from scapy.utils import hexdump
from scapy.utils6 import in6_mactoifaceid

from io import BytesIO
from vpp_papi import mac_pton

# Set up an empty logger for the testcase that can be overridden as necessary
null_logger = logging.getLogger('VppTestCase.util')
null_logger.addHandler(logging.NullHandler())


def ppp(headline, packet):
    """ Return string containing the output of scapy packet.show() call. """
    return '%s\n%s\n\n%s\n' % (headline,
                               hexdump(packet, dump=True),
                               packet.show(dump=True))


def ppc(headline, capture, limit=10):
    """ Return string containing ppp() printout for a capture.

    :param headline: printed as first line of output
    :param capture: packets to print
    :param limit: limit the print to # of packets
    """
    if not capture:
        return headline
    tail = ""
    if limit < len(capture):
        tail = "\nPrint limit reached, %s out of %s packets printed" % (
            limit, len(capture))
    body = "".join([ppp("Packet #%s:" % count, p)
                    for count, p in zip(range(0, limit), capture)])
    return "%s\n%s%s" % (headline, body, tail)


def ip4_range(ip4, s, e):
    tmp = ip4.rsplit('.', 1)[0]
    return ("%s.%d" % (tmp, i) for i in range(s, e))


def mcast_ip_to_mac(ip):
    ip = ipaddress.ip_address(ip)
    if not ip.is_multicast:
        raise ValueError("Must be multicast address.")
    ip_as_int = int(ip)
    if ip.version == 4:
        mcast_mac = "01:00:5e:%02x:%02x:%02x" % ((ip_as_int >> 16) & 0x7f,
                                                 (ip_as_int >> 8) & 0xff,
                                                 ip_as_int & 0xff)
    else:
        mcast_mac = "33:33:%02x:%02x:%02x:%02x" % ((ip_as_int >> 24) & 0xff,
                                                   (ip_as_int >> 16) & 0xff,
                                                   (ip_as_int >> 8) & 0xff,
                                                   ip_as_int & 0xff)
    return mcast_mac


# wrapper around scapy library function.
def mk_ll_addr(mac):
    euid = in6_mactoifaceid(str(mac))
    addr = "fe80::" + euid
    return addr


def ip6_normalize(ip6):
    return socket.inet_ntop(socket.AF_INET6,
                            socket.inet_pton(socket.AF_INET6, ip6))


def get_core_path(tempdir):
    return "%s/%s" % (tempdir, get_core_pattern())


def is_core_present(tempdir):
    return os.path.isfile(get_core_path(tempdir))


def get_core_pattern():
    with open("/proc/sys/kernel/core_pattern", "r") as f:
        corefmt = f.read().strip()
    return corefmt


def check_core_path(logger, core_path):
    corefmt = get_core_pattern()
    if corefmt.startswith("|"):
        logger.error(
            "WARNING: redirecting the core dump through a"
            " filter may result in truncated dumps.")
        logger.error(
            "   You may want to check the filter settings"
            " or uninstall it and edit the"
            " /proc/sys/kernel/core_pattern accordingly.")
        logger.error(
            "   current core pattern is: %s" % corefmt)


class NumericConstant:

    desc_dict = {}

    def __init__(self, value):
        self._value = value

    def __int__(self):
        return self._value

    def __long__(self):
        return self._value

    def __str__(self):
        if self._value in self.desc_dict:
            return self.desc_dict[self._value]
        return ""


class Host:
    """ Generic test host "connected" to VPPs interface. """

    @property
    def mac(self):
        """ MAC address """
        return self._mac

    @property
    def bin_mac(self):
        """ MAC address """
        return mac_pton(self._mac)

    @property
    def ip4(self):
        """ IPv4 address - string """
        return self._ip4

    @property
    def ip4n(self):
        """ IPv4 address of remote host - raw, suitable as API parameter."""
        return socket.inet_pton(socket.AF_INET, self._ip4)

    @property
    def ip6(self):
        """ IPv6 address - string """
        return self._ip6

    @property
    def ip6n(self):
        """ IPv6 address of remote host - raw, suitable as API parameter."""
        return socket.inet_pton(socket.AF_INET6, self._ip6)

    @property
    def ip6_ll(self):
        """ IPv6 link-local address - string """
        return self._ip6_ll

    @property
    def ip6n_ll(self):
        """ IPv6 link-local address of remote host -
        raw, suitable as API parameter."""
        return socket.inet_pton(socket.AF_INET6, self._ip6_ll)

    def __eq__(self, other):
        if isinstance(other, Host):
            return (self.mac == other.mac and
                    self.ip4 == other.ip4 and
                    self.ip6 == other.ip6 and
                    self.ip6_ll == other.ip6_ll)
        else:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __repr__(self):
        return "Host { mac:%s ip4:%s ip6:%s ip6_ll:%s }" % (self.mac,
                                                            self.ip4,
                                                            self.ip6,
                                                            self.ip6_ll)

    def __hash__(self):
        return hash(self.__repr__())

    def __init__(self, mac=None, ip4=None, ip6=None, ip6_ll=None):
        self._mac = mac
        self._ip4 = ip4
        self._ip6 = ip6
        self._ip6_ll = ip6_ll


class L4_Conn():
    """ L4 'connection' tied to two VPP interfaces """

    def __init__(self, testcase, if1, if2, af, l4proto, port1, port2):
        self.testcase = testcase
        self.ifs = [None, None]
        self.ifs[0] = if1
        self.ifs[1] = if2
        self.address_family = af
        self.l4proto = l4proto
        self.ports = [None, None]
        self.ports[0] = port1
        self.ports[1] = port2
        self

    def pkt(self, side, l4args={}, payload="x"):
        is_ip6 = 1 if self.address_family == AF_INET6 else 0
        s0 = side
        s1 = 1 - side
        src_if = self.ifs[s0]
        dst_if = self.ifs[s1]
        layer_3 = [IP(src=src_if.remote_ip4, dst=dst_if.remote_ip4),
                   IPv6(src=src_if.remote_ip6, dst=dst_if.remote_ip6)]
        merged_l4args = {'sport': self.ports[s0], 'dport': self.ports[s1]}
        merged_l4args.update(l4args)
        p = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
             layer_3[is_ip6] /
             self.l4proto(**merged_l4args) /
             Raw(payload))
        return p

    def send(self, side, flags=None, payload=""):
        l4args = {}
        if flags is not None:
            l4args['flags'] = flags
        self.ifs[side].add_stream(self.pkt(side,
                                           l4args=l4args, payload=payload))
        self.ifs[1 - side].enable_capture()
        self.testcase.pg_start()

    def recv(self, side):
        p = self.ifs[side].wait_for_packet(1)
        return p

    def send_through(self, side, flags=None, payload=""):
        self.send(side, flags, payload)
        p = self.recv(1 - side)
        return p

    def send_pingpong(self, side, flags1=None, flags2=None):
        p1 = self.send_through(side, flags1)
        p2 = self.send_through(1 - side, flags2)
        return [p1, p2]


class L4_CONN_SIDE:
    L4_CONN_SIDE_ZERO = 0
    L4_CONN_SIDE_ONE = 1


def fragment_rfc791(packet, fragsize, logger=null_logger):
    """
    Fragment an IPv4 packet per RFC 791
    :param packet: packet to fragment
    :param fragsize: size at which to fragment
    :note: IP options are not supported
    :returns: list of fragments
    """
    logger.debug(ppp("Fragmenting packet:", packet))
    packet = packet.__class__(scapy.compat.raw(packet))  # recalc. all values
    if len(packet[IP].options) > 0:
        raise Exception("Not implemented")
    if len(packet) <= fragsize:
        return [packet]

    pre_ip_len = len(packet) - len(packet[IP])
    ip_header_len = packet[IP].ihl * 4
    hex_packet = scapy.compat.raw(packet)
    hex_headers = hex_packet[:(pre_ip_len + ip_header_len)]
    hex_payload = hex_packet[(pre_ip_len + ip_header_len):]

    pkts = []
    ihl = packet[IP].ihl
    otl = len(packet[IP])
    nfb = int((fragsize - pre_ip_len - ihl * 4) / 8)
    fo = packet[IP].frag

    p = packet.__class__(hex_headers + hex_payload[:nfb * 8])
    p[IP].flags = "MF"
    p[IP].frag = fo
    p[IP].len = ihl * 4 + nfb * 8
    del p[IP].chksum
    pkts.append(p)

    p = packet.__class__(hex_headers + hex_payload[nfb * 8:])
    p[IP].len = otl - nfb * 8
    p[IP].frag = fo + nfb
    del p[IP].chksum

    more_fragments = fragment_rfc791(p, fragsize, logger)
    pkts.extend(more_fragments)

    return pkts


def fragment_rfc8200(packet, identification, fragsize, logger=null_logger):
    """
    Fragment an IPv6 packet per RFC 8200
    :param packet: packet to fragment
    :param fragsize: size at which to fragment
    :note: IP options are not supported
    :returns: list of fragments
    """
    packet = packet.__class__(scapy.compat.raw(packet))  # recalc. all values
    if len(packet) <= fragsize:
        return [packet]
    logger.debug(ppp("Fragmenting packet:", packet))
    pkts = []
    counter = 0
    routing_hdr = None
    hop_by_hop_hdr = None
    upper_layer = None
    seen_ipv6 = False
    ipv6_nr = -1
    l = packet.getlayer(counter)
    while l is not None:
        if l.__class__ is IPv6:
            if seen_ipv6:
                # ignore 2nd IPv6 header and everything below..
                break
            ipv6_nr = counter
            seen_ipv6 = True
        elif l.__class__ is IPv6ExtHdrFragment:
            raise Exception("Already fragmented")
        elif l.__class__ is IPv6ExtHdrRouting:
            routing_hdr = counter
        elif l.__class__ is IPv6ExtHdrHopByHop:
            hop_by_hop_hdr = counter
        elif seen_ipv6 and not upper_layer and \
                not l.__class__.__name__.startswith('IPv6ExtHdr'):
            upper_layer = counter
        counter = counter + 1
        l = packet.getlayer(counter)

    logger.debug(
        "Layers seen: IPv6(#%s), Routing(#%s), HopByHop(#%s), upper(#%s)" %
        (ipv6_nr, routing_hdr, hop_by_hop_hdr, upper_layer))

    if upper_layer is None:
        raise Exception("Upper layer header not found in IPv6 packet")

    last_per_fragment_hdr = ipv6_nr
    if routing_hdr is None:
        if hop_by_hop_hdr is not None:
            last_per_fragment_hdr = hop_by_hop_hdr
    else:
        last_per_fragment_hdr = routing_hdr
    logger.debug("Last per-fragment hdr is #%s" % (last_per_fragment_hdr))

    per_fragment_headers = packet.copy()
    per_fragment_headers[last_per_fragment_hdr].remove_payload()
    logger.debug(ppp("Per-fragment headers:", per_fragment_headers))

    ext_and_upper_layer = packet.getlayer(last_per_fragment_hdr)[1]
    hex_payload = scapy.compat.raw(ext_and_upper_layer)
    logger.debug("Payload length is %s" % len(hex_payload))
    logger.debug(ppp("Ext and upper layer:", ext_and_upper_layer))

    fragment_ext_hdr = IPv6ExtHdrFragment()
    logger.debug(ppp("Fragment header:", fragment_ext_hdr))

    len_ext_and_upper_layer_payload = len(ext_and_upper_layer.payload)
    if not len_ext_and_upper_layer_payload and \
       hasattr(ext_and_upper_layer, "data"):
        len_ext_and_upper_layer_payload = len(ext_and_upper_layer.data)

    if len(per_fragment_headers) + len(fragment_ext_hdr) +\
            len(ext_and_upper_layer) - len_ext_and_upper_layer_payload\
            > fragsize:
        raise Exception("Cannot fragment this packet - MTU too small "
                        "(%s, %s, %s, %s, %s)" % (
                            len(per_fragment_headers), len(fragment_ext_hdr),
                            len(ext_and_upper_layer),
                            len_ext_and_upper_layer_payload, fragsize))

    orig_nh = packet[IPv6].nh
    p = per_fragment_headers
    del p[IPv6].plen
    del p[IPv6].nh
    p = p / fragment_ext_hdr
    del p[IPv6ExtHdrFragment].nh
    first_payload_len_nfb = int((fragsize - len(p)) / 8)
    p = p / Raw(hex_payload[:first_payload_len_nfb * 8])
    del p[IPv6].plen
    p[IPv6ExtHdrFragment].nh = orig_nh
    p[IPv6ExtHdrFragment].id = identification
    p[IPv6ExtHdrFragment].offset = 0
    p[IPv6ExtHdrFragment].m = 1
    p = p.__class__(scapy.compat.raw(p))
    logger.debug(ppp("Fragment %s:" % len(pkts), p))
    pkts.append(p)
    offset = first_payload_len_nfb * 8
    logger.debug("Offset after first fragment: %s" % offset)
    while len(hex_payload) > offset:
        p = per_fragment_headers
        del p[IPv6].plen
        del p[IPv6].nh
        p = p / fragment_ext_hdr
        del p[IPv6ExtHdrFragment].nh
        l_nfb = int((fragsize - len(p)) / 8)
        p = p / Raw(hex_payload[offset:offset + l_nfb * 8])
        p[IPv6ExtHdrFragment].nh = orig_nh
        p[IPv6ExtHdrFragment].id = identification
        p[IPv6ExtHdrFragment].offset = int(offset / 8)
        p[IPv6ExtHdrFragment].m = 1
        p = p.__class__(scapy.compat.raw(p))
        logger.debug(ppp("Fragment %s:" % len(pkts), p))
        pkts.append(p)
        offset = offset + l_nfb * 8

    pkts[-1][IPv6ExtHdrFragment].m = 0  # reset more-flags in last fragment

    return pkts


def reassemble4_core(listoffragments, return_ip):
    buffer = BytesIO()
    first = listoffragments[0]
    buffer.seek(20)
    for pkt in listoffragments:
        buffer.seek(pkt[IP].frag*8)
        buffer.write(bytes(pkt[IP].payload))
    first.len = len(buffer.getvalue()) + 20
    first.flags = 0
    del(first.chksum)
    if return_ip:
        header = bytes(first[IP])[:20]
        return first[IP].__class__(header + buffer.getvalue())
    else:
        header = bytes(first[Ether])[:34]
        return first[Ether].__class__(header + buffer.getvalue())


def reassemble4_ether(listoffragments):
    return reassemble4_core(listoffragments, False)


def reassemble4(listoffragments):
    return reassemble4_core(listoffragments, True)


def sum_stats(stats):
    """ Return summary stats irregardles of worker index """
    return sum([x[0] for x in stats])


def sum_stats_for_intf(stats, if_idx):
    """ Return summary stats irregardles of worker index """
    return sum([x[if_idx] for x in stats])
