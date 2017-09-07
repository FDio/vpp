""" test framework utilities """

import socket
import sys
from abc import abstractmethod, ABCMeta
from cStringIO import StringIO
from scapy.layers.inet6 import in6_mactoifaceid

from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.inet6 import IPv6, ICMPv6Unknown, ICMPv6EchoRequest
from scapy.packet import Packet
from socket import inet_pton, AF_INET, AF_INET6


def ppp(headline, packet):
    """ Return string containing the output of scapy packet.show() call. """
    o = StringIO()
    old_stdout = sys.stdout
    sys.stdout = o
    print(headline)
    packet.show()
    sys.stdout = old_stdout
    return o.getvalue()


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
            len(capture), limit)
        limit = len(capture)
    body = "".join([ppp("Packet #%s:" % count, p)
                    for count, p in zip(range(0, limit), capture)])
    return "%s\n%s%s" % (headline, body, tail)


def ip4_range(ip4, s, e):
    tmp = ip4.rsplit('.', 1)[0]
    return ("%s.%d" % (tmp, i) for i in range(s, e))


def ip4n_range(ip4n, s, e):
    ip4 = socket.inet_ntop(socket.AF_INET, ip4n)
    return (socket.inet_pton(socket.AF_INET, ip)
            for ip in ip4_range(ip4, s, e))


def mactobinary(mac):
    """ Convert the : separated format into binary packet data for the API """
    return mac.replace(':', '').decode('hex')


def mk_ll_addr(mac):
    euid = in6_mactoifaceid(mac)
    addr = "fe80::" + euid
    return addr


class NumericConstant(object):
    __metaclass__ = ABCMeta

    desc_dict = {}

    @abstractmethod
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


class Host(object):
    """ Generic test host "connected" to VPPs interface. """

    @property
    def mac(self):
        """ MAC address """
        return self._mac

    @property
    def bin_mac(self):
        """ MAC address """
        return mactobinary(self._mac)

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


class ForeignAddressFactory(object):
    count = 0
    prefix_len = 24
    net_template = '10.10.10.{}'
    net = net_template.format(0) + '/' + str(prefix_len)

    def get_ip4(self):
        if self.count > 255:
            raise Exception("Network host address exhaustion")
        self.count += 1
        return self.net_template.format(self.count)


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
        s1 = 1-side
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
        self.ifs[1-side].enable_capture()
        self.testcase.pg_start()

    def recv(self, side):
        p = self.ifs[side].wait_for_packet(1)
        return p

    def send_through(self, side, flags=None, payload=""):
        self.send(side, flags, payload)
        p = self.recv(1-side)
        return p

    def send_pingpong(self, side, flags1=None, flags2=None):
        p1 = self.send_through(side, flags1)
        p2 = self.send_through(1-side, flags2)
        return [p1, p2]


class L4_CONN_SIDE:
    L4_CONN_SIDE_ZERO = 0
    L4_CONN_SIDE_ONE = 1
