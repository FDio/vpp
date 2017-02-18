""" test framework utilities """

import socket
import sys
from abc import abstractmethod, ABCMeta
from cStringIO import StringIO


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

    def __init__(self, mac=None, ip4=None, ip6=None):
        self._mac = mac
        self._ip4 = ip4
        self._ip6 = ip6


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
