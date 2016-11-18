import socket
import sys
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


class Host(object):
    """ Generic test host "connected" to VPPs interface. """

    @property
    def mac(self):
        """ MAC address """
        return self._mac

    @property
    def ip4(self):
        """ IPv4 address """
        return self._ip4

    @property
    def ip4n(self):
        """ IPv4 address """
        return socket.inet_pton(socket.AF_INET, self._ip4)

    @property
    def ip6(self):
        """ IPv6 address """
        return self._ip6

    def __init__(self, mac=None, ip4=None, ip6=None):
        self._mac = mac
        self._ip4 = ip4
        self._ip6 = ip6
