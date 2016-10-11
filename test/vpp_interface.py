from abc import abstractmethod, ABCMeta
import socket
from logging import info, error
from scapy.layers.l2 import Ether, ARP

from scapy.layers.inet6 import IPv6, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6NDOptSrcLLAddr, ICMPv6NDOptDstLLAddr


class VppInterface(object):
    """
    Generic VPP interface
    """
    __metaclass__ = ABCMeta

    @property
    def sw_if_index(self):
        """Interface index assigned by VPP"""
        return self._sw_if_index

    @property
    def remote_mac(self):
        """MAC-address of the remote interface "connected" to this interface"""
        return self._remote_mac

    @property
    def local_mac(self):
        """MAC-address of the VPP interface"""
        return self._local_mac

    @property
    def local_ip4(self):
        """Local IPv4 address on VPP interface (string)"""
        return self._local_ip4

    @property
    def local_ip4n(self):
        """Local IPv4 address - raw, suitable as API parameter"""
        return self._local_ip4n

    @property
    def remote_ip4(self):
        """IPv4 address of remote peer "connected" to this interface"""
        return self._remote_ip4

    @property
    def remote_ip4n(self):
        """IPv4 address of remote peer - raw, suitable as API parameter"""
        return self._remote_ip4n

    @property
    def local_ip6(self):
        """Local IPv6 address on VPP interface (string)"""
        return self._local_ip6

    @property
    def local_ip6n(self):
        """Local IPv6 address - raw, suitable as API parameter"""
        return self._local_ip6n

    @property
    def remote_ip6(self):
        """IPv6 address of remote peer "connected" to this interface"""
        return self._remote_ip6

    @property
    def remote_ip6n(self):
        """IPv6 address of remote peer - raw, suitable as API parameter"""
        return self._remote_ip6n

    @property
    def name(self):
        """Name of the interface"""
        return self._name

    @property
    def dump(self):
        """Raw result of sw_interface_dump for this interface"""
        return self._dump

    @property
    def test(self):
        """Test case creating this interface"""
        return self._test

    def post_init_setup(self):
        """Additional setup run after creating an interface object"""
        self._remote_mac = "02:00:00:00:ff:%02x" % self.sw_if_index

        self._local_ip4 = "172.16.%u.1" % self.sw_if_index
        self._local_ip4n = socket.inet_pton(socket.AF_INET, self.local_ip4)
        self._remote_ip4 = "172.16.%u.2" % self.sw_if_index
        self._remote_ip4n = socket.inet_pton(socket.AF_INET, self.remote_ip4)

        self._local_ip6 = "fd01:%u::1" % self.sw_if_index
        self._local_ip6n = socket.inet_pton(socket.AF_INET6, self.local_ip6)
        self._remote_ip6 = "fd01:%u::2" % self.sw_if_index
        self._remote_ip6n = socket.inet_pton(socket.AF_INET6, self.remote_ip6)

        r = self.test.vapi.sw_interface_dump()
        for intf in r:
            if intf.sw_if_index == self.sw_if_index:
                self._name = intf.interface_name.split(b'\0', 1)[0]
                self._local_mac = ':'.join(intf.l2_address.encode('hex')[i:i + 2]
                                           for i in range(0, 12, 2))
                self._dump = intf
                break
        else:
            raise Exception(
                "Could not find interface with sw_if_index %d "
                "in interface dump %s" %
                (self.sw_if_index, repr(r)))

    @abstractmethod
    def __init__(self, test, index):
        self._test = test
        self.post_init_setup()
        info("New %s, MAC=%s, remote_ip4=%s, local_ip4=%s" %
             (self.__name__, self.remote_mac, self.remote_ip4, self.local_ip4))

    def config_ip4(self):
        """Configure IPv4 address on the VPP interface"""
        addr = self.local_ip4n
        addr_len = 24
        self.test.vapi.sw_interface_add_del_address(
            self.sw_if_index, addr, addr_len)

    def config_ip6(self):
        """Configure IPv6 address on the VPP interface"""
        addr = self._local_ip6n
        addr_len = 64
        self.test.vapi.sw_interface_add_del_address(
            self.sw_if_index, addr, addr_len, is_ipv6=1)

    def disable_ipv6_ra(self):
        """Configure IPv6 RA suppress on the VPP interface"""
        self.test.vapi.sw_interface_ra_suppress(self.sw_if_index)

    def create_arp_req(self):
        """Create ARP request applicable for this interface"""
        return (Ether(dst="ff:ff:ff:ff:ff:ff", src=self.remote_mac) /
                ARP(op=ARP.who_has, pdst=self.local_ip4,
                    psrc=self.remote_ip4, hwsrc=self.remote_mac))

    def create_ndp_req(self):
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
        info("Sending ARP request for %s on port %s" %
             (self.local_ip4, pg_interface.name))
        arp_req = self.create_arp_req()
        pg_interface.add_stream(arp_req)
        pg_interface.enable_capture()
        self.test.pg_start()
        info(self.test.vapi.cli("show trace"))
        arp_reply = pg_interface.get_capture()
        if arp_reply is None or len(arp_reply) == 0:
            info("No ARP received on port %s" % pg_interface.name)
            return
        arp_reply = arp_reply[0]
        # Make Dot1AD packet content recognizable to scapy
        if arp_reply.type == 0x88a8:
            arp_reply.type = 0x8100
            arp_reply = Ether(str(arp_reply))
        try:
            if arp_reply[ARP].op == ARP.is_at:
                info("VPP %s MAC address is %s " %
                     (self.name, arp_reply[ARP].hwsrc))
                self._local_mac = arp_reply[ARP].hwsrc
            else:
                info("No ARP received on port %s" % pg_interface.name)
        except:
            error("Unexpected response to ARP request:")
            error(arp_reply.show())
            raise

    def resolve_ndp(self, pg_interface=None):
        """Resolve NDP using provided packet-generator interface

        :param pg_interface: interface used to resolve, if None then this
            interface is used

        """
        if pg_interface is None:
            pg_interface = self
        info("Sending NDP request for %s on port %s" %
             (self.local_ip6, pg_interface.name))
        ndp_req = self.create_ndp_req()
        pg_interface.add_stream(ndp_req)
        pg_interface.enable_capture()
        self.test.pg_start()
        info(self.test.vapi.cli("show trace"))
        ndp_reply = pg_interface.get_capture()
        if ndp_reply is None or len(ndp_reply) == 0:
            info("No NDP received on port %s" % pg_interface.name)
            return
        ndp_reply = ndp_reply[0]
        # Make Dot1AD packet content recognizable to scapy
        if ndp_reply.type == 0x88a8:
            ndp_reply.type = 0x8100
            ndp_reply = Ether(str(ndp_reply))
        try:
            ndp_na = ndp_reply[ICMPv6ND_NA]
            opt = ndp_na[ICMPv6NDOptDstLLAddr]
            info("VPP %s MAC address is %s " %
                 (self.name, opt.lladdr))
            self._local_mac = opt.lladdr
        except:
            error("Unexpected response to NDP request:")
            error(ndp_reply.show())
            raise

    def admin_up(self):
        """ Put interface ADMIN-UP """
        self.test.vapi.sw_interface_set_flags(self.sw_if_index, admin_up_down=1)

    def add_sub_if(self, sub_if):
        """
        Register a sub-interface with this interface

        :param sub_if: sub-interface

        """
        if not hasattr(self, 'sub_if'):
            self.sub_if = sub_if
        else:
            if isinstance(self.sub_if, list):
                self.sub_if.append(sub_if)
            else:
                self.sub_if = sub_if
