from abc import abstractmethod, ABCMeta
import socket
from logging import info
from scapy.layers.l2 import Ether, ARP
from vapi import vapi


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
    def name(self):
        """Name of the interface"""
        return self._name

    @property
    def dump(self):
        """Raw result of sw_interface_dump for this interface"""
        return self._dump

    def post_init_setup(self):
        """ """
        self._remote_mac = "02:00:00:00:ff:%02x" % self.sw_if_index
        self._local_ip4 = "172.16.%u.1" % self.sw_if_index
        self._local_ip4n = socket.inet_pton(socket.AF_INET, self.local_ip4)
        self._remote_ip4 = "172.16.%u.2" % self.sw_if_index
        self._remote_ip4n = socket.inet_pton(socket.AF_INET, self.remote_ip4)
        r = vapi.sw_interface_dump()
        found = False
        for intf in r:
            if intf.sw_if_index == self.sw_if_index:
                found = True
                self._name = intf.interface_name.split(b'\0', 1)[0]
                self._dump = intf
                break
        if not found:
            raise Exception(
                "Could not find interface with sw_if_index %d "
                "in interface dump %s" %
                (self.sw_if_index, repr(r)))

    @abstractmethod
    def __init__(self, cls, index):
        self.post_init_setup()
        info("New VppInterface, MAC=%s, remote_ip4=%s, local_ip4=%s" %
             (self.remote_mac, self.remote_ip4, self.local_ip4))

    def config_ip4(self):
        """Configure IPv4 address on the VPP interface"""
        addr = self.local_ip4n
        addr_len = 24
        vapi.sw_interface_add_del_address(self.sw_if_index, addr, addr_len)

    def config_ip6(self):
        """Configure IPv6 address on the VPP interface"""
        addr = self.vpp_ip6n
        addr_len = 64
        vapi.sw_interface_add_del_address(
            self.sw_if_index, addr, addr_len, is_ipv6=1)

    def create_arp_req(self):
        """Create ARP request applicable for this interface"""
        return (Ether(dst="ff:ff:ff:ff:ff:ff", src=self.remote_mac) /
                ARP(op=ARP.who_has, pdst=self.local_ip4,
                    psrc=self.remote_ip4, hwsrc=self.remote_mac))

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
        info(vapi.cli("show trace"))
        arp_reply = pg_interface.get_capture()
        if arp_reply is None or len(arp_reply) == 0:
            info("No ARP received on port %s" % pg_interface.name)
            return
        arp_reply = arp_reply[0]
        if arp_reply[ARP].op == ARP.is_at:
            info("VPP %s MAC address is %s " %
                 (self.name, arp_reply[ARP].hwsrc))
            self._local_mac = arp_reply[ARP].hwsrc
        else:
            info("No ARP received on port %s" % pg_interface.name)

    def admin_up(self):
        """ Put interface ADMIN-UP """
        vapi.sw_interface_set_flags(self.sw_if_index, admin_up_down=1)

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
