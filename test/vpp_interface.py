from abc import abstractmethod, ABCMeta
import socket
from logging import info


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
    def remote_mac_extend(self):
        """List of MAC addresses of the remote hosts "connected" to this interface"""
        return self._remote_mac_extend

    @remote_mac_extend.setter
    def remote_mac_extend(self, value):
        self._remote_mac_extend = value

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
    def remote_ip4_extend(self):
        """List of IPv4  addresses of the remote hosts "connected" to this interface"""
        return self._remote_ip4_extend

    @remote_ip4_extend.setter
    def remote_ip4_extend(self, value):
        self._remote_ip4_extend = value
        self._remote_ip4n_extend = [socket.inet_pton(socket.AF_INET, remote) for remote in self._remote_ip4_extend]

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
        self._remote_mac = "02:%02x:00:00:ff:02" % self.sw_if_index
        self._remote_mac_extend = ["02:%02x:00:00:ff:%02x" % (self.sw_if_index, x) for x in range(3, 250)]

        self._local_ip4 = "172.16.%u.1" % self.sw_if_index
        self._local_ip4n = socket.inet_pton(socket.AF_INET, self.local_ip4)
        self._remote_ip4 = "172.16.%u.2" % self.sw_if_index
        self._remote_ip4n = socket.inet_pton(socket.AF_INET, self.remote_ip4)
        self._remote_ip4_extend = ["172.16.%u.%u" % (self.sw_if_index, x) for x in range(3, 250)]
        self._remote_ip4n_extend = [socket.inet_pton(socket.AF_INET, remote) for remote in self._remote_ip4_extend]

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

    def configure_extend_ipv4_mac_binding(self):
        """Configure neighbor MAC to IPv4 addreses."""
        for i in range(len(self._remote_ip4n_extend)):
            mac = self._remote_mac_extend[i]
            macn = mac.replace(":", "").decode('hex')
            ipn = self._remote_ip4n_extend[i]
            self.test.vapi.ip_neighbor_add_del(self.sw_if_index, macn, ipn)

    def config_ip6(self):
        """Configure IPv6 address on the VPP interface"""
        addr = self._local_ip6n
        addr_len = 64
        self.test.vapi.sw_interface_add_del_address(
            self.sw_if_index, addr, addr_len, is_ipv6=1)

    def set_table_ip4(self, table_id):
        """Set the interface in a IPv4 Table.
        Must be called before configuring IP4 addresses"""
        self.test.vapi.sw_interface_set_table(
            self.sw_if_index, 0, table_id)

    def set_table_ip6(self, table_id):
        """Set the interface in a IPv6 Table.
        Must be called before configuring IP6 addresses"""
        self.test.vapi.sw_interface_set_table(
            self.sw_if_index, 1, table_id)

    def disable_ipv6_ra(self):
        """Configure IPv6 RA suppress on the VPP interface"""
        self.test.vapi.sw_interface_ra_suppress(self.sw_if_index)

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

    def enable_mpls(self):
        """Enable MPLS on the VPP interface"""
        self.test.vapi.sw_interface_enable_disable_mpls(
            self.sw_if_index)
