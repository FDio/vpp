import binascii
import socket
import abc

from util import Host, mk_ll_addr
from vpp_papi import mac_ntop, VppEnum
from ipaddress import IPv4Network, IPv6Network

try:
    text_type = unicode
except NameError:
    text_type = str


class VppInterface(metaclass=abc.ABCMeta):
    """Generic VPP interface."""

    @property
    def sw_if_index(self):
        """Interface index assigned by VPP."""
        return self._sw_if_index

    @property
    def remote_mac(self):
        """MAC-address of the remote interface "connected" to this interface"""
        return self._remote_hosts[0].mac

    @property
    def local_mac(self):
        """MAC-address of the VPP interface."""
        return str(self._local_mac)

    @property
    def local_addr(self):
        return self._local_addr

    @property
    def remote_addr(self):
        return self._remote_addr

    @property
    def local_ip4(self):
        """Local IPv4 address on VPP interface (string)."""
        return self._local_ip4

    @local_ip4.setter
    def local_ip4(self, value):
        self._local_ip4 = value

    @property
    def local_ip4_prefix_len(self):
        """Local IPv4 prefix length """
        return self._local_ip4_len

    @local_ip4_prefix_len.setter
    def local_ip4_prefix_len(self, value):
        self._local_ip4_len = value

    @property
    def local_ip4_prefix(self):
        """Local IPv4 prefix """
        return ("%s/%d" % (self._local_ip4, self._local_ip4_len))

    @property
    def remote_ip4(self):
        """IPv4 address of remote peer "connected" to this interface."""
        return self._remote_hosts[0].ip4

    @property
    def local_ip6(self):
        """Local IPv6 address on VPP interface (string)."""
        return self._local_ip6

    @local_ip6.setter
    def local_ip6(self, value):
        self._local_ip6 = value

    @property
    def local_ip6_prefix_len(self):
        """Local IPv6 prefix length """
        return self._local_ip6_len

    @local_ip6_prefix_len.setter
    def local_ip6_prefix_len(self, value):
        self._local_ip6_len = value

    @property
    def local_ip6_prefix(self):
        """Local IPv4 prefix """
        return ("%s/%d" % (self._local_ip6, self._local_ip6_len))

    @property
    def remote_ip6(self):
        """IPv6 address of remote peer "connected" to this interface."""
        return self._remote_hosts[0].ip6

    @property
    def local_ip6_ll(self):
        """Local IPv6 link-local address on VPP interface (string)."""
        if not self._local_ip6_ll:
            self._local_ip6_ll = str(
                self.test.vapi.sw_interface_ip6_get_link_local_address(
                    self.sw_if_index).ip)
        return self._local_ip6_ll

    @property
    def remote_ip6_ll(self):
        """Link-local IPv6 address of remote peer
        "connected" to this interface."""
        return self._remote_ip6_ll

    @property
    def name(self):
        """Name of the interface."""
        return self._name

    @property
    def dump(self):
        """RAW result of sw_interface_dump for this interface."""
        return self._dump

    @property
    def test(self):
        """Test case creating this interface."""
        return self._test

    @property
    def remote_hosts(self):
        """Remote hosts list"""
        return self._remote_hosts

    @remote_hosts.setter
    def remote_hosts(self, value):
        """
        :param list value: List of remote hosts.
        """
        self._remote_hosts = value
        self._hosts_by_mac = {}
        self._hosts_by_ip4 = {}
        self._hosts_by_ip6 = {}
        for host in self._remote_hosts:
            self._hosts_by_mac[host.mac] = host
            self._hosts_by_ip4[host.ip4] = host
            self._hosts_by_ip6[host.ip6] = host

    def host_by_mac(self, mac):
        """
        :param mac: MAC address to find host by.
        :return: Host object assigned to interface.
        """
        return self._hosts_by_mac[mac]

    def host_by_ip4(self, ip):
        """
        :param ip: IPv4 address to find host by.
        :return: Host object assigned to interface.
        """
        return self._hosts_by_ip4[ip]

    def host_by_ip6(self, ip):
        """
        :param ip: IPv6 address to find host by.
        :return: Host object assigned to interface.
        """
        return self._hosts_by_ip6[ip]

    def generate_remote_hosts(self, count=1):
        """Generate and add remote hosts for the interface.

        :param int count: Number of generated remote hosts.
        """
        self._remote_hosts = []
        self._hosts_by_mac = {}
        self._hosts_by_ip4 = {}
        self._hosts_by_ip6 = {}
        for i in range(
                2, count + 2):  # 0: network address, 1: local vpp address
            mac = "02:%02x:00:00:ff:%02x" % (self.sw_if_index, i)
            ip4 = "172.16.%u.%u" % (self.sw_if_index, i)
            ip6 = "fd01:%x::%x" % (self.sw_if_index, i)
            ip6_ll = mk_ll_addr(mac)
            host = Host(mac, ip4, ip6, ip6_ll)
            self._remote_hosts.append(host)
            self._hosts_by_mac[mac] = host
            self._hosts_by_ip4[ip4] = host
            self._hosts_by_ip6[ip6] = host

    @abc.abstractmethod
    def __init__(self, test):
        self._test = test

        self._remote_hosts = []
        self._hosts_by_mac = {}
        self._hosts_by_ip4 = {}
        self._hosts_by_ip6 = {}

    def set_mac(self, mac):
        self._local_mac = str(mac)
        self.test.vapi.sw_interface_set_mac_address(
            self.sw_if_index, mac.packed)
        return self

    def set_sw_if_index(self, sw_if_index):
        if sw_if_index > 255:
            raise RuntimeError("Don't support sw_if_index values "
                               "greater than 255.")
        self._sw_if_index = sw_if_index

        self.generate_remote_hosts()

        self._local_ip4 = "172.16.%u.1" % self.sw_if_index
        self._local_ip4_len = 24
        self._local_ip4_subnet = "172.16.%u.0" % self.sw_if_index
        self._local_ip4_bcast = "172.16.%u.255" % self.sw_if_index
        self.has_ip4_config = False
        self.ip4_table_id = 0

        self._local_ip6 = "fd01:%x::1" % self.sw_if_index
        self._local_ip6_len = 64
        self.has_ip6_config = False
        self.ip6_table_id = 0

        self._local_addr = {socket.AF_INET: self.local_ip4,
                            socket.AF_INET6: self.local_ip6}
        self._remote_addr = {socket.AF_INET: self.remote_ip4,
                             socket.AF_INET6: self.remote_ip6}

        r = self.test.vapi.sw_interface_dump(sw_if_index=self.sw_if_index)
        for intf in r:
            if intf.sw_if_index == self.sw_if_index:
                self._name = intf.interface_name
                self._local_mac = intf.l2_address
                self._dump = intf
                break
        else:
            raise Exception(
                "Could not find interface with sw_if_index %d "
                "in interface dump %s" %
                (self.sw_if_index, moves.reprlib.repr(r)))
        self._remote_ip6_ll = mk_ll_addr(self.remote_mac)
        self._local_ip6_ll = None

    def config_ip4(self):
        """Configure IPv4 address on the VPP interface."""
        self.test.vapi.sw_interface_add_del_address(
            sw_if_index=self.sw_if_index, prefix=self.local_ip4_prefix)
        self.has_ip4_config = True
        return self

    def unconfig_ip4(self):
        """Remove IPv4 address on the VPP interface."""
        try:
            if self.has_ip4_config:
                self.test.vapi.sw_interface_add_del_address(
                    sw_if_index=self.sw_if_index,
                    prefix=self.local_ip4_prefix, is_add=0)
        except AttributeError:
            self.has_ip4_config = False
        self.has_ip4_config = False
        return self

    def configure_ipv4_neighbors(self):
        """For every remote host assign neighbor's MAC to IPv4 addresses.

        :param vrf_id: The FIB table / VRF ID. (Default value = 0)
        """
        for host in self._remote_hosts:
            self.test.vapi.ip_neighbor_add_del(self.sw_if_index,
                                               host.mac,
                                               host.ip4)
        return self

    def config_ip6(self):
        """Configure IPv6 address on the VPP interface."""
        self.test.vapi.sw_interface_add_del_address(
            sw_if_index=self.sw_if_index, prefix=self.local_ip6_prefix)
        self.has_ip6_config = True
        return self

    def unconfig_ip6(self):
        """Remove IPv6 address on the VPP interface."""
        try:
            if self.has_ip6_config:
                self.test.vapi.sw_interface_add_del_address(
                    sw_if_index=self.sw_if_index,
                    prefix=self.local_ip6_prefix, is_add=0)
        except AttributeError:
            self.has_ip6_config = False
        self.has_ip6_config = False
        return self

    def configure_ipv6_neighbors(self):
        """For every remote host assign neighbor's MAC to IPv6 addresses.

        :param vrf_id: The FIB table / VRF ID. (Default value = 0)
        """
        for host in self._remote_hosts:
            self.test.vapi.ip_neighbor_add_del(self.sw_if_index,
                                               host.mac,
                                               host.ip6)

    def unconfig(self):
        """Unconfigure IPv6 and IPv4 address on the VPP interface."""
        self.unconfig_ip4()
        self.unconfig_ip6()
        return self

    def set_table_ip4(self, table_id):
        """Set the interface in a IPv4 Table.

        .. note:: Must be called before configuring IP4 addresses.
        """
        self.ip4_table_id = table_id
        self.test.vapi.sw_interface_set_table(
            self.sw_if_index, 0, self.ip4_table_id)
        return self

    def set_table_ip6(self, table_id):
        """Set the interface in a IPv6 Table.

        .. note:: Must be called before configuring IP6 addresses.
        """
        self.ip6_table_id = table_id
        self.test.vapi.sw_interface_set_table(
            self.sw_if_index, 1, self.ip6_table_id)
        return self

    def disable_ipv6_ra(self):
        """Configure IPv6 RA suppress on the VPP interface."""
        self.test.vapi.sw_interface_ip6nd_ra_config(
            sw_if_index=self.sw_if_index,
            suppress=1)
        return self

    def ip6_ra_config(self, no=0, suppress=0, send_unicast=0):
        """Configure IPv6 RA suppress on the VPP interface."""
        self.test.vapi.sw_interface_ip6nd_ra_config(
            sw_if_index=self.sw_if_index,
            is_no=no,
            suppress=suppress,
            send_unicast=send_unicast)
        return self

    def ip6_ra_prefix(self, prefix, is_no=0,
                      off_link=0, no_autoconfig=0, use_default=0):
        """Configure IPv6 RA suppress on the VPP interface.

        prefix can be a string in the format of '<address>/<length_in_bits>'
        or ipaddress.ipnetwork object (if strict.)"""

        self.test.vapi.sw_interface_ip6nd_ra_prefix(
            sw_if_index=self.sw_if_index,
            prefix=prefix,
            use_default=use_default,
            off_link=off_link, no_autoconfig=no_autoconfig,
            is_no=is_no)
        return self

    def admin_up(self):
        """Put interface ADMIN-UP."""
        self.test.vapi.sw_interface_set_flags(
            self.sw_if_index,
            flags=VppEnum.vl_api_if_status_flags_t.IF_STATUS_API_FLAG_ADMIN_UP)
        return self

    def admin_down(self):
        """Put interface ADMIN-down."""
        self.test.vapi.sw_interface_set_flags(self.sw_if_index,
                                              flags=0)
        return self

    def link_up(self):
        """Put interface link-state-UP."""
        self.test.vapi.cli("test interface link-state %s up" % self.name)

    def link_down(self):
        """Put interface link-state-down."""
        self.test.vapi.cli("test interface link-state %s down" % self.name)

    def ip6_enable(self):
        """IPv6 Enable interface"""
        self.test.vapi.sw_interface_ip6_enable_disable(self.sw_if_index,
                                                       enable=1)
        return self

    def ip6_disable(self):
        """Put interface ADMIN-DOWN."""
        self.test.vapi.sw_interface_ip6_enable_disable(self.sw_if_index,
                                                       enable=0)
        return self

    def add_sub_if(self, sub_if):
        """Register a sub-interface with this interface.

        :param sub_if: sub-interface
        """
        if not hasattr(self, 'sub_if'):
            self.sub_if = sub_if
        else:
            if isinstance(self.sub_if, list):
                self.sub_if.append(sub_if)
            else:
                self.sub_if = sub_if
        return self

    def enable_mpls(self):
        """Enable MPLS on the VPP interface."""
        self.test.vapi.sw_interface_set_mpls_enable(self.sw_if_index)
        return self

    def disable_mpls(self):
        """Enable MPLS on the VPP interface."""
        self.test.vapi.sw_interface_set_mpls_enable(self.sw_if_index, 0)
        return self

    def is_ip4_entry_in_fib_dump(self, dump):
        for i in dump:
            n = IPv4Network(text_type("%s/%d" % (self.local_ip4,
                                                 self.local_ip4_prefix_len)))
            if i.route.prefix == n and \
               i.route.table_id == self.ip4_table_id:
                return True
        return False

    def set_unnumbered(self, ip_sw_if_index):
        """ Set the interface to unnumbered via ip_sw_if_index """
        self.test.vapi.sw_interface_set_unnumbered(ip_sw_if_index,
                                                   self.sw_if_index)
        return self

    def unset_unnumbered(self, ip_sw_if_index):
        """ Unset the interface to unnumbered via ip_sw_if_index """
        self.test.vapi.sw_interface_set_unnumbered(ip_sw_if_index,
                                                   self.sw_if_index, is_add=0)
        return self

    def set_proxy_arp(self, enable=1):
        """ Set the interface to enable/disable Proxy ARP """
        self.test.vapi.proxy_arp_intfc_enable_disable(
            sw_if_index=self.sw_if_index,
            enable=enable)
        return self

    def query_vpp_config(self):
        dump = self.test.vapi.sw_interface_dump(sw_if_index=self.sw_if_index)
        return self.is_interface_config_in_dump(dump)

    def get_interface_config_from_dump(self, dump):
        for i in dump:
            if i.interface_name.rstrip(' \t\r\n\0') == self.name and \
                    i.sw_if_index == self.sw_if_index:
                return i
        else:
            return None

    def is_interface_config_in_dump(self, dump):
        return self.get_interface_config_from_dump(dump) is not None

    def assert_interface_state(self, admin_up_down, link_up_down,
                               expect_event=False):
        if expect_event:
            event = self.test.vapi.wait_for_event(timeout=1,
                                                  name='sw_interface_event')
            self.test.assert_equal(event.sw_if_index, self.sw_if_index,
                                   "sw_if_index")
            self.test.assert_equal((event.flags & 1), admin_up_down,
                                   "admin state")
            self.test.assert_equal((event.flags & 2), link_up_down,
                                   "link state")
        dump = self.test.vapi.sw_interface_dump()
        if_state = self.get_interface_config_from_dump(dump)
        self.test.assert_equal((if_state.flags & 1), admin_up_down,
                               "admin state")
        self.test.assert_equal((if_state.flags & 2), link_up_down,
                               "link state")

    def __str__(self):
        return self.name

    def get_rx_stats(self):
        return (self.test.statistics["/if/rx"]
                [:, self.sw_if_index].sum_packets())

    def get_tx_stats(self):
        return (self.test.statistics["/if/tx"]
                [:, self.sw_if_index].sum_packets())

    def set_l3_mtu(self, mtu):
        self.test.vapi.sw_interface_set_mtu(self.sw_if_index, [mtu, 0, 0, 0])
        return self

    def set_ip4_mtu(self, mtu):
        self.test.vapi.sw_interface_set_mtu(self.sw_if_index, [0, mtu, 0, 0])
        return self

    def set_ip6_mtu(self, mtu):
        self.test.vapi.sw_interface_set_mtu(self.sw_if_index, [0, 0, mtu, 0])
        return self

    def set_mpls_mtu(self, mtu):
        self.test.vapi.sw_interface_set_mtu(self.sw_if_index, [0, 0, 0, mtu])
        return self
