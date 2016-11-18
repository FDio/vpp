from abc import abstractmethod, ABCMeta
import socket


class VppInterface(object):
    """Generic VPP interface."""
    __metaclass__ = ABCMeta

    @property
    def sw_if_index(self):
        """Interface index assigned by VPP."""
        return self._sw_if_index

    @property
    def remote_mac(self):
        """MAC-address of the remote interface "connected" to this interface."""
        return self._remote_hosts[0].mac

    @property
    def local_mac(self):
        """MAC-address of the VPP interface."""
        return self._local_mac

    @property
    def local_ip4(self):
        """Local IPv4 address on VPP interface (string)."""
        return self._local_ip4

    @property
    def local_ip4n(self):
        """Local IPv4 address - raw, suitable as API parameter."""
        return socket.inet_pton(socket.AF_INET, self._local_ip4)

    @property
    def remote_ip4(self):
        """IPv4 address of remote peer "connected" to this interface."""
        return self._remote_hosts[0].ip4

    @property
    def remote_ip4n(self):
        """IPv4 address of remote peer - raw, suitable as API parameter."""
        return socket.inet_pton(socket.AF_INET, self.remote_ip4)

    @property
    def local_ip6(self):
        """Local IPv6 address on VPP interface (string)."""
        return self._local_ip6

    @property
    def local_ip6n(self):
        """Local IPv6 address - raw, suitable as API parameter."""
        return socket.inet_pton(socket.AF_INET6, self.local_ip6)

    @property
    def remote_ip6(self):
        """IPv6 address of remote peer "connected" to this interface."""
        return self._remote_hosts[0].ip6

    @property
    def remote_ip6n(self):
        """IPv6 address of remote peer - raw, suitable as API parameter"""
        return socket.inet_pton(socket.AF_INET6, self.remote_ip6)

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
            ip6 = "fd01:%04x::%04x" % (self.sw_if_index, i)
            host = Host(mac, ip4, ip6)
            self._remote_hosts.append(host)
            self._hosts_by_mac[mac] = host
            self._hosts_by_ip4[ip4] = host
            self._hosts_by_ip6[ip6] = host

    @abstractmethod
    def __init__(self, test):
        self._test = test

        self._remote_hosts = []
        self._hosts_by_mac = {}
        self._hosts_by_ip4 = {}
        self._hosts_by_ip6 = {}

        self.generate_remote_hosts()

        self._local_ip4 = "172.16.%u.1" % self.sw_if_index
        self._local_ip4n = socket.inet_pton(socket.AF_INET, self.local_ip4)

        self._local_ip6 = "fd01:%04x::1" % self.sw_if_index
        self._local_ip6n = socket.inet_pton(socket.AF_INET6, self.local_ip6)

        r = self.test.vapi.sw_interface_dump()
        for intf in r:
            if intf.sw_if_index == self.sw_if_index:
                self._name = intf.interface_name.split(b'\0', 1)[0]
                self._local_mac =\
                    ':'.join(intf.l2_address.encode('hex')[i:i + 2]
                             for i in range(0, 12, 2))
                self._dump = intf
                break
        else:
            raise Exception(
                "Could not find interface with sw_if_index %d "
                "in interface dump %s" %
                (self.sw_if_index, repr(r)))

    def config_ip4(self):
        """Configure IPv4 address on the VPP interface."""
        addr = self.local_ip4n
        addr_len = 24
        self.test.vapi.sw_interface_add_del_address(
            self.sw_if_index, addr, addr_len)
        self.has_ip4_config = True

    def unconfig_ip4(self):
        """Remove IPv4 address on the VPP interface"""
        try:
            if (self.has_ip4_config):
                self.test.vapi.sw_interface_add_del_address(
                    self.sw_if_index,
                    self.local_ip4n,
                    24, is_add=0)
        except AttributeError:
            self.has_ip4_config = False
        self.has_ip4_config = False

    def configure_ipv4_neighbors(self):
        """For every remote host assign neighbor's MAC to IPv4 addresses."""
        for host in self._remote_hosts:
            macn = host.mac.replace(":", "").decode('hex')
            ipn = host.ip4n
            self.test.vapi.ip_neighbor_add_del(self.sw_if_index, macn, ipn)

    def config_ip6(self):
        """Configure IPv6 address on the VPP interface."""
        addr = self._local_ip6n
        addr_len = 64
        self.test.vapi.sw_interface_add_del_address(
            self.sw_if_index, addr, addr_len, is_ipv6=1)
        self.has_ip6_config = True

    def unconfig_ip6(self):
        """Remove IPv6 address on the VPP interface"""
        try:
            if (self.has_ip6_config):
                self.test.vapi.sw_interface_add_del_address(
                    self.sw_if_index,
                    self.local_ip6n,
                    64, is_ipv6=1, is_add=0)
        except AttributeError:
            self.has_ip6_config = False
        self.has_ip6_config = False

    def unconfig(self):
        """Unconfigure IPv6 and IPv4 address on the VPP interface"""
        self.unconfig_ip4()
        self.unconfig_ip6()

    def set_table_ip4(self, table_id):
        """Set the interface in a IPv4 Table.

        .. note:: Must be called before configuring IP4 addresses."""
        self.test.vapi.sw_interface_set_table(
            self.sw_if_index, 0, table_id)

    def set_table_ip6(self, table_id):
        """Set the interface in a IPv6 Table.

        .. note:: Must be called before configuring IP6 addresses.
        """
        self.test.vapi.sw_interface_set_table(
            self.sw_if_index, 1, table_id)

    def disable_ipv6_ra(self):
        """Configure IPv6 RA suppress on the VPP interface."""
        self.test.vapi.sw_interface_ra_suppress(self.sw_if_index)

    def admin_up(self):
        """Put interface ADMIN-UP."""
        self.test.vapi.sw_interface_set_flags(self.sw_if_index, admin_up_down=1)

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

    def enable_mpls(self):
        """Enable MPLS on the VPP interface."""
        self.test.vapi.sw_interface_enable_disable_mpls(
            self.sw_if_index)
