from scapy.layers.dhcp6 import DHCP6_Advertise, DHCP6OptClientId, \
    DHCP6OptStatusCode, DHCP6OptPref, DHCP6OptIA_PD, DHCP6OptIAPrefix, \
    DHCP6OptServerId, DHCP6_Solicit, DHCP6_Reply, DHCP6_Request, DHCP6_Renew, \
    DHCP6_Rebind
from scapy.layers.inet6 import IPv6, Ether, UDP
from scapy.utils6 import in6_mactoifaceid
from scapy.utils import inet_ntop, inet_pton
from socket import AF_INET6
from framework import VppTestCase


def ip6_normalize(ip6):
    return inet_ntop(AF_INET6, inet_pton(AF_INET6, ip6))


def mk_ll_addr(mac):
    euid = in6_mactoifaceid(mac)
    addr = "fe80::" + euid
    return addr


class TestDHCPv6PD(VppTestCase):
    """ DHCPv6 PD Data Plane Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestDHCPv6PD, cls).setUpClass()

    def setUp(self):
        super(TestDHCPv6PD, self).setUp()
        self.create_pg_interfaces(range(1))
        self.interfaces = list(self.pg_interfaces)
        # setup all interfaces
        for i in self.interfaces:
            i.admin_up()
            i.config_ip6()

    def tearDown(self):
        for i in self.interfaces:
            i.unconfig_ip6()
            i.admin_down()
        super(TestDHCPv6PD, self).tearDown()

    def test_dhcp_send_solicit(self):
        """ Verify DHCPv6 PD Solicit packet """

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        prefix_bin = '\00\01\00\02\00\03' + '\00' * 10
        prefix = {'prefix': prefix_bin,
                  'prefix_length': 50,
                  'preferred_time': 60,
                  'valid_time': 120}
        self.vapi.dhcp6_pd_send_client_message(1, self.pg0.sw_if_index,
                                               T1=20, T2=40, prefixes=[prefix])
        rx_list = self.pg0.get_capture(1)
        self.assertEqual(len(rx_list), 1)
        packet = rx_list[0]
        self.assertTrue(packet.haslayer(IPv6))
        self.assertTrue(packet[IPv6].haslayer(DHCP6_Solicit))
        dst = ip6_normalize(packet[IPv6].dst)
        dst2 = ip6_normalize("ff02::1:2")
        self.assert_equal(dst, dst2)
        src = ip6_normalize(packet[IPv6].src)
        src2 = ip6_normalize(self.pg0.local_ip6_ll)
        self.assert_equal(src, src2)
        ia_pd = packet[DHCP6OptIA_PD]
        self.assert_equal(ia_pd.T1, 20)
        self.assert_equal(ia_pd.T2, 40)
        self.assert_equal(len(ia_pd.iapdopt), 1)
        prefix = ia_pd.iapdopt[0]
        self.assert_equal(prefix.prefix, '1:2:3::')
        self.assert_equal(prefix.plen, 50)
        self.assert_equal(prefix.preflft, 60)
        self.assert_equal(prefix.validlft, 120)

    def test_dhcp_receive_advertise(self):
        """ Verify events triggered by received DHCPv6 PD Advertise packet """

        self.vapi.want_dhcp6_pd_reply_events()
        self.vapi.dhcp6_clients_enable_disable()

        ia_pd_opts = DHCP6OptIAPrefix(prefix='7:8::', plen=56, preflft=60,
                                      validlft=120)
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IPv6(src=mk_ll_addr(self.pg0.remote_mac),
                  dst=self.pg0.local_ip6_ll) /
             UDP(sport=547, dport=546) /
             DHCP6_Advertise() /
             DHCP6OptServerId(duid='server') /
             DHCP6OptClientId(duid='default') /
             DHCP6OptPref(prefval=7) /
             DHCP6OptStatusCode(statuscode=1) /
             DHCP6OptIA_PD(iaid=2, T1=20, T2=40, iapdopt=ia_pd_opts)
             )
        self.pg0.add_stream([p])
        self.pg_start()

        ev = self.vapi.wait_for_event(10, "dhcp6_pd_reply_event")

        self.assert_equal(ev.preference, 7)
        self.assert_equal(ev.status_code, 1)
        self.assert_equal(ev.T1, 20)
        self.assert_equal(ev.T2, 40)

        reported_prefix = ev.prefixes[0]
        prefix = inet_pton(AF_INET6, ia_pd_opts.getfieldval("prefix"))
        self.assert_equal(reported_prefix.prefix, prefix)
        self.assert_equal(reported_prefix.prefix_length,
                          ia_pd_opts.getfieldval("plen"))
        self.assert_equal(reported_prefix.preferred_time,
                          ia_pd_opts.getfieldval("preflft"))
        self.assert_equal(reported_prefix.valid_time,
                          ia_pd_opts.getfieldval("validlft"))


class TestDHCPv6PDControlPlane(VppTestCase):
    """ DHCPv6 PD Control Plane Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestDHCPv6PDControlPlane, cls).setUpClass()

    def setUp(self):
        super(TestDHCPv6PDControlPlane, self).setUp()
        self.create_pg_interfaces(range(2))
        self.interfaces = list(self.pg_interfaces)
        # setup all interfaces
        for i in self.interfaces:
            i.admin_up()

    def tearDown(self):
        self.vapi.dhcp6_pd_client_enable_disable(self.pg0.sw_if_index, 0)
        super(TestDHCPv6PDControlPlane, self).tearDown()

    @staticmethod
    def get_interface_addresses(fib, pg):
        lst = []
        for entry in fib:
            if entry.address_length == 128:
                path = entry.path[0]
                if path.sw_if_index == pg.sw_if_index:
                    lst.append(entry.address)
        return lst

    def test_T1_and_T2_timeouts(self):
        self.vapi.dhcp6_pd_client_enable_disable(self.pg0.sw_if_index)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # wait for Solicit message
        rx_list = self.pg0.get_capture(1, timeout=3)
        packet = rx_list[0]
        self.assertTrue(packet.haslayer(DHCP6_Solicit))

        # send Advertise message
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IPv6(src=mk_ll_addr(self.pg0.remote_mac),
                  dst=self.pg0.local_ip6_ll) /
             UDP(sport=547, dport=546) /
             DHCP6_Advertise() /
             DHCP6OptServerId(duid='server') /
             DHCP6OptClientId(duid='default') /
             DHCP6OptIA_PD(iaid=2, T1=1, T2=2)
             )
        self.pg0.add_stream([p])
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # wait for Request message
        rx_list = self.pg0.get_capture(1)
        packet = rx_list[0]
        self.assertTrue(packet.haslayer(DHCP6_Request))

        # send Reply message
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IPv6(src=mk_ll_addr(self.pg0.remote_mac),
                  dst=self.pg0.local_ip6_ll) /
             UDP(sport=547, dport=546) /
             DHCP6_Reply() /
             DHCP6OptServerId(duid='server') /
             DHCP6OptClientId(duid='default') /
             DHCP6OptIA_PD(iaid=2, T1=1, T2=2)
             )
        self.pg0.add_stream([p])
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        self.sleep(1)

        # wait for Renew message
        rx_list = self.pg0.get_capture(1)
        packet = rx_list[0]
        self.assertTrue(packet.haslayer(DHCP6_Renew))

        self.pg_enable_capture(self.pg_interfaces)

        self.sleep(1)

        # wait for Rebind message
        rx_list = self.pg0.get_capture(1)
        packet = rx_list[0]
        self.assertTrue(packet.haslayer(DHCP6_Rebind))

    def test_prefixes(self):
        """ Test handling of prefixes """

        fib = self.vapi.ip6_fib_dump()
        initial_addresses = set(self.get_interface_addresses(fib, self.pg0))

        self.vapi.dhcp6_pd_client_enable_disable(self.pg0.sw_if_index)

        address_bin_1 = '\x00' * 6 + '\x00\x02' + '\x00' * 6 + '\x04\x05'
        address_prefix_length_1 = 60
        self.vapi.control_plane_ip6_address_add_del(self.pg1.sw_if_index,
                                                    address_bin_1,
                                                    address_prefix_length_1)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # wait for Solicit message
        rx_list = self.pg0.get_capture(1, timeout=3)
        packet = rx_list[0]
        self.assertTrue(packet.haslayer(DHCP6_Solicit))

        # send Advertise message
        ia_pd_opts = DHCP6OptIAPrefix(prefix='7:8::', plen=56, preflft=2,
                                      validlft=3)
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IPv6(src=mk_ll_addr(self.pg0.remote_mac),
                  dst=self.pg0.local_ip6_ll) /
             UDP(sport=547, dport=546) /
             DHCP6_Advertise() /
             DHCP6OptServerId(duid='server') /
             DHCP6OptClientId(duid='default') /
             DHCP6OptIA_PD(iaid=2, T1=20, T2=40, iapdopt=ia_pd_opts)
             )
        self.pg0.add_stream([p])
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # wait for Request message
        rx_list = self.pg0.get_capture(1)
        packet = rx_list[0]
        self.assertTrue(packet.haslayer(DHCP6_Request))

        # send Reply message
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IPv6(src=mk_ll_addr(self.pg0.remote_mac),
                  dst=self.pg0.local_ip6_ll) /
             UDP(sport=547, dport=546) /
             DHCP6_Reply() /
             DHCP6OptServerId(duid='server') /
             DHCP6OptClientId(duid='default') /
             DHCP6OptIA_PD(iaid=2, T1=20, T2=40, iapdopt=ia_pd_opts)
             )
        self.pg0.add_stream([p])
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        self.sleep(0.1)

        # check FIB for new address
        fib = self.vapi.ip6_fib_dump()
        addresses = set(self.get_interface_addresses(fib, self.pg1))
        new_addresses = addresses.difference(initial_addresses)
        self.assertEqual(len(new_addresses), 1)
        addr = list(new_addresses)[0]
        self.assertEqual(inet_ntop(AF_INET6, addr), '7:8:0:2::405')

        self.sleep(1)

        address_bin_2 = '\x00' * 6 + '\x00\x76' + '\x00' * 6 + '\x04\x06'
        address_prefix_length_2 = 62
        self.vapi.control_plane_ip6_address_add_del(self.pg1.sw_if_index,
                                                    address_bin_2,
                                                    address_prefix_length_2)

        self.sleep(1)

        # check FIB contains 2 addresses
        fib = self.vapi.ip6_fib_dump()
        addresses = set(self.get_interface_addresses(fib, self.pg1))
        new_addresses = addresses.difference(initial_addresses)
        self.assertEqual(len(new_addresses), 2)
        addr1 = list(new_addresses)[0]
        addr2 = list(new_addresses)[1]
        if inet_ntop(AF_INET6, addr1) == '7:8:0:76::406':
            addr1, addr2 = addr2, addr1
        self.assertEqual(inet_ntop(AF_INET6, addr1), '7:8:0:2::405')
        self.assertEqual(inet_ntop(AF_INET6, addr2), '7:8:0:76::406')

        self.sleep(1)

        # check that the addresses are deleted
        fib = self.vapi.ip6_fib_dump()
        addresses = set(self.get_interface_addresses(fib, self.pg1))
        new_addresses = addresses.difference(initial_addresses)
        self.assertEqual(len(new_addresses), 0)
