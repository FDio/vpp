from scapy.layers.dhcp6 import DHCP6_Advertise, DHCP6OptClientId, \
    DHCP6OptStatusCode, DHCP6OptPref, DHCP6OptIA_PD, DHCP6OptIAPrefix, \
    DHCP6OptServerId, DHCP6_Solicit, DHCP6_Reply, DHCP6_Request, DHCP6_Renew, \
    DHCP6_Rebind, DUID_LL, DHCP6_Release, DHCP6OptElapsedTime, DHCP6OptIA_NA, \
    DHCP6OptIAAddress
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


class TestDHCPv6DataPlane(VppTestCase):
    """ DHCPv6 Data Plane Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestDHCPv6DataPlane, cls).setUpClass()

    def setUp(self):
        super(TestDHCPv6DataPlane, self).setUp()

        self.create_pg_interfaces(range(1))
        self.interfaces = list(self.pg_interfaces)
        for i in self.interfaces:
            i.admin_up()
            i.config_ip6()

        self.server_duid = DUID_LL(lladdr=self.pg0.remote_mac)

    def tearDown(self):
        for i in self.interfaces:
            i.unconfig_ip6()
            i.admin_down()
        super(TestDHCPv6DataPlane, self).tearDown()

    def test_dhcp_ia_na_send_solicit_receive_advertise(self):
        """ Verify DHCPv6 IA NA Solicit packet and Advertise envent """

        self.vapi.dhcp6_clients_enable_disable()

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        address_bin = '\00\01\00\02\00\03' + '\00' * 8 + '\00\05'
        address = {'address': address_bin,
                   'preferred_time': 60,
                   'valid_time': 120}
        self.vapi.dhcp6_send_client_message(1, self.pg0.sw_if_index,
                                            T1=20, T2=40, addresses=[address])
        rx_list = self.pg0.get_capture(1)
        self.assertEqual(len(rx_list), 1)
        packet = rx_list[0]

        self.assertTrue(packet.haslayer(IPv6))
        self.assertTrue(packet[IPv6].haslayer(DHCP6_Solicit))

        client_duid = packet[DHCP6OptClientId].duid
        trid = packet[DHCP6_Solicit].trid

        dst = ip6_normalize(packet[IPv6].dst)
        dst2 = ip6_normalize("ff02::1:2")
        self.assert_equal(dst, dst2)
        src = ip6_normalize(packet[IPv6].src)
        src2 = ip6_normalize(self.pg0.local_ip6_ll)
        self.assert_equal(src, src2)
        ia_na = packet[DHCP6OptIA_NA]
        self.assert_equal(ia_na.T1, 20)
        self.assert_equal(ia_na.T2, 40)
        self.assert_equal(len(ia_na.ianaopts), 1)
        address = ia_na.ianaopts[0]
        self.assert_equal(address.addr, '1:2:3::5')
        self.assert_equal(address.preflft, 60)
        self.assert_equal(address.validlft, 120)

        self.vapi.want_dhcp6_reply_events()

        try:
            ia_na_opts = DHCP6OptIAAddress(addr='7:8::2', preflft=60,
                                           validlft=120)
            p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
                 IPv6(src=mk_ll_addr(self.pg0.remote_mac),
                      dst=self.pg0.local_ip6_ll) /
                 UDP(sport=547, dport=546) /
                 DHCP6_Advertise(trid=trid) /
                 DHCP6OptServerId(duid=self.server_duid) /
                 DHCP6OptClientId(duid=client_duid) /
                 DHCP6OptPref(prefval=7) /
                 DHCP6OptStatusCode(statuscode=1) /
                 DHCP6OptIA_NA(iaid=1, T1=20, T2=40, ianaopts=ia_na_opts)
                 )
            self.pg0.add_stream([p])
            self.pg_start()

            ev = self.vapi.wait_for_event(1, "dhcp6_reply_event")

            self.assert_equal(ev.preference, 7)
            self.assert_equal(ev.status_code, 1)
            self.assert_equal(ev.T1, 20)
            self.assert_equal(ev.T2, 40)

            reported_address = ev.addresses[0]
            address = inet_pton(AF_INET6, ia_na_opts.getfieldval("addr"))
            self.assert_equal(reported_address.address, address)
            self.assert_equal(reported_address.preferred_time,
                              ia_na_opts.getfieldval("preflft"))
            self.assert_equal(reported_address.valid_time,
                              ia_na_opts.getfieldval("validlft"))

        finally:
            self.vapi.want_dhcp6_reply_events(enable_disable=0)

    def test_dhcp_pd_send_solicit_receive_advertise(self):
        """ Verify DHCPv6 PD Solicit packet and Advertise envent """

        self.vapi.dhcp6_clients_enable_disable()

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

        client_duid = packet[DHCP6OptClientId].duid
        trid = packet[DHCP6_Solicit].trid

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

        self.vapi.want_dhcp6_pd_reply_events()

        try:
            ia_pd_opts = DHCP6OptIAPrefix(prefix='7:8::', plen=56, preflft=60,
                                          validlft=120)
            p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
                 IPv6(src=mk_ll_addr(self.pg0.remote_mac),
                      dst=self.pg0.local_ip6_ll) /
                 UDP(sport=547, dport=546) /
                 DHCP6_Advertise(trid=trid) /
                 DHCP6OptServerId(duid=self.server_duid) /
                 DHCP6OptClientId(duid=client_duid) /
                 DHCP6OptPref(prefval=7) /
                 DHCP6OptStatusCode(statuscode=1) /
                 DHCP6OptIA_PD(iaid=1, T1=20, T2=40, iapdopt=ia_pd_opts)
                 )
            self.pg0.add_stream([p])
            self.pg_start()

            ev = self.vapi.wait_for_event(1, "dhcp6_pd_reply_event")

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

        finally:
            self.vapi.want_dhcp6_pd_reply_events(enable_disable=0)


class TestDHCPv6IANAControlPlane(VppTestCase):
    """ DHCPv6 IA NA Control Plane Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestDHCPv6IANAControlPlane, cls).setUpClass()

    def setUp(self):
        super(TestDHCPv6IANAControlPlane, self).setUp()

        self.create_pg_interfaces(range(1))
        self.interfaces = list(self.pg_interfaces)
        for i in self.interfaces:
            i.admin_up()

        self.server_duid = DUID_LL(lladdr=self.pg0.remote_mac)
        self.client_duid = None
        self.T1 = 1
        self.T2 = 2

        fib = self.vapi.ip6_fib_dump()
        self.initial_addresses = set(self.get_interface_addresses(fib,
                                                                  self.pg0))

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        self.vapi.dhcp6_client_enable_disable(self.pg0.sw_if_index)

    def tearDown(self):
        self.vapi.dhcp6_client_enable_disable(self.pg0.sw_if_index, enable=0)

        for i in self.interfaces:
            i.admin_down()

        super(TestDHCPv6IANAControlPlane, self).tearDown()

    @staticmethod
    def get_interface_addresses(fib, pg):
        lst = []
        for entry in fib:
            if entry.address_length == 128:
                path = entry.path[0]
                if path.sw_if_index == pg.sw_if_index:
                    lst.append(entry.address)
        return lst

    def get_addresses(self):
        fib = self.vapi.ip6_fib_dump()
        addresses = set(self.get_interface_addresses(fib, self.pg0))
        return addresses.difference(self.initial_addresses)

    def validate_duid_ll(self, duid):
        DUID_LL(duid)

    def validate_packet(self, packet, msg_type, is_resend=False):
        try:
            self.assertTrue(packet.haslayer(msg_type))
            client_duid = packet[DHCP6OptClientId].duid
            if self.client_duid is None:
                self.client_duid = client_duid
                self.validate_duid_ll(client_duid)
            else:
                self.assertEqual(self.client_duid, client_duid)
            if msg_type != DHCP6_Solicit and msg_type != DHCP6_Rebind:
                server_duid = packet[DHCP6OptServerId].duid
                self.assertEqual(server_duid, self.server_duid)
            if is_resend:
                self.assertEqual(self.trid, packet[msg_type].trid)
            else:
                self.trid = packet[msg_type].trid
            ip = packet[IPv6]
            udp = packet[UDP]
            self.assertEqual(ip.dst, 'ff02::1:2')
            self.assertEqual(udp.sport, 546)
            self.assertEqual(udp.dport, 547)
            dhcpv6 = packet[msg_type]
            elapsed_time = dhcpv6[DHCP6OptElapsedTime]
            if (is_resend):
                self.assertNotEqual(elapsed_time.elapsedtime, 0)
            else:
                self.assertEqual(elapsed_time.elapsedtime, 0)
        except:
            packet.show()
            raise

    def wait_for_packet(self, msg_type, timeout=None, is_resend=False):
        if timeout is None:
            timeout = 3
        rx_list = self.pg0.get_capture(1, timeout=timeout)
        packet = rx_list[0]
        self.validate_packet(packet, msg_type, is_resend=is_resend)

    def wait_for_solicit(self, timeout=None, is_resend=False):
        self.wait_for_packet(DHCP6_Solicit, timeout, is_resend=is_resend)

    def wait_for_request(self, timeout=None, is_resend=False):
        self.wait_for_packet(DHCP6_Request, timeout, is_resend=is_resend)

    def wait_for_renew(self, timeout=None, is_resend=False):
        self.wait_for_packet(DHCP6_Renew, timeout, is_resend=is_resend)

    def wait_for_rebind(self, timeout=None, is_resend=False):
        self.wait_for_packet(DHCP6_Rebind, timeout, is_resend=is_resend)

    def wait_for_release(self, timeout=None, is_resend=False):
        self.wait_for_packet(DHCP6_Release, timeout, is_resend=is_resend)

    def send_packet(self, msg_type, t1=None, t2=None, ianaopts=None):
        if t1 is None:
            t1 = self.T1
        if t2 is None:
            t2 = self.T2
        if ianaopts is None:
            opt_ia_na = DHCP6OptIA_NA(iaid=1, T1=t1, T2=t2)
        else:
            opt_ia_na = DHCP6OptIA_NA(iaid=1, T1=t1, T2=t2, ianaopts=ianaopts)
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IPv6(src=mk_ll_addr(self.pg0.remote_mac),
                  dst=self.pg0.local_ip6_ll) /
             UDP(sport=547, dport=546) /
             msg_type(trid=self.trid) /
             DHCP6OptServerId(duid=self.server_duid) /
             DHCP6OptClientId(duid=self.client_duid) /
             opt_ia_na
             )
        self.pg0.add_stream([p])
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

    def send_advertise(self, t1=None, t2=None, ianaopts=None):
        self.send_packet(DHCP6_Advertise, t1, t2, ianaopts)

    def send_reply(self, t1=None, t2=None, ianaopts=None):
        self.send_packet(DHCP6_Reply, t1, t2, ianaopts)

    def test_T1_and_T2_timeouts(self):
        """ Test T1 and T2 timeouts """

        self.wait_for_solicit()
        self.send_advertise()
        self.wait_for_request()
        self.send_reply()

        self.sleep(1)

        self.wait_for_renew()

        self.pg_enable_capture(self.pg_interfaces)

        self.sleep(1)

        self.wait_for_rebind()

    def test_addresses(self):
        """ Test handling of addresses """

        ia_na_opts = DHCP6OptIAAddress(addr='7:8::2', preflft=1,
                                       validlft=2)

        self.wait_for_solicit()
        self.send_advertise(t1=20, t2=40, ianaopts=ia_na_opts)
        self.wait_for_request()
        self.send_reply(t1=20, t2=40, ianaopts=ia_na_opts)
        self.sleep(0.1)

        # check FIB for new address
        new_addresses = self.get_addresses()
        self.assertEqual(len(new_addresses), 1)
        addr = list(new_addresses)[0]
        self.assertEqual(inet_ntop(AF_INET6, addr), '7:8::2')

        self.sleep(2)

        # check that the address is deleted
        fib = self.vapi.ip6_fib_dump()
        addresses = set(self.get_interface_addresses(fib, self.pg0))
        new_addresses = addresses.difference(self.initial_addresses)
        self.assertEqual(len(new_addresses), 0)

    def test_sending_client_messages_solicit(self):
        """ VPP receives messages from DHCPv6 client """

        self.wait_for_solicit()
        self.send_packet(DHCP6_Solicit)
        self.send_packet(DHCP6_Request)
        self.send_packet(DHCP6_Renew)
        self.send_packet(DHCP6_Rebind)
        self.sleep(1)
        self.wait_for_solicit(is_resend=True)

    def test_sending_inappropriate_packets(self):
        """ Server sends messages with inappropriate message types """

        self.wait_for_solicit()
        self.send_reply()
        self.wait_for_solicit(is_resend=True)
        self.send_advertise()
        self.wait_for_request()
        self.send_advertise()
        self.wait_for_request(is_resend=True)
        self.send_reply()
        self.wait_for_renew()

    def test_no_address_available_in_advertise(self):
        """ Advertise message contains NoAddrsAvail status code """

        self.wait_for_solicit()
        noavail = DHCP6OptStatusCode(statuscode=2)  # NoAddrsAvail
        self.send_advertise(ianaopts=noavail)
        self.wait_for_solicit(is_resend=True)

    def test_preferred_greater_than_valit_lifetime(self):
        """ Preferred lifetime is greater than valid lifetime """

        self.wait_for_solicit()
        self.send_advertise()
        self.wait_for_request()
        ia_na_opts = DHCP6OptIAAddress(addr='7:8::2', preflft=4, validlft=3)
        self.send_reply(ianaopts=ia_na_opts)

        self.sleep(0.5)

        # check FIB contains no addresses
        fib = self.vapi.ip6_fib_dump()
        addresses = set(self.get_interface_addresses(fib, self.pg0))
        new_addresses = addresses.difference(self.initial_addresses)
        self.assertEqual(len(new_addresses), 0)

    def test_T1_greater_than_T2(self):
        """ T1 is greater than T2 """

        self.wait_for_solicit()
        self.send_advertise()
        self.wait_for_request()
        ia_na_opts = DHCP6OptIAAddress(addr='7:8::2', preflft=4, validlft=8)
        self.send_reply(t1=80, t2=40, ianaopts=ia_na_opts)

        self.sleep(0.5)

        # check FIB contains no addresses
        fib = self.vapi.ip6_fib_dump()
        addresses = set(self.get_interface_addresses(fib, self.pg0))
        new_addresses = addresses.difference(self.initial_addresses)
        self.assertEqual(len(new_addresses), 0)


class TestDHCPv6PDControlPlane(VppTestCase):
    """ DHCPv6 PD Control Plane Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestDHCPv6PDControlPlane, cls).setUpClass()

    def setUp(self):
        super(TestDHCPv6PDControlPlane, self).setUp()

        self.create_pg_interfaces(range(2))
        self.interfaces = list(self.pg_interfaces)
        for i in self.interfaces:
            i.admin_up()

        self.server_duid = DUID_LL(lladdr=self.pg0.remote_mac)
        self.client_duid = None
        self.T1 = 1
        self.T2 = 2

        fib = self.vapi.ip6_fib_dump()
        self.initial_addresses = set(self.get_interface_addresses(fib,
                                                                  self.pg1))

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        self.prefix_group = 'my-pd-prefix-group'

        self.vapi.dhcp6_pd_client_enable_disable(
            self.pg0.sw_if_index,
            prefix_group=self.prefix_group)

    def tearDown(self):
        self.vapi.dhcp6_pd_client_enable_disable(self.pg0.sw_if_index,
                                                 enable=0)

        for i in self.interfaces:
            i.admin_down()

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

    def get_addresses(self):
        fib = self.vapi.ip6_fib_dump()
        addresses = set(self.get_interface_addresses(fib, self.pg1))
        return addresses.difference(self.initial_addresses)

    def validate_duid_ll(self, duid):
        DUID_LL(duid)

    def validate_packet(self, packet, msg_type, is_resend=False):
        try:
            self.assertTrue(packet.haslayer(msg_type))
            client_duid = packet[DHCP6OptClientId].duid
            if self.client_duid is None:
                self.client_duid = client_duid
                self.validate_duid_ll(client_duid)
            else:
                self.assertEqual(self.client_duid, client_duid)
            if msg_type != DHCP6_Solicit and msg_type != DHCP6_Rebind:
                server_duid = packet[DHCP6OptServerId].duid
                self.assertEqual(server_duid, self.server_duid)
            if is_resend:
                self.assertEqual(self.trid, packet[msg_type].trid)
            else:
                self.trid = packet[msg_type].trid
            ip = packet[IPv6]
            udp = packet[UDP]
            self.assertEqual(ip.dst, 'ff02::1:2')
            self.assertEqual(udp.sport, 546)
            self.assertEqual(udp.dport, 547)
            dhcpv6 = packet[msg_type]
            elapsed_time = dhcpv6[DHCP6OptElapsedTime]
            if (is_resend):
                self.assertNotEqual(elapsed_time.elapsedtime, 0)
            else:
                self.assertEqual(elapsed_time.elapsedtime, 0)
        except:
            packet.show()
            raise

    def wait_for_packet(self, msg_type, timeout=None, is_resend=False):
        if timeout is None:
            timeout = 3
        rx_list = self.pg0.get_capture(1, timeout=timeout)
        packet = rx_list[0]
        self.validate_packet(packet, msg_type, is_resend=is_resend)

    def wait_for_solicit(self, timeout=None, is_resend=False):
        self.wait_for_packet(DHCP6_Solicit, timeout, is_resend=is_resend)

    def wait_for_request(self, timeout=None, is_resend=False):
        self.wait_for_packet(DHCP6_Request, timeout, is_resend=is_resend)

    def wait_for_renew(self, timeout=None, is_resend=False):
        self.wait_for_packet(DHCP6_Renew, timeout, is_resend=is_resend)

    def wait_for_rebind(self, timeout=None, is_resend=False):
        self.wait_for_packet(DHCP6_Rebind, timeout, is_resend=is_resend)

    def wait_for_release(self, timeout=None, is_resend=False):
        self.wait_for_packet(DHCP6_Release, timeout, is_resend=is_resend)

    def send_packet(self, msg_type, t1=None, t2=None, iapdopt=None):
        if t1 is None:
            t1 = self.T1
        if t2 is None:
            t2 = self.T2
        if iapdopt is None:
            opt_ia_pd = DHCP6OptIA_PD(iaid=1, T1=t1, T2=t2)
        else:
            opt_ia_pd = DHCP6OptIA_PD(iaid=1, T1=t1, T2=t2, iapdopt=iapdopt)
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IPv6(src=mk_ll_addr(self.pg0.remote_mac),
                  dst=self.pg0.local_ip6_ll) /
             UDP(sport=547, dport=546) /
             msg_type(trid=self.trid) /
             DHCP6OptServerId(duid=self.server_duid) /
             DHCP6OptClientId(duid=self.client_duid) /
             opt_ia_pd
             )
        self.pg0.add_stream([p])
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

    def send_advertise(self, t1=None, t2=None, iapdopt=None):
        self.send_packet(DHCP6_Advertise, t1, t2, iapdopt)

    def send_reply(self, t1=None, t2=None, iapdopt=None):
        self.send_packet(DHCP6_Reply, t1, t2, iapdopt)

    def test_T1_and_T2_timeouts(self):
        """ Test T1 and T2 timeouts """

        self.wait_for_solicit()
        self.send_advertise()
        self.wait_for_request()
        self.send_reply()

        self.sleep(1)

        self.wait_for_renew()

        self.pg_enable_capture(self.pg_interfaces)

        self.sleep(1)

        self.wait_for_rebind()

    def test_prefixes(self):
        """ Test handling of prefixes """

        address_bin_1 = None
        address_bin_2 = None
        try:
            address_bin_1 = '\x00' * 6 + '\x00\x02' + '\x00' * 6 + '\x04\x05'
            address_prefix_length_1 = 60
            self.vapi.ip6_add_del_address_using_prefix(self.pg1.sw_if_index,
                                                       address_bin_1,
                                                       address_prefix_length_1,
                                                       self.prefix_group)

            ia_pd_opts = DHCP6OptIAPrefix(prefix='7:8::', plen=56, preflft=2,
                                          validlft=3)

            self.wait_for_solicit()
            self.send_advertise(t1=20, t2=40, iapdopt=ia_pd_opts)
            self.wait_for_request()
            self.send_reply(t1=20, t2=40, iapdopt=ia_pd_opts)
            self.sleep(0.1)

            # check FIB for new address
            new_addresses = self.get_addresses()
            self.assertEqual(len(new_addresses), 1)
            addr = list(new_addresses)[0]
            self.assertEqual(inet_ntop(AF_INET6, addr), '7:8:0:2::405')

            self.sleep(1)

            address_bin_2 = '\x00' * 6 + '\x00\x76' + '\x00' * 6 + '\x04\x06'
            address_prefix_length_2 = 62
            self.vapi.ip6_add_del_address_using_prefix(self.pg1.sw_if_index,
                                                       address_bin_2,
                                                       address_prefix_length_2,
                                                       self.prefix_group)

            self.sleep(1)

            # check FIB contains 2 addresses
            fib = self.vapi.ip6_fib_dump()
            addresses = set(self.get_interface_addresses(fib, self.pg1))
            new_addresses = addresses.difference(self.initial_addresses)
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
            new_addresses = addresses.difference(self.initial_addresses)
            self.assertEqual(len(new_addresses), 0)

        finally:
            if address_bin_1 is not None:
                self.vapi.ip6_add_del_address_using_prefix(
                    self.pg1.sw_if_index, address_bin_1,
                    address_prefix_length_1, self.prefix_group, is_add=0)
            if address_bin_2 is not None:
                self.vapi.ip6_add_del_address_using_prefix(
                    self.pg1.sw_if_index, address_bin_2,
                    address_prefix_length_2, self.prefix_group, is_add=0)

    def test_sending_client_messages_solicit(self):
        """ VPP receives messages from DHCPv6 client """

        self.wait_for_solicit()
        self.send_packet(DHCP6_Solicit)
        self.send_packet(DHCP6_Request)
        self.send_packet(DHCP6_Renew)
        self.send_packet(DHCP6_Rebind)
        self.sleep(1)
        self.wait_for_solicit(is_resend=True)

    def test_sending_inappropriate_packets(self):
        """ Server sends messages with inappropriate message types """

        self.wait_for_solicit()
        self.send_reply()
        self.wait_for_solicit(is_resend=True)
        self.send_advertise()
        self.wait_for_request()
        self.send_advertise()
        self.wait_for_request(is_resend=True)
        self.send_reply()
        self.wait_for_renew()

    def test_no_prefix_available_in_advertise(self):
        """ Advertise message contains NoPrefixAvail status code """

        self.wait_for_solicit()
        noavail = DHCP6OptStatusCode(statuscode=6)  # NoPrefixAvail
        self.send_advertise(iapdopt=noavail)
        self.wait_for_solicit(is_resend=True)

    def test_preferred_greater_than_valit_lifetime(self):
        """ Preferred lifetime is greater than valid lifetime """

        try:
            address_bin = '\x00' * 6 + '\x00\x02' + '\x00' * 6 + '\x04\x05'
            address_prefix_length = 60
            self.vapi.ip6_add_del_address_using_prefix(self.pg1.sw_if_index,
                                                       address_bin,
                                                       address_prefix_length,
                                                       self.prefix_group)

            self.wait_for_solicit()
            self.send_advertise()
            self.wait_for_request()
            ia_pd_opts = DHCP6OptIAPrefix(prefix='7:8::', plen=56, preflft=4,
                                          validlft=3)
            self.send_reply(iapdopt=ia_pd_opts)

            self.sleep(0.5)

            # check FIB contains no addresses
            fib = self.vapi.ip6_fib_dump()
            addresses = set(self.get_interface_addresses(fib, self.pg1))
            new_addresses = addresses.difference(self.initial_addresses)
            self.assertEqual(len(new_addresses), 0)

        finally:
            self.vapi.ip6_add_del_address_using_prefix(self.pg1.sw_if_index,
                                                       address_bin,
                                                       address_prefix_length,
                                                       self.prefix_group,
                                                       is_add=0)

    def test_T1_greater_than_T2(self):
        """ T1 is greater than T2 """

        try:
            address_bin = '\x00' * 6 + '\x00\x02' + '\x00' * 6 + '\x04\x05'
            address_prefix_length = 60
            self.vapi.ip6_add_del_address_using_prefix(self.pg1.sw_if_index,
                                                       address_bin,
                                                       address_prefix_length,
                                                       self.prefix_group)

            self.wait_for_solicit()
            self.send_advertise()
            self.wait_for_request()
            ia_pd_opts = DHCP6OptIAPrefix(prefix='7:8::', plen=56, preflft=4,
                                          validlft=8)
            self.send_reply(t1=80, t2=40, iapdopt=ia_pd_opts)

            self.sleep(0.5)

            # check FIB contains no addresses
            fib = self.vapi.ip6_fib_dump()
            addresses = set(self.get_interface_addresses(fib, self.pg1))
            new_addresses = addresses.difference(self.initial_addresses)
            self.assertEqual(len(new_addresses), 0)

        finally:
            self.vapi.ip6_add_del_address_using_prefix(self.pg1.sw_if_index,
                                                       address_bin,
                                                       address_prefix_length,
                                                       self.prefix_group,
                                                       is_add=0)
