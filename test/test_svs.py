#!/usr/bin/env python

from framework import VppTestCase, VppTestRunner
from vpp_ip_route import VppIpTable

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, ICMP
from scapy.layers.inet6 import IPv6

from vpp_papi import VppEnum


class TestSVS(VppTestCase):
    """ SVS Test Case """

    def setUp(self):
        super(TestSVS, self).setUp()

        # create 2 pg interfaces
        self.create_pg_interfaces(range(4))

        table_id = 0

        for i in self.pg_interfaces:
            i.admin_up()

            if table_id != 0:
                tbl = VppIpTable(self, table_id)
                tbl.add_vpp_config()
                tbl = VppIpTable(self, table_id, is_ip6=1)
                tbl.add_vpp_config()

            i.set_table_ip4(table_id)
            i.set_table_ip6(table_id)
            i.config_ip4()
            i.resolve_arp()
            i.config_ip6()
            i.resolve_ndp()
            table_id += 1

    def tearDown(self):
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.unconfig_ip6()
            i.ip6_disable()
            i.set_table_ip4(0)
            i.set_table_ip6(0)
            i.admin_down()
        super(TestSVS, self).tearDown()

    def test_svs4(self):
        """ Source VRF Select IP4 """

        #
        # packets destinet out of the 3 non-default table interfaces
        #
        pkts_0 = [(Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                   IP(src="1.1.1.1", dst=self.pg1.remote_ip4) /
                   UDP(sport=1234, dport=1234) /
                   Raw('\xa5' * 100)),
                  (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                   IP(src="2.2.2.2", dst=self.pg2.remote_ip4) /
                   UDP(sport=1234, dport=1234) /
                   Raw('\xa5' * 100)),
                  (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                   IP(src="3.3.3.3", dst=self.pg3.remote_ip4) /
                   UDP(sport=1234, dport=1234) /
                   Raw('\xa5' * 100))]
        pkts_1 = [(Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
                   IP(src="1.1.1.1", dst=self.pg1.remote_ip4) /
                   UDP(sport=1234, dport=1234) /
                   Raw('\xa5' * 100)),
                  (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
                   IP(src="2.2.2.2", dst=self.pg2.remote_ip4) /
                   UDP(sport=1234, dport=1234) /
                   Raw('\xa5' * 100)),
                  (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
                   IP(src="3.3.3.3", dst=self.pg3.remote_ip4) /
                   UDP(sport=1234, dport=1234) /
                   Raw('\xa5' * 100))]

        #
        # before adding the SVS config all these packets are dropped when
        # ingressing on pg0 since pg0 is in the default table
        #
        for p in pkts_0:
            self.send_and_assert_no_replies(self.pg0, p * 1)

        #
        # Add table 1001 & 1002 into which we'll add the routes
        # determing the source VRF selection
        #
        table_ids = [101, 102]

        for table_id in table_ids:
            self.vapi.svs_table_add_del(
                VppEnum.vl_api_address_family_t.ADDRESS_IP4, table_id)

            #
            # map X.0.0.0/8 to each SVS table for lookup in table X
            #
            for i in range(1, 4):
                self.vapi.svs_route_add_del(
                    table_id, "%d.0.0.0/8" % i, i)

        #
        # Enable SVS on pg0/pg1 using table 1001/1002
        #
        self.vapi.svs_enable_disable(
            VppEnum.vl_api_address_family_t.ADDRESS_IP4, table_ids[0],
            self.pg0.sw_if_index)
        self.vapi.svs_enable_disable(
            VppEnum.vl_api_address_family_t.ADDRESS_IP4, table_ids[1],
            self.pg1.sw_if_index)

        #
        # now all the packets should be delivered out the respective interface
        #
        self.send_and_expect(self.pg0, pkts_0[0] * 65, self.pg1)
        self.send_and_expect(self.pg0, pkts_0[1] * 65, self.pg2)
        self.send_and_expect(self.pg0, pkts_0[2] * 65, self.pg3)
        self.send_and_expect(self.pg1, pkts_1[0] * 65, self.pg1)
        self.send_and_expect(self.pg1, pkts_1[1] * 65, self.pg2)
        self.send_and_expect(self.pg1, pkts_1[2] * 65, self.pg3)

        #
        # check that if the SVS lookup does not match a route the packet
        # is forwarded using the interface's routing table
        #
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg0.remote_ip4) /
             UDP(sport=1234, dport=1234) /
             Raw('\xa5' * 100))
        self.send_and_expect(self.pg0, p * 65, self.pg0)

        p = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
             IP(src=self.pg1.remote_ip4, dst=self.pg1.remote_ip4) /
             UDP(sport=1234, dport=1234) /
             Raw('\xa5' * 100))
        self.send_and_expect(self.pg1, p * 65, self.pg1)

        #
        # dump the SVS configs
        #
        ss = self.vapi.svs_dump()

        self.assertEqual(ss[0].table_id, table_ids[0])
        self.assertEqual(ss[0].sw_if_index, self.pg0.sw_if_index)
        self.assertEqual(ss[0].af, VppEnum.vl_api_address_family_t.ADDRESS_IP4)
        self.assertEqual(ss[1].table_id, table_ids[1])
        self.assertEqual(ss[1].sw_if_index, self.pg1.sw_if_index)
        self.assertEqual(ss[1].af, VppEnum.vl_api_address_family_t.ADDRESS_IP4)

        #
        # cleanup
        #
        self.vapi.svs_enable_disable(
            VppEnum.vl_api_address_family_t.ADDRESS_IP4,
            table_ids[0],
            self.pg0.sw_if_index,
            is_enable=0)
        self.vapi.svs_enable_disable(
            VppEnum.vl_api_address_family_t.ADDRESS_IP4,
            table_ids[1],
            self.pg1.sw_if_index,
            is_enable=0)

        for table_id in table_ids:
            for i in range(1, 4):
                self.vapi.svs_route_add_del(
                    table_id, "%d.0.0.0/8" % i,
                    0, is_add=0)
            self.vapi.svs_table_add_del(
                VppEnum.vl_api_address_family_t.ADDRESS_IP4,
                table_id,
                is_add=0)

    def test_svs6(self):
        """ Source VRF Select IP6 """

        #
        # packets destinet out of the 3 non-default table interfaces
        #
        pkts_0 = [(Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                   IPv6(src="2001:1::1", dst=self.pg1.remote_ip6) /
                   UDP(sport=1234, dport=1234) /
                   Raw('\xa5' * 100)),
                  (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                   IPv6(src="2001:2::1", dst=self.pg2.remote_ip6) /
                   UDP(sport=1234, dport=1234) /
                   Raw('\xa5' * 100)),
                  (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                   IPv6(src="2001:3::1", dst=self.pg3.remote_ip6) /
                   UDP(sport=1234, dport=1234) /
                   Raw('\xa5' * 100))]
        pkts_1 = [(Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
                   IPv6(src="2001:1::1", dst=self.pg1.remote_ip6) /
                   UDP(sport=1234, dport=1234) /
                   Raw('\xa5' * 100)),
                  (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
                   IPv6(src="2001:2::1", dst=self.pg2.remote_ip6) /
                   UDP(sport=1234, dport=1234) /
                   Raw('\xa5' * 100)),
                  (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
                   IPv6(src="2001:3::1", dst=self.pg3.remote_ip6) /
                   UDP(sport=1234, dport=1234) /
                   Raw('\xa5' * 100))]

        #
        # before adding the SVS config all these packets are dropped when
        # ingressing on pg0 since pg0 is in the default table
        #
        for p in pkts_0:
            self.send_and_assert_no_replies(self.pg0, p * 1)

        #
        # Add table 1001 & 1002 into which we'll add the routes
        # determing the source VRF selection
        #
        table_ids = [101, 102]

        for table_id in table_ids:
            self.vapi.svs_table_add_del(
                VppEnum.vl_api_address_family_t.ADDRESS_IP6, table_id)

            #
            # map X.0.0.0/8 to each SVS table for lookup in table X
            #
            for i in range(1, 4):
                self.vapi.svs_route_add_del(
                    table_id, "2001:%d::/32" % i,
                    i)

        #
        # Enable SVS on pg0/pg1 using table 1001/1002
        #
        self.vapi.svs_enable_disable(
            VppEnum.vl_api_address_family_t.ADDRESS_IP6,
            table_ids[0],
            self.pg0.sw_if_index)
        self.vapi.svs_enable_disable(
            VppEnum.vl_api_address_family_t.ADDRESS_IP6,
            table_ids[1],
            self.pg1.sw_if_index)

        #
        # now all the packets should be delivered out the respective interface
        #
        self.send_and_expect(self.pg0, pkts_0[0] * 65, self.pg1)
        self.send_and_expect(self.pg0, pkts_0[1] * 65, self.pg2)
        self.send_and_expect(self.pg0, pkts_0[2] * 65, self.pg3)
        self.send_and_expect(self.pg1, pkts_1[0] * 65, self.pg1)
        self.send_and_expect(self.pg1, pkts_1[1] * 65, self.pg2)
        self.send_and_expect(self.pg1, pkts_1[2] * 65, self.pg3)

        #
        # check that if the SVS lookup does not match a route the packet
        # is forwarded using the interface's routing table
        #
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IPv6(src=self.pg0.remote_ip6, dst=self.pg0.remote_ip6) /
             UDP(sport=1234, dport=1234) /
             Raw('\xa5' * 100))
        self.send_and_expect(self.pg0, p * 65, self.pg0)

        p = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
             IPv6(src=self.pg1.remote_ip6, dst=self.pg1.remote_ip6) /
             UDP(sport=1234, dport=1234) /
             Raw('\xa5' * 100))
        self.send_and_expect(self.pg1, p * 65, self.pg1)

        #
        # dump the SVS configs
        #
        ss = self.vapi.svs_dump()

        self.assertEqual(ss[0].table_id, table_ids[0])
        self.assertEqual(ss[0].sw_if_index, self.pg0.sw_if_index)
        self.assertEqual(ss[0].af, VppEnum.vl_api_address_family_t.ADDRESS_IP6)
        self.assertEqual(ss[1].table_id, table_ids[1])
        self.assertEqual(ss[1].sw_if_index, self.pg1.sw_if_index)
        self.assertEqual(ss[1].af, VppEnum.vl_api_address_family_t.ADDRESS_IP6)

        #
        # cleanup
        #
        self.vapi.svs_enable_disable(
            VppEnum.vl_api_address_family_t.ADDRESS_IP6,
            table_ids[0],
            self.pg0.sw_if_index,
            is_enable=0)
        self.vapi.svs_enable_disable(
            VppEnum.vl_api_address_family_t.ADDRESS_IP6,
            table_ids[1],
            self.pg1.sw_if_index,
            is_enable=0)
        for table_id in table_ids:
            for i in range(1, 4):
                self.vapi.svs_route_add_del(
                    table_id, "2001:%d::/32" % i,
                    0, is_add=0)
            self.vapi.svs_table_add_del(
                VppEnum.vl_api_address_family_t.ADDRESS_IP6,
                table_id,
                is_add=0)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
