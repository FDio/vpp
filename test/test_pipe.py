#!/usr/bin/env python3
from socket import AF_INET, AF_INET6, inet_pton
import unittest
from ipaddress import IPv4Network

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP

from framework import VppTestCase, VppTestRunner
from vpp_interface import VppInterface
from vpp_ip_route import VppIpTable, VppIpRoute, VppRoutePath
from vpp_acl import AclRule, VppAcl, VppAclInterface

NUM_PKTS = 67


class VppPipe(VppInterface):
    """
    VPP Pipe
    """
    details_api = 'pipe_dump'

    @property
    def east(self):
        return self.result.pipe_sw_if_index[1]

    @property
    def west(self):
        return self.result.pipe_sw_if_index[0]

    def __init__(self, test, instance=None):
        super(VppPipe, self).__init__(test)
        self.instance = instance

    def add_vpp_config(self):
        self.result = self._test.vapi.pipe_create(
            user_instance=self.instance)
        self.set_sw_if_index(self.result.sw_if_index)

    def remove_vpp_config(self):
        self._test.vapi.pipe_delete(
            parent_sw_if_index=self.result.sw_if_index)

    def object_id(self):
        return "pipe-%d" % (self._sw_if_index)

    def set_unnumbered(self, ip_sw_if_index, is_add=True):
        self._test.vapi.sw_interface_set_unnumbered(ip_sw_if_index,
                                                    self.east, is_add)
        self._test.vapi.sw_interface_set_unnumbered(ip_sw_if_index,
                                                    self.west, is_add)

    def __repr__(self):
        return f"{self.__class__.__name__}({self.test}, " \
               f"instance={repr(self.instance)})"


class TestPipe(VppTestCase):
    """ Pipes """

    @classmethod
    def setUpClass(cls):
        super(TestPipe, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestPipe, cls).tearDownClass()

    def setUp(self):
        super(TestPipe, self).setUp()

        self.create_pg_interfaces(range(4))

        for i in self.pg_interfaces:
            i.admin_up()

    def tearDown(self):
        for i in self.pg_interfaces:
            i.admin_down()

        super(TestPipe, self).tearDown()

    def test_pipe(self):
        """ Pipes """

        pipes = [VppPipe(self), VppPipe(self, 10)]

        for p in pipes:
            p.add_vpp_config()
            p.admin_up()

        #
        # L2 cross-connect pipe0 east with pg0 and west with pg1
        #
        self.vapi.sw_interface_set_l2_xconnect(self.pg0.sw_if_index,
                                               pipes[0].east,
                                               enable=1)
        self.vapi.sw_interface_set_l2_xconnect(pipes[0].east,
                                               self.pg0.sw_if_index,
                                               enable=1)
        self.vapi.sw_interface_set_l2_xconnect(self.pg1.sw_if_index,
                                               pipes[0].west,
                                               enable=1)
        self.vapi.sw_interface_set_l2_xconnect(pipes[0].west,
                                               self.pg1.sw_if_index,
                                               enable=1)

        # test bi-directional L2 flow pg0<->pg1
        p = (Ether(src=self.pg0.remote_mac,
                   dst=self.pg1.remote_mac) /
             IP(src="1.1.1.1",
                dst="1.1.1.2") /
             UDP(sport=1234, dport=1234) /
             Raw(b'\xa5' * 100))

        self.send_and_expect(self.pg0, p * NUM_PKTS, self.pg1)
        self.send_and_expect(self.pg1, p * NUM_PKTS, self.pg0)

        #
        # Attach ACL to ensure features are run on the pipe
        #
        rule_1 = AclRule(is_permit=0, proto=17,
                         src_prefix=IPv4Network("1.1.1.1/32"),
                         dst_prefix=IPv4Network("1.1.1.2/32"), ports=1234)
        acl = VppAcl(self, rules=[rule_1])
        acl.add_vpp_config()

        # Apply the ACL on the pipe on output
        acl_if_e = VppAclInterface(self, sw_if_index=pipes[0].east, n_input=0,
                                   acls=[acl])
        acl_if_e.add_vpp_config()

        self.send_and_assert_no_replies(self.pg0, p * NUM_PKTS)
        self.send_and_expect(self.pg1, p * NUM_PKTS, self.pg0)

        # remove from output and apply on input
        acl_if_e.remove_vpp_config()
        acl_if_w = VppAclInterface(self, sw_if_index=pipes[0].west, n_input=1,
                                   acls=[acl])
        acl_if_w.add_vpp_config()

        self.send_and_assert_no_replies(self.pg0, p * NUM_PKTS)
        self.send_and_expect(self.pg1, p * NUM_PKTS, self.pg0)

        acl_if_w.remove_vpp_config()
        self.send_and_expect(self.pg0, p * NUM_PKTS, self.pg1)
        self.send_and_expect(self.pg1, p * NUM_PKTS, self.pg0)

        #
        # L3 routes in two separate tables so a pipe can be used to L3
        # x-connect
        #
        tables = []
        tables.append(VppIpTable(self, 1))
        tables.append(VppIpTable(self, 2))

        for t in tables:
            t.add_vpp_config()

        self.pg2.set_table_ip4(1)
        self.pg2.config_ip4()
        self.pg2.resolve_arp()
        self.pg3.set_table_ip4(2)
        self.pg3.config_ip4()
        self.pg3.resolve_arp()

        routes = []
        routes.append(VppIpRoute(self, "1.1.1.1", 32,
                                 [VppRoutePath(self.pg3.remote_ip4,
                                               self.pg3.sw_if_index)],
                                 table_id=2))
        routes.append(VppIpRoute(self, "1.1.1.1", 32,
                                 [VppRoutePath("0.0.0.0", pipes[1].east)],
                                 table_id=1))
        routes.append(VppIpRoute(self, "1.1.1.2", 32,
                                 [VppRoutePath("0.0.0.0", pipes[1].west)],
                                 table_id=2))
        routes.append(VppIpRoute(self, "1.1.1.2", 32,
                                 [VppRoutePath(self.pg2.remote_ip4,
                                               self.pg2.sw_if_index)],
                                 table_id=1))

        for r in routes:
            r.add_vpp_config()

        p_east = (Ether(src=self.pg2.remote_mac,
                        dst=self.pg2.local_mac) /
                  IP(src="1.1.1.2",
                     dst="1.1.1.1") /
                  UDP(sport=1234, dport=1234) /
                  Raw(b'\xa5' * 100))

        # bind the pipe ends to the correct tables
        self.vapi.sw_interface_set_table(pipes[1].west, 0, 2)
        self.vapi.sw_interface_set_table(pipes[1].east, 0, 1)

        # IP is not enabled on the pipes at this point
        self.send_and_assert_no_replies(self.pg2, p_east * NUM_PKTS)

        # IP enable the Pipes by making them unnumbered
        pipes[0].set_unnumbered(self.pg2.sw_if_index)
        pipes[1].set_unnumbered(self.pg3.sw_if_index)

        self.send_and_expect(self.pg2, p_east * NUM_PKTS, self.pg3)

        # and the return path
        p_west = (Ether(src=self.pg3.remote_mac,
                        dst=self.pg3.local_mac) /
                  IP(src="1.1.1.1",
                     dst="1.1.1.2") /
                  UDP(sport=1234, dport=1234) /
                  Raw(b'\xa5' * 100))
        self.send_and_expect(self.pg3, p_west * NUM_PKTS, self.pg2)

        #
        # Use ACLs to test features run on the Pipes
        #
        acl_if_e1 = VppAclInterface(self, sw_if_index=pipes[1].east, n_input=0,
                                    acls=[acl])
        acl_if_e1.add_vpp_config()
        self.send_and_assert_no_replies(self.pg2, p_east * NUM_PKTS)
        self.send_and_expect(self.pg3, p_west * NUM_PKTS, self.pg2)

        # remove from output and apply on input
        acl_if_e1.remove_vpp_config()
        acl_if_w1 = VppAclInterface(self, sw_if_index=pipes[1].west, n_input=1,
                                    acls=[acl])
        acl_if_w1.add_vpp_config()
        self.send_and_assert_no_replies(self.pg2, p_east * NUM_PKTS)
        self.send_and_expect(self.pg3, p_west * NUM_PKTS, self.pg2)
        acl_if_w1.remove_vpp_config()

        self.send_and_expect(self.pg2, p_east * NUM_PKTS, self.pg3)
        self.send_and_expect(self.pg3, p_west * NUM_PKTS, self.pg2)

        # cleanup (so the tables delete)
        self.pg2.unconfig_ip4()
        self.pg2.set_table_ip4(0)
        self.pg3.unconfig_ip4()
        self.pg3.set_table_ip4(0)
        self.vapi.sw_interface_set_table(pipes[1].west, 0, 0)
        self.vapi.sw_interface_set_table(pipes[1].east, 0, 0)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
