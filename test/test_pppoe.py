#!/usr/bin/env python3

import socket
import unittest

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.ppp import PPPoE, PPPoED, PPP
from scapy.layers.inet import IP

from framework import VppTestCase
from asfframework import VppTestRunner
from vpp_ip_route import VppIpRoute, VppRoutePath
from vpp_pppoe_interface import VppPppoeInterface
from util import ppp
from config import config


@unittest.skipIf("pppoe" in config.excluded_plugins, "Exclude PPPoE plugin tests")
class TestPPPoE(VppTestCase):
    """PPPoE Test Case"""

    @classmethod
    def setUpClass(cls):
        super(TestPPPoE, cls).setUpClass()

        cls.session_id = 1
        cls.dst_ip = "100.1.1.100"
        cls.dst_ipn = socket.inet_pton(socket.AF_INET, cls.dst_ip)

    @classmethod
    def tearDownClass(cls):
        super(TestPPPoE, cls).tearDownClass()

    def setUp(self):
        super(TestPPPoE, self).setUp()

        # create 2 pg interfaces
        self.create_pg_interfaces(range(3))

        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

    def tearDown(self):
        super(TestPPPoE, self).tearDown()

        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.admin_down()

    def show_commands_at_teardown(self):
        self.logger.info(self.vapi.cli("show int"))
        self.logger.info(self.vapi.cli("show pppoe fib"))
        self.logger.info(self.vapi.cli("show pppoe session"))
        self.logger.info(self.vapi.cli("show ip fib"))
        self.logger.info(self.vapi.cli("show trace"))

    def create_stream_pppoe_discovery(self, src_if, dst_if, client_mac, count=1):
        packets = []
        for i in range(count):
            # create packet info stored in the test case instance
            info = self.create_packet_info(src_if, dst_if)
            # convert the info into packet payload
            payload = self.info_to_payload(info)
            # create the packet itself
            p = (
                Ether(dst=src_if.local_mac, src=client_mac)
                / PPPoED(sessionid=0)
                / Raw(payload)
            )
            # store a copy of the packet in the packet info
            info.data = p.copy()
            # append the packet to the list
            packets.append(p)

        # return the created packet list
        return packets

    def create_stream_pppoe_lcp(self, src_if, dst_if, client_mac, session_id, count=1):
        packets = []
        for i in range(count):
            # create packet info stored in the test case instance
            info = self.create_packet_info(src_if, dst_if)
            # convert the info into packet payload
            payload = self.info_to_payload(info)
            # create the packet itself
            p = (
                Ether(dst=src_if.local_mac, src=client_mac)
                / PPPoE(sessionid=session_id)
                / PPP(proto=0xC021)
                / Raw(payload)
            )
            # store a copy of the packet in the packet info
            info.data = p.copy()
            # append the packet to the list
            packets.append(p)

        # return the created packet list
        return packets

    def create_stream_pppoe_ip4(
        self, src_if, dst_if, client_mac, session_id, client_ip, count=1
    ):
        packets = []
        for i in range(count):
            # create packet info stored in the test case instance
            info = self.create_packet_info(src_if, dst_if)
            # convert the info into packet payload
            payload = self.info_to_payload(info)
            # create the packet itself
            p = (
                Ether(dst=src_if.local_mac, src=client_mac)
                / PPPoE(sessionid=session_id)
                / PPP(proto=0x0021)
                / IP(src=client_ip, dst=self.dst_ip)
                / Raw(payload)
            )
            # store a copy of the packet in the packet info
            info.data = p.copy()
            # append the packet to the list
            packets.append(p)

        # return the created packet list
        return packets

    def create_stream_ip4(self, src_if, dst_if, client_ip, dst_ip, count=1):
        pkts = []
        for i in range(count):
            # create packet info stored in the test case instance
            info = self.create_packet_info(src_if, dst_if)
            # convert the info into packet payload
            payload = self.info_to_payload(info)
            # create the packet itself
            p = (
                Ether(dst=src_if.local_mac, src=src_if.remote_mac)
                / IP(src=dst_ip, dst=client_ip)
                / Raw(payload)
            )
            # store a copy of the packet in the packet info
            info.data = p.copy()
            # append the packet to the list
            pkts.append(p)

        # return the created packet list
        return pkts

    def verify_decapped_pppoe(self, src_if, capture, sent):
        self.assertEqual(len(capture), len(sent))

        for i in range(len(capture)):
            try:
                tx = sent[i]
                rx = capture[i]

                tx_ip = tx[IP]
                rx_ip = rx[IP]

                self.assertEqual(rx_ip.src, tx_ip.src)
                self.assertEqual(rx_ip.dst, tx_ip.dst)

            except:
                self.logger.error(ppp("Rx:", rx))
                self.logger.error(ppp("Tx:", tx))
                raise

    def verify_encaped_pppoe(self, src_if, capture, sent, session_id):
        self.assertEqual(len(capture), len(sent))

        for i in range(len(capture)):
            try:
                tx = sent[i]
                rx = capture[i]

                tx_ip = tx[IP]
                rx_ip = rx[IP]

                self.assertEqual(rx_ip.src, tx_ip.src)
                self.assertEqual(rx_ip.dst, tx_ip.dst)

                rx_pppoe = rx[PPPoE]

                self.assertEqual(rx_pppoe.sessionid, session_id)

            except:
                self.logger.error(ppp("Rx:", rx))
                self.logger.error(ppp("Tx:", tx))
                raise

    def test_PPPoE_Decap(self):
        """PPPoE Decap Test"""

        self.vapi.cli("clear trace")

        #
        # Add a route that resolves the server's destination
        #
        route_sever_dst = VppIpRoute(
            self,
            "100.1.1.100",
            32,
            [VppRoutePath(self.pg1.remote_ip4, self.pg1.sw_if_index)],
        )
        route_sever_dst.add_vpp_config()

        # Send PPPoE Discovery
        tx0 = self.create_stream_pppoe_discovery(
            self.pg0, self.pg1, self.pg0.remote_mac
        )
        self.pg0.add_stream(tx0)
        self.pg_start()

        # Send PPPoE PPP LCP
        tx1 = self.create_stream_pppoe_lcp(
            self.pg0, self.pg1, self.pg0.remote_mac, self.session_id
        )
        self.pg0.add_stream(tx1)
        self.pg_start()

        # Create PPPoE session
        pppoe_if = VppPppoeInterface(
            self, self.pg0.remote_ip4, self.pg0.remote_mac, self.session_id
        )
        pppoe_if.add_vpp_config()
        pppoe_if.set_unnumbered(self.pg0.sw_if_index)
        #
        # Send tunneled packets that match the created tunnel and
        # are decapped and forwarded
        #
        tx2 = self.create_stream_pppoe_ip4(
            self.pg0,
            self.pg1,
            self.pg0.remote_mac,
            self.session_id,
            self.pg0.remote_ip4,
        )
        self.pg0.add_stream(tx2)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx2 = self.pg1.get_capture(len(tx2))
        self.verify_decapped_pppoe(self.pg0, rx2, tx2)

        self.logger.info(self.vapi.cli("show pppoe fib"))
        self.logger.info(self.vapi.cli("show pppoe session"))
        self.logger.info(self.vapi.cli("show ip fib"))

        #
        # test case cleanup
        #

        # Delete PPPoE session
        pppoe_if.remove_vpp_config()

        # Delete a route that resolves the server's destination
        route_sever_dst.remove_vpp_config()

    def test_PPPoE_Encap(self):
        """PPPoE Encap Test"""

        self.vapi.cli("clear trace")

        #
        # Add a route that resolves the server's destination
        #
        route_sever_dst = VppIpRoute(
            self,
            "100.1.1.100",
            32,
            [VppRoutePath(self.pg1.remote_ip4, self.pg1.sw_if_index)],
        )
        route_sever_dst.add_vpp_config()

        # Send PPPoE Discovery
        tx0 = self.create_stream_pppoe_discovery(
            self.pg0, self.pg1, self.pg0.remote_mac
        )
        self.pg0.add_stream(tx0)
        self.pg_start()

        # Send PPPoE PPP LCP
        tx1 = self.create_stream_pppoe_lcp(
            self.pg0, self.pg1, self.pg0.remote_mac, self.session_id
        )
        self.pg0.add_stream(tx1)
        self.pg_start()

        # Create PPPoE session
        pppoe_if = VppPppoeInterface(
            self, self.pg0.remote_ip4, self.pg0.remote_mac, self.session_id
        )
        pppoe_if.add_vpp_config()
        pppoe_if.set_unnumbered(self.pg0.sw_if_index)

        #
        # Send a packet stream that is routed into the session
        #  - packets are PPPoE encapped
        #
        self.vapi.cli("clear trace")
        tx2 = self.create_stream_ip4(
            self.pg1, self.pg0, self.pg0.remote_ip4, self.dst_ip, 65
        )
        self.pg1.add_stream(tx2)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx2 = self.pg0.get_capture(len(tx2))
        self.verify_encaped_pppoe(self.pg1, rx2, tx2, self.session_id)

        self.logger.info(self.vapi.cli("show pppoe fib"))
        self.logger.info(self.vapi.cli("show pppoe session"))
        self.logger.info(self.vapi.cli("show ip fib"))
        self.logger.info(self.vapi.cli("show adj"))

        #
        # test case cleanup
        #

        # Delete PPPoE session
        pppoe_if.remove_vpp_config()

        # Delete a route that resolves the server's destination
        route_sever_dst.remove_vpp_config()

    def test_PPPoE_Add_Twice(self):
        """PPPoE Add Same Session Twice Test"""

        self.vapi.cli("clear trace")

        #
        # Add a route that resolves the server's destination
        #
        route_sever_dst = VppIpRoute(
            self,
            "100.1.1.100",
            32,
            [VppRoutePath(self.pg1.remote_ip4, self.pg1.sw_if_index)],
        )
        route_sever_dst.add_vpp_config()

        # Send PPPoE Discovery
        tx0 = self.create_stream_pppoe_discovery(
            self.pg0, self.pg1, self.pg0.remote_mac
        )
        self.pg0.add_stream(tx0)
        self.pg_start()

        # Send PPPoE PPP LCP
        tx1 = self.create_stream_pppoe_lcp(
            self.pg0, self.pg1, self.pg0.remote_mac, self.session_id
        )
        self.pg0.add_stream(tx1)
        self.pg_start()

        # Create PPPoE session
        pppoe_if = VppPppoeInterface(
            self, self.pg0.remote_ip4, self.pg0.remote_mac, self.session_id
        )
        pppoe_if.add_vpp_config()
        pppoe_if.set_unnumbered(self.pg0.sw_if_index)

        #
        # The double create (create the same session twice) should fail,
        # and we should still be able to use the original
        #
        try:
            pppoe_if.add_vpp_config()
        except Exception:
            pass
        else:
            self.fail("Double GRE tunnel add does not fail")

        #
        # test case cleanup
        #

        # Delete PPPoE session
        pppoe_if.remove_vpp_config()

        # Delete a route that resolves the server's destination
        route_sever_dst.remove_vpp_config()

    def test_PPPoE_Del_Twice(self):
        """PPPoE Delete Same Session Twice Test"""

        self.vapi.cli("clear trace")

        #
        # Add a route that resolves the server's destination
        #
        route_sever_dst = VppIpRoute(
            self,
            "100.1.1.100",
            32,
            [VppRoutePath(self.pg1.remote_ip4, self.pg1.sw_if_index)],
        )
        route_sever_dst.add_vpp_config()

        # Send PPPoE Discovery
        tx0 = self.create_stream_pppoe_discovery(
            self.pg0, self.pg1, self.pg0.remote_mac
        )
        self.pg0.add_stream(tx0)
        self.pg_start()

        # Send PPPoE PPP LCP
        tx1 = self.create_stream_pppoe_lcp(
            self.pg0, self.pg1, self.pg0.remote_mac, self.session_id
        )
        self.pg0.add_stream(tx1)
        self.pg_start()

        # Create PPPoE session
        pppoe_if = VppPppoeInterface(
            self, self.pg0.remote_ip4, self.pg0.remote_mac, self.session_id
        )
        pppoe_if.add_vpp_config()

        # Delete PPPoE session
        pppoe_if.remove_vpp_config()

        #
        # The double del (del the same session twice) should fail,
        # and we should still be able to use the original
        #
        try:
            pppoe_if.remove_vpp_config()
        except Exception:
            pass
        else:
            self.fail("Double GRE tunnel del does not fail")

        #
        # test case cleanup
        #

        # Delete a route that resolves the server's destination
        route_sever_dst.remove_vpp_config()

    def test_PPPoE_Decap_Multiple(self):
        """PPPoE Decap Multiple Sessions Test"""

        self.vapi.cli("clear trace")

        #
        # Add a route that resolves the server's destination
        #
        route_sever_dst = VppIpRoute(
            self,
            "100.1.1.100",
            32,
            [VppRoutePath(self.pg1.remote_ip4, self.pg1.sw_if_index)],
        )
        route_sever_dst.add_vpp_config()

        # Send PPPoE Discovery 1
        tx0 = self.create_stream_pppoe_discovery(
            self.pg0, self.pg1, self.pg0.remote_mac
        )
        self.pg0.add_stream(tx0)
        self.pg_start()

        # Send PPPoE PPP LCP 1
        tx1 = self.create_stream_pppoe_lcp(
            self.pg0, self.pg1, self.pg0.remote_mac, self.session_id
        )
        self.pg0.add_stream(tx1)
        self.pg_start()

        # Create PPPoE session 1
        pppoe_if1 = VppPppoeInterface(
            self, self.pg0.remote_ip4, self.pg0.remote_mac, self.session_id
        )
        pppoe_if1.add_vpp_config()
        pppoe_if1.set_unnumbered(self.pg0.sw_if_index)

        # Send PPPoE Discovery 2
        tx3 = self.create_stream_pppoe_discovery(
            self.pg2, self.pg1, self.pg2.remote_mac
        )
        self.pg2.add_stream(tx3)
        self.pg_start()

        # Send PPPoE PPP LCP 2
        tx4 = self.create_stream_pppoe_lcp(
            self.pg2, self.pg1, self.pg2.remote_mac, self.session_id + 1
        )
        self.pg2.add_stream(tx4)
        self.pg_start()

        # Create PPPoE session 2
        pppoe_if2 = VppPppoeInterface(
            self, self.pg2.remote_ip4, self.pg2.remote_mac, self.session_id + 1
        )
        pppoe_if2.add_vpp_config()
        pppoe_if2.set_unnumbered(self.pg0.sw_if_index)

        #
        # Send tunneled packets that match the created tunnel and
        # are decapped and forwarded
        #
        tx2 = self.create_stream_pppoe_ip4(
            self.pg0,
            self.pg1,
            self.pg0.remote_mac,
            self.session_id,
            self.pg0.remote_ip4,
        )
        self.pg0.add_stream(tx2)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx2 = self.pg1.get_capture(len(tx2))
        self.verify_decapped_pppoe(self.pg0, rx2, tx2)

        tx5 = self.create_stream_pppoe_ip4(
            self.pg2,
            self.pg1,
            self.pg2.remote_mac,
            self.session_id + 1,
            self.pg2.remote_ip4,
        )
        self.pg2.add_stream(tx5)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx5 = self.pg1.get_capture(len(tx5))
        self.verify_decapped_pppoe(self.pg2, rx5, tx5)

        self.logger.info(self.vapi.cli("show pppoe fib"))
        self.logger.info(self.vapi.cli("show pppoe session"))
        self.logger.info(self.vapi.cli("show ip fib"))

        #
        # test case cleanup
        #

        # Delete PPPoE session
        pppoe_if1.remove_vpp_config()
        pppoe_if2.remove_vpp_config()

        # Delete a route that resolves the server's destination
        route_sever_dst.remove_vpp_config()

    def test_PPPoE_Encap_Multiple(self):
        """PPPoE Encap Multiple Sessions Test"""

        self.vapi.cli("clear trace")

        #
        # Add a route that resolves the server's destination
        #
        route_sever_dst = VppIpRoute(
            self,
            "100.1.1.100",
            32,
            [VppRoutePath(self.pg1.remote_ip4, self.pg1.sw_if_index)],
        )
        route_sever_dst.add_vpp_config()

        # Send PPPoE Discovery 1
        tx0 = self.create_stream_pppoe_discovery(
            self.pg0, self.pg1, self.pg0.remote_mac
        )
        self.pg0.add_stream(tx0)
        self.pg_start()

        # Send PPPoE PPP LCP 1
        tx1 = self.create_stream_pppoe_lcp(
            self.pg0, self.pg1, self.pg0.remote_mac, self.session_id
        )
        self.pg0.add_stream(tx1)
        self.pg_start()

        # Create PPPoE session 1
        pppoe_if1 = VppPppoeInterface(
            self, self.pg0.remote_ip4, self.pg0.remote_mac, self.session_id
        )
        pppoe_if1.add_vpp_config()

        # Send PPPoE Discovery 2
        tx3 = self.create_stream_pppoe_discovery(
            self.pg2, self.pg1, self.pg2.remote_mac
        )
        self.pg2.add_stream(tx3)
        self.pg_start()

        # Send PPPoE PPP LCP 2
        tx4 = self.create_stream_pppoe_lcp(
            self.pg2, self.pg1, self.pg2.remote_mac, self.session_id + 1
        )
        self.pg2.add_stream(tx4)
        self.pg_start()

        # Create PPPoE session 2
        pppoe_if2 = VppPppoeInterface(
            self, self.pg2.remote_ip4, self.pg2.remote_mac, self.session_id + 1
        )
        pppoe_if2.add_vpp_config()

        #
        # Send a packet stream that is routed into the session
        #  - packets are PPPoE encapped
        #
        self.vapi.cli("clear trace")
        tx2 = self.create_stream_ip4(
            self.pg1, self.pg0, self.pg0.remote_ip4, self.dst_ip
        )
        self.pg1.add_stream(tx2)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx2 = self.pg0.get_capture(len(tx2))
        self.verify_encaped_pppoe(self.pg1, rx2, tx2, self.session_id)

        tx5 = self.create_stream_ip4(
            self.pg1, self.pg2, self.pg2.remote_ip4, self.dst_ip
        )
        self.pg1.add_stream(tx5)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx5 = self.pg2.get_capture(len(tx5))
        self.verify_encaped_pppoe(self.pg1, rx5, tx5, self.session_id + 1)

        self.logger.info(self.vapi.cli("show pppoe fib"))
        self.logger.info(self.vapi.cli("show pppoe session"))
        self.logger.info(self.vapi.cli("show ip fib"))

        #
        # test case cleanup
        #

        # Delete PPPoE session
        pppoe_if1.remove_vpp_config()
        pppoe_if2.remove_vpp_config()

        # Delete a route that resolves the server's destination
        route_sever_dst.remove_vpp_config()

    def test_route_via_pppoe_subif(self):
        """a route via a sub-interface created on a PPPoE session"""

        #
        # the mapping from sw_if_index to session grows to cover the index of
        # every session, so the index equal to its length is the one with no
        # slot at all.  The loopbacks take every free interface index left by
        # the earlier test cases, the sessions below take the indices those
        # cases released until one of them is given a new index above the
        # loopbacks, and the sub-interface created on that session takes
        # exactly the index one past the end of the mapping.  The adjacency
        # code resolves the interface class of a sub-interface to the class of
        # its super interface but hands the callbacks the sub-interface's own
        # index, so the route below reaches them with that index.
        #
        loops = self.create_loopback_interfaces(32)

        # Send PPPoE Discovery
        tx0 = self.create_stream_pppoe_discovery(
            self.pg0, self.pg1, self.pg0.remote_mac
        )
        self.pg0.add_stream(tx0)
        self.pg_start()

        #
        # a session deleted by an earlier test case leaves its interface index
        # on the free list, and the next session takes that index back instead
        # of a new one, so keep adding sessions until one lands past the last
        # loopback and the session below is at the top of the interface pool.
        #
        sessions = []
        for client_session_id in range(self.session_id, self.session_id + 64):
            session = VppPppoeInterface(
                self, self.pg0.remote_ip4, self.pg0.remote_mac, client_session_id
            )
            session.add_vpp_config()
            sessions.append(session)
            if session.sw_if_index > loops[-1].sw_if_index:
                break
        pppoe_if = sessions[-1]
        self.logger.info("pppoe session sw_if_index=%d" % pppoe_if.sw_if_index)

        #
        # the session has to be the interface right after the last loopback,
        # otherwise the mapping can already reach past its index and the
        # sub-interface below never leaves the end of it.
        #
        self.assertEqual(loops[-1].sw_if_index + 1, pppoe_if.sw_if_index)

        r = self.vapi.create_vlan_subif(pppoe_if.sw_if_index, 100)
        sub_index = r.sw_if_index
        self.logger.info("pppoe session sub-interface sw_if_index=%d" % sub_index)
        self.assertEqual(sub_index, pppoe_if.sw_if_index + 1)

        #
        # the sub-interface is created down, and a route through a down
        # interface is a drop whatever the session lookup returns, so the
        # interface has to be up for the lookup to decide the outcome.
        #
        self.vapi.sw_interface_set_flags(sub_index, 1)

        route = VppIpRoute(
            self, "10.99.0.0", 24, [VppRoutePath("192.0.2.1", sub_index)]
        )
        route.add_vpp_config()

        #
        # the sub-interface is not a session, so its adjacency must not be
        # given the PPPoE rewrite of one.  With the lookup unbounded the
        # callback read the slot one past the end of the mapping, then installed
        # that session's rewrite on this route.
        #
        fib = self.vapi.cli("show ip fib 10.99.0.0/24")
        self.logger.info(fib)
        self.assertIn("10.99.0.0/24 fib:0", fib)
        self.assertIn("oper-flags:resolved", fib)
        self.assertIn("arp-ipv4: via 0.0.0.0", fib)
        self.assertNotIn("stacked-on:", fib)

        #
        # a packet routed through the sub-interface must not leave encapsulated
        # for a session either, and the trace shows it stopping in the ARP node.
        #
        self.vapi.cli("clear trace")
        self.pg1.add_stream(
            self.create_stream_ip4(self.pg1, self.pg0, "10.99.0.1", "10.99.0.2")
        )
        self.pg_start()
        trace = self.vapi.cli("show trace")
        self.logger.info(trace)
        self.assertIn("ip4-arp", trace)

        route.remove_vpp_config()
        self.vapi.delete_subif(sub_index)
        for session in reversed(sessions):
            session.remove_vpp_config()
        for loop in loops:
            loop.remove_vpp_config()


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
