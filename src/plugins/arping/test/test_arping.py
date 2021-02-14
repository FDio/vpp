from scapy.layers.l2 import ARP
from scapy.layers.inet6 import ICMPv6ND_NS, ICMPv6ND_NA

from framework import VppTestCase

""" TestArping is a subclass of  VPPTestCase classes.

Basic test for sanity check of arping.

"""


class TestArping(VppTestCase):
    """ Arping Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestArping, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(2))
            cls.interfaces = list(cls.pg_interfaces)

            for i in cls.interfaces:
                i.admin_up()
                i.config_ip4()
                i.config_ip6()
                i.disable_ipv6_ra()
                i.resolve_arp()
                i.resolve_ndp()
        except Exception:
            super(TestArping, cls).tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        super(TestArping, cls).tearDownClass()

    def tearDown(self):
        super(TestArping, self).tearDown()

    def show_commands_at_teardown(self):
        self.logger.info(self.vapi.cli("show hardware"))

    def verify_arping_request(self, p, src, dst):
        arp = p[ARP]
        self.assertEqual(arp.hwtype, 0x0001)
        self.assertEqual(arp.ptype, 0x0800)
        self.assertEqual(arp.hwlen, 6)
        self.assertEqual(arp.op, 1)
        self.assertEqual(arp.psrc, src)
        self.assertEqual(arp.pdst, dst)

    def verify_arping_ip6_ns(self, p, src, dst):
        icmpv6 = p[ICMPv6ND_NS]
        self.assertEqual(icmpv6.type, 135)
        self.assertEqual(icmpv6.tgt, dst)

    def verify_arping_ip6_na(self, p, src, dst):
        icmpv6 = p[ICMPv6ND_NA]
        self.assertEqual(icmpv6.type, 136)
        self.assertEqual(icmpv6.tgt, dst)

    def test_arping_ip4_cli(self):
        """ arping IP4 CLI test """
        try:
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            remote_ip4 = self.pg1.remote_ip4

            ping_cmd = "arping " + remote_ip4 + "pg1 repeat 5 interval 0.1"
            ret = self.vapi.cli(ping_cmd)
            self.logger.info(ret)
            out = self.pg1.get_capture(5)
            for p in out:
                self.verify_arping_request(p, self.pg1.local_ip4,
                                           self.pg1.remote_ip4)
        finally:
            self.vapi.cli("show error")

    def test_arping_ip4_gratuitous_cli(self):
        """ arping ip4 gratuitous CLI test """
        try:
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()

            ping_cmd = ("arping gratuitous" + self.pg1.local_ip4 +
                        "pg1 repeat 5 interval 0.1")
            ret = self.vapi.cli(ping_cmd)
            self.logger.info(ret)
            out = self.pg1.get_capture(5)
            for p in out:
                self.verify_arping_request(p, self.pg1.local_ip4,
                                           self.pg1.local_ip4)
        finally:
            self.vapi.cli("show error")

    def test_arping_ip4_api(self):
        """ arping ip4 API test """
        try:
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            remote_ip4 = self.pg1.remote_ip4

            ret = self.vapi.arping(address=remote_ip4,
                                   sw_if_index=self.pg1.sw_if_index,
                                   is_garp=0, repeat=5, interval=0.1)
            self.logger.info(ret)
            out = self.pg1.get_capture(5)
            for p in out:
                self.verify_arping_request(p, self.pg1.local_ip4,
                                           self.pg1.remote_ip4)
        finally:
            self.vapi.cli("show error")

    def test_arping_ip4_gratuitous_api(self):
        """ arping ip4 gratuitous API test """
        try:
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()

            ret = self.vapi.arping(address=self.pg1.local_ip4,
                                   sw_if_index=self.pg1.sw_if_index,
                                   is_garp=1, repeat=5, interval=0.1)
            self.logger.info(ret)
            out = self.pg1.get_capture(5)
            for p in out:
                self.verify_arping_request(p, self.pg1.local_ip4,
                                           self.pg1.local_ip4)
        finally:
            self.vapi.cli("show error")

    def test_arping_ip6_cli(self):
        """ arping IP6 CLI test """
        try:
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            remote_ip6 = self.pg1.remote_ip6

            ping_cmd = "arping " + remote_ip6 + "pg1 repeat 5 interval 0.1"
            ret = self.vapi.cli(ping_cmd)
            self.logger.info(ret)
            out = self.pg1.get_capture(5)
            for p in out:
                self.verify_arping_ip6_ns(p, self.pg1.local_ip6,
                                          self.pg1.remote_ip6)
        finally:
            self.vapi.cli("show error")

    def test_arping_ip6_api(self):
        """ arping ip6 API test """
        try:
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            remote_ip6 = self.pg1.remote_ip6

            ret = self.vapi.arping(address=remote_ip6,
                                   sw_if_index=self.pg1.sw_if_index,
                                   is_garp=0, repeat=5, interval=0.1)
            self.logger.info(ret)
            out = self.pg1.get_capture(5)
            for p in out:
                self.verify_arping_ip6_ns(p, self.pg1.local_ip6,
                                          self.pg1.remote_ip6)
        finally:
            self.vapi.cli("show error")

    def test_arping_ip6_gratuitous_cli(self):
        """ arping ip6 gratuitous CLI test """
        try:
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()

            ping_cmd = ("arping gratuitous" + self.pg1.local_ip6 +
                        "pg1 repeat 5 interval 0.1")
            ret = self.vapi.cli(ping_cmd)
            self.logger.info(ret)
            out = self.pg1.get_capture(5)
            for p in out:
                self.verify_arping_ip6_na(p, self.pg1.local_ip6,
                                          self.pg1.local_ip6)
        finally:
            self.vapi.cli("show error")

    def test_arping_ip6_gratuitous_api(self):
        """ arping ip6 gratuitous API test """
        try:
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()

            ret = self.vapi.arping(address=self.pg1.local_ip6,
                                   sw_if_index=self.pg1.sw_if_index,
                                   is_garp=1, repeat=5, interval=0.1)
            self.logger.info(ret)
            out = self.pg1.get_capture(5)
            for p in out:
                self.verify_arping_ip6_na(p, self.pg1.local_ip6,
                                          self.pg1.local_ip6)
        finally:
            self.vapi.cli("show error")


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
