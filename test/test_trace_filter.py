#!/usr/bin/env python3

import unittest

from framework import VppTestCase, VppTestRunner, running_extended_tests
from vpp_ip_route import VppIpTable, VppIpRoute, VppRoutePath

from scapy.contrib.geneve import GENEVE
from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.vxlan import VXLAN
from scapy.compat import raw


class TestTracefilter(VppTestCase):
    """ Packet Tracer Filter Test """

    @classmethod
    def setUpClass(cls):
        super(TestTracefilter, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestTracefilter, cls).tearDownClass()

    def setUp(self):
        super(TestTracefilter, self).setUp()
        self.create_pg_interfaces(range(2))
        self.pg0.generate_remote_hosts(11)
        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

    def tearDown(self):
        super(TestTracefilter, self).tearDown()
        for i in self.pg_interfaces:
            i.unconfig()
            i.admin_down()

    def cli(self, cmd):
        r = self.vapi.cli_return_response(cmd)
        if r.retval != 0:
            s = "reply '%s'" % r.reply if hasattr(
                r, "reply") else "retval '%s'" % r.retval
            raise RuntimeError("cli command '%s' FAIL with %s" % (cmd, s))
        return r

    # check number of hits for classifier
    def assert_hits(self, n):
        r = self.cli("show classify table verbose 2")
        self.assertTrue(r.reply.find("hits %i" % n) != -1)

    def add_filter(self, mask, match):
        r = self.cli("classify filter trace mask %s match %s" % (mask, match))
        self.vapi.cli("clear trace")
        r = self.cli("trace add pg-input 1000 filter")

    def del_all_filters(self):
        self.cli("classify filter trace del")
        r = self.cli("show classify filter")
        s = "packet tracer:                 first table none"
        self.assertTrue(r.reply.find(s) != -1)

    def test_basic(self):
        """ Packet Tracer Filter Test """
        self.add_filter(
            "l3 ip4 src",
            "l3 ip4 src %s" %
            self.pg0.remote_hosts[5].ip4)
        self.add_filter(
            "l3 ip4 proto l4 src_port",
            "l3 ip4 proto 17 l4 src_port 2345")
        # the packet we are trying to match
        p = list()
        for i in range(100):
            src = self.pg0.remote_hosts[i % len(self.pg0.remote_hosts)].ip4
            p.append((Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
                      IP(src=src, dst=self.pg1.remote_ip4) /
                      UDP(sport=1234, dport=2345) / Raw('\xa5' * 100)))
        for i in range(17):
            p.append((Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
                      IP(src=self.pg0.remote_hosts[0].ip4,
                         dst=self.pg1.remote_ip4) /
                      UDP(sport=2345, dport=1234) / Raw('\xa5' * 100)))

        self.send_and_expect(self.pg0, p, self.pg1, trace=False)

        # Check for 9 and 17 classifier hits, which is the right answer
        self.assert_hits(9)
        self.assert_hits(17)

        self.del_all_filters()

    # install a classify rule, inject traffic and check for hits
    def assert_classify(self, mask, match, packets, n=None):
        self.add_filter("hex %s" % mask, "hex %s" % match)
        self.send_and_expect(self.pg0, packets, self.pg1, trace=False)
        self.assert_hits(n if n is not None else len(packets))
        self.del_all_filters()

    def test_encap(self):
        """ Packet Tracer Filter Test with encap """

        # the packet we are trying to match
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
             UDP() /
             VXLAN() /
             Ether() /
             IP() /
             UDP() /
             GENEVE(vni=1234) /
             Ether() /
             IP(src='192.168.4.167') /
             UDP() /
             Raw('\xa5' * 100))

        #
        # compute filter mask & value
        # we compute it by XOR'ing a template packet with a modified packet
        # we need to set checksums to 0 to make sure scapy will not recompute
        # them
        #
        tmpl = (Ether() /
                IP(chksum=0) /
                UDP(chksum=0) /
                VXLAN() /
                Ether() /
                IP(chksum=0) /
                UDP(chksum=0) /
                GENEVE(vni=0) /
                Ether() /
                IP(src='0.0.0.0', chksum=0))
        ori = raw(tmpl)

        # the mask
        tmpl[GENEVE].vni = 0xffffff
        user = tmpl[GENEVE].payload
        user[IP].src = '255.255.255.255'
        new = raw(tmpl)
        mask = "".join(("{:02x}".format(o ^ n) for o, n in zip(ori, new)))

        # this does not match (wrong vni)
        tmpl[GENEVE].vni = 1
        user = tmpl[GENEVE].payload
        user[IP].src = '192.168.4.167'
        new = raw(tmpl)
        match = "".join(("{:02x}".format(o ^ n) for o, n in zip(ori, new)))
        self.assert_classify(mask, match, [p] * 11, 0)

        # this must match
        tmpl[GENEVE].vni = 1234
        new = raw(tmpl)
        match = "".join(("{:02x}".format(o ^ n) for o, n in zip(ori, new)))
        self.assert_classify(mask, match, [p] * 17)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
