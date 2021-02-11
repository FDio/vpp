#!/usr/bin/env python3

# Copyright (c) 2021 Cisco and/or its affiliates.
#
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
#
# Licensed under the Apache License 2.0 or
# GNU General Public License v2.0 or later;  you may not use this file
# except in compliance with one of these Licenses. You
# may obtain a copy of the Licenses at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#     https://www.gnu.org/licenses/old-licenses/gpl-2.0-standalone.html
#
# Note: If this file is linked with Scapy, which is GPLv2+, your use of it
# must be under GPLv2+.  If at any point in the future it is no longer linked
# with Scapy (or other GPLv2+ licensed software), you are free to choose
# Apache 2.
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
        self.create_pg_interfaces(range(1))
        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()

    def tearDown(self):
        super(TestTracefilter, self).tearDown()
        for i in self.pg_interfaces:
            i.unconfig()
            i.admin_down()

    def cli(self, cmd):
        r = self.vapi.cli_return_response(cmd)
        if r.retval != 0:
            if hasattr(r, 'reply'):
                self.logger.info(cmd + " FAIL reply " + r.reply)
            else:
                self.logger.info(cmd + " FAIL retval " + str(r.retval))
        return r

    # check number of hits for classifier
    def assert_hits(self, n):
        r = self.cli("show classify table verbose 2")
        self.assertTrue(r.retval == 0)
        self.assertTrue(hasattr(r, 'reply'))
        self.assertTrue(r.reply.find("hits %i" % n) != -1)

    def test_mactime_unitTest(self):
        """ Packet Tracer Filter Test """
        cmds = ["loopback create",
                "set int ip address loop0 192.168.1.1/24",
                "set int state loop0 up",
                "packet-generator new {\n"
                " name classifyme\n"
                " limit 100\n"
                " size 300-300\n"
                " interface loop0\n"
                " node ethernet-input\n"
                " data { \n"
                "      IP4: 1.2.3 -> 4.5.6\n"
                "      UDP: 192.168.1.10 - 192.168.1.20 -> 192.168.2.10\n"
                "      UDP: 1234 -> 2345\n"
                "      incrementing 286\n"
                "     }\n"
                "}\n",
                "classify filter trace mask l3 ip4 src"
                " match l3 ip4 src 192.168.1.15",
                "trace add pg-input 100 filter",
                "pa en classifyme"]

        for cmd in cmds:
            self.cli(cmd)

        # Check for 9 classifier hits, which is the right answer
        self.assert_hits(9)

        # cleanup
        self.cli("pa de classifyme")
        self.cli("classify filter trace del mask l3 ip4 src")

    # install a classify rule, inject traffic and check for hits
    def assert_classify(self, mask, match, packets, n=None):
        r = self.cli(
            "classify filter trace mask hex %s match hex %s" %
            (mask, match))
        self.assertTrue(r.retval == 0)
        r = self.cli("trace add pg-input %i filter" % len(packets))
        self.assertTrue(r.retval == 0)
        self.pg0.add_stream(packets)
        self.cli("pa en")
        self.assert_hits(n if n is not None else len(packets))
        self.cli("clear trace")
        self.cli(
            "classify filter trace del mask hex %s" %
            (mask))

    def test_encap(self):
        """ Packet Tracer Filter Test with encap """

        # the packet we are trying to match
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4) /
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
