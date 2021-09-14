#  Copyright (c) 2019. Vinci Consulting Corp. All Rights Reserved.
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

import framework
import ipaddress

DEFAULT_VIP = "lb_vip_details(_0=978, context=12, vip=vl_api_lb_ip_addr_t(pfx=IPv6Network(u'::/0'), protocol=<vl_api_ip_proto_t.IP_API_PROTO_RESERVED: 255>, port=0), encap=<vl_api_lb_encap_type_t.LB_API_ENCAP_TYPE_GRE4: 0>, dscp=<vl_api_ip_dscp_t.IP_API_DSCP_CS0: 0>, srv_type=<vl_api_lb_srv_type_t.LB_API_SRV_TYPE_CLUSTERIP: 0>, target_port=0, flow_table_length=0)"  # noqa


class TestLbEmptyApi(framework.VppTestCase):
    """TestLbEmptyApi """

    def test_lb_empty_vip_dump(self):

        # no records should  normally return [], but
        # lb initializes with a default VIP
        rv = self.vapi.lb_vip_dump()
        # print(rv)
        self.assertEqual(rv, [], 'Expected: [] Received: %r.' % rv)

    def test_lb_empty_as_dump(self):

        # no records should return []
        rv = self.vapi.lb_as_dump()
        # print(rv)
        self.assertEqual(rv, [], 'Expected: [] Received: %r.' % rv)


class TestLbApi(framework.VppTestCase):
    """TestLbApi """

    def test_lb_vip_dump(self):
        # add some vips
        # rv = self.vapi.lb_add_del_vip(pfx=ipaddress.IPv4Network(u'1.2.3.0/24'),  # noqa
        #                               protocol=17,
        #                               encap=0)
        # print(rv)
        self.vapi.cli("lb vip 2001::/16 encap gre6")
        rv = self.vapi.lb_vip_dump()
        # print(rv)
        self.assertEqual(str(rv[-1].vip.pfx), "2001::/16",
                         'Expected: 2001::/16 Received: %r.' % rv[-1].vip.pfx)

        self.vapi.cli("lb vip 2001::/16 del")


class TestLbAsApi(framework.VppTestCase):
    """TestLbAsApi """

    def test_lb_as_dump(self):
        # add some vips
        self.vapi.cli("lb vip 2001::/16 encap gre6")
        self.vapi.cli("lb as 2001::/16 2000::1")
        # add some as's for the vips
        # rv = self.vapi.lb_add_del_as(
        #     pfx=ipaddress.IPv4Network(u"10.0.0.0/24"),
        #     as_address=ipaddress.IPv4Address(u"192.168.1.1"))

        # print(rv)
        rv = self.vapi.lb_as_dump()
        # print(rv)
        self.assertEqual(str(rv[0].vip.pfx), "2001::/16",
                         'Expected: "2001::/16" Received: %r.' % rv[0].vip.pfx)
        self.assertEqual(str(rv[0].app_srv), "2000::1",
                         'Expected: "2000::1" Received: %r.' % rv[0].app_srv)
