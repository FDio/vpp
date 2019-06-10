#  Copyright (c) 2019. Vinci Consulting Corp. All Rights Reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import framework
import ipaddress


class TestLbApi(framework.VppTestCase):
    """TestLbApi """

    def test_lb_vip_dump(self):

        # no records should return []
        rv = self.vapi.lb_vip_dump()
        print(rv)
        self.assertEqual(rv, [], 'Expected: [] Received: %r.' % rv)

        # add some vips
        rv = self.vapi.lb_add_del_vip(pfx=ipaddress.IPv4Network(u'1.2.3.0/24'),
                                      protocol=17,
                                      encap=0)
        print(rv)
        rv = self.vapi.lb_vip_dump()
        print(rv)
        self.assertEqua(rv, [], 'Expected: [<vips>] Received: %r.' % rv)

        # add test for dump by key which doesnt match

        # add test for dump by key that matches

    def test_lb_as_dump(self):

        # no records should return []
        rv = self.vapi.lb_as_dump()
        print(rv)
        self.assertEqual(rv, [], 'Expected: [] Received: %r.' % rv)

        # add some vips
        # add some as's for the vips
        rv = self.vapi.lb_add_del_as(
            pfx=ipaddress.IPv4Network(u"10.0.0.0/24"),
            as_address=ipaddress.IPv4Address(u"192.168.1.1").packed)

        print(rv)
        rv = self.vapi.lb_as_dump()
        print(rv)
        self.assertEqual(rv, [], 'Expected: [<vips>] Received: %r.' % rv)

        # add test for dump by key which doesnt match

        # add test for dump by key that matches
