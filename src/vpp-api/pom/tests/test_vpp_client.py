# Copyright (c) 2020 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import unittest
import logging
import sys
import os
import time

from vpp_pom import VppEnum, VppClient, VppLoInterface, VppMemif, VppStartupConf, VppDiedError


class BaseVppClientTest(unittest.TestCase):
    # initialize constants
    logging.basicConfig(stream=sys.stderr, level=logging.INFO)
    vpp_install_path = "/home/ja/vpp/build-root/install-vpp_debug-native"

    # create startup conf
    startup_conf = VppStartupConf(f"{vpp_install_path}/vpp/bin/vpp")
    startup_conf.add_parameter("unix", "nodaemon")
    startup_conf.add_parameter("api-segment", "prefix TestVppClient")

    vclient = VppClient(
        "TestVppClient",
        "TestVppClient",
        logger=logging,
        api_socket=None,
        vpp_install_path=vpp_install_path)


class TestVppClient(BaseVppClientTest):
    """ Test Vpp client """

    def test_run(self):
        """ Test run/quit vpp """
        self.vclient.run_vpp(self.startup_conf)

        try:
            self.vclient.hook.poll_vpp()
        except VppDiedError:
            self.assertTrue(False)

        self.vclient.quit_vpp()

    def test_connect(self):
        """ Test connecting to VPP """
        self.vclient.run_vpp(self.startup_conf)
        self.vclient.connect()

        # connection is established in setUpClass()
        self.assertTrue(True)

        self.vclient.disconnect()
        self.vclient.quit_vpp()

    def test_request(self):
        """ Test sending a request to vpp """
        self.vclient.run_vpp(self.startup_conf)
        self.vclient.connect()

        # send show_version request and excpect valid reply
        reply = self.vclient.show_version()
        self.assertTrue(reply)
        self.assertEqual(reply.retval, 0)

        self.vclient.disconnect()
        self.vclient.quit_vpp()


class TestVppClientFetures(BaseVppClientTest):
    """ Test Vpp client features """

    @classmethod
    def setUpClass(cls):
        super(TestVppClientFetures, cls).setUpClass()
        cls.vclient.run_vpp(cls.startup_conf)
        cls.vclient.connect()

    @classmethod
    def tearDownClass(cls):
        super(TestVppClientFetures, cls).tearDownClass()
        cls.vclient.quit_vpp()

    def test_object_registry(self):
        """ Test object registry """
        # add a loopback interface
        lo = VppLoInterface(self.vclient)
        lo.add_vpp_config()

        # verify that the interace was added
        self.assertTrue(lo.query_vpp_config())

        # remove all configurations in object registry
        self.vclient.registry.remove_vpp_config()

        # verify that the interface was removed
        self.assertFalse(lo.query_vpp_config())

    def test_core(self):
        """ Test core object """
        # add a loopback interface
        lo = VppLoInterface(self.vclient)
        lo.add_vpp_config()

        # verify that the interace was added
        self.assertTrue(lo.query_vpp_config())

        # remove configuration
        lo.remove_vpp_config()

        # verify that the interface was removed
        self.assertFalse(lo.query_vpp_config())

    def test_plugin(self):
        """ Test plugin object """
        memif = VppMemif(self.vclient,
                         VppEnum.vl_api_memif_role_t.MEMIF_ROLE_API_SLAVE,
                         VppEnum.vl_api_memif_mode_t.MEMIF_MODE_API_ETHERNET)

        # add memif interface
        memif.add_vpp_config()

        # verify that the interface was added
        self.assertTrue(memif.query_vpp_config())

        # remove the interface
        memif.remove_vpp_config()

        # verify that the interface was removed
        self.assertFalse(memif.query_vpp_config())

    def test_cli(self):
        """ Test CLI """
        # test cli hook
        self.assertTrue(self.vclient.cli("show version"))
