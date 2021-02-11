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
import os
import re
import subprocess

# The framework library integrates with scapy, so GPL is mandatory.
from framework import VppTestCase, VppTestRunner
from vpp_ip_route import VppIpTable, VppIpRoute, VppRoutePath


def checkQat():
    r = os.path.exists("/dev/qat_dev_processes")
    if r:
        return True
    else:
        # print("NO QAT! EXIT!")
        return False


def checkOpenSSLVersion():
    ret = False
    r = "OPENSSL_ROOT_DIR" in os.environ
    if r:
        ssl = os.environ["OPENSSL_ROOT_DIR"] + "/bin/openssl version"
        p = subprocess.Popen(ssl, stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, shell=True)
        p.wait()
        output = p.stdout.read()
        status = p.returncode

        if status:
            pass
            # print("openssl version error!")
        else:
            ssl_ver_src = re.findall(r"(\d+)\.+\d+.+\d+", output)
            ssl_ver = int(ssl_ver_src[0])
            if ssl_ver < 3:
                ret = False
            else:
                ret = True
    else:
        # print("NO OPENSSL_ROOT_DIR!")
        pass

    return ret


def checkAll():
    ret = checkQat() & checkOpenSSLVersion()
    return ret


class TestTLS(VppTestCase):
    """ TLS Qat Test Case. """

    @classmethod
    def setUpClass(cls):
        super(TestTLS, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestTLS, cls).tearDownClass()

    def setUp(self):
        super(TestTLS, self).setUp()

        self.vapi.session_enable_disable(is_enable=1)
        self.create_loopback_interfaces(2)

        table_id = 0

        for i in self.lo_interfaces:
            i.admin_up()

            if table_id != 0:
                tbl = VppIpTable(self, table_id)
                tbl.add_vpp_config()

            i.set_table_ip4(table_id)
            i.config_ip4()
            table_id += 1

        # Configure namespaces
        self.vapi.app_namespace_add_del(namespace_id="0",
                                        sw_if_index=self.loop0.sw_if_index)
        self.vapi.app_namespace_add_del(namespace_id="1",
                                        sw_if_index=self.loop1.sw_if_index)

    def tearDown(self):
        for i in self.lo_interfaces:
            i.unconfig_ip4()
            i.set_table_ip4(0)
            i.admin_down()
        self.vapi.session_enable_disable(is_enable=0)
        super(TestTLS, self).tearDown()

    @unittest.skipUnless(checkAll(),
                         "QAT or OpenSSL not satisfied,skip.")
    def test_tls_transfer(self):
        """ TLS qat echo client/server transfer """

        # Add inter-table routes
        ip_t01 = VppIpRoute(self, self.loop1.local_ip4, 32,
                            [VppRoutePath("0.0.0.0",
                                          0xffffffff,
                                          nh_table_id=1)])

        ip_t10 = VppIpRoute(self, self.loop0.local_ip4, 32,
                            [VppRoutePath("0.0.0.0",
                                          0xffffffff,
                                          nh_table_id=0)], table_id=1)
        ip_t01.add_vpp_config()
        ip_t10.add_vpp_config()

        # Enable QAT engine and TLS async
        r = self.vapi.tls_openssl_set_engine(
                async_enable=1,
                engine="qat",
                algorithm="RSA,PKEY_CRYPTO",
                ciphers="RSA")
        self.assertIsNotNone(r,
                             'No response msg ')

        # Start builtin server and client
        uri = "tls://" + self.loop0.local_ip4 + "/1234"
        error = self.vapi.cli("test echo server appns 0 fifo-size 4 "
                              "tls-engine 1 uri " +
                              uri)
        if error:
            self.logger.critical(error)
            self.assertNotIn("failed", error)

        error = self.vapi.cli("test echo client mbytes 10 appns 1 "
                              "fifo-size 4 no-output test-bytes "
                              "tls-engine 1 "
                              "syn-timeout 2 uri " + uri)
        if error:
            self.logger.critical(error)
            self.assertNotIn("failed", error)

        # Delete inter-table routes
        ip_t01.remove_vpp_config()
        ip_t10.remove_vpp_config()


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
