#!/usr/bin/env python
""" Vpp VCL tests """

import unittest
import os
import signal
import subprocess
from threading import Thread
from log import single_line_delim
from framework import VppTestCase, running_extended_tests, \
    running_on_centos, VppTestRunner, Worker
from vpp_ip_route import VppIpTable, VppIpRoute, VppRoutePath


class VCLCUTTHRUTestCase(VppTestCase):
    """ VCL Cut Thru Test """

    server_addr = "127.0.0.1"
    server_port = "22000"

    @classmethod
    def setUpClass(cls):
        super(VCLCUTTHRUTestCase, cls).setUpClass()

        cls.vapi.session_enable_disable(is_enabled=1)

    def setUp(self):
        super(VCLCUTTHRUTestCase, self).setUp()

    def test_vcl_cutthru(self):
        """ run VCL cut-thru test """
        timeout = 5
        var = "VPP_TEST_BUILD_DIR"
        build_dir = os.getenv(var, None)
        self.assertIsNotNone(build_dir,
                             "Environment variable `%s' not set" % var)
        vcl_exe_dir = "%s/vpp/.libs" % build_dir
        executable = "%s/vcl_test_server" % vcl_exe_dir
        worker_server = Worker([executable, self.server_port], self.logger)
        worker_server.env["VCL_API_PREFIX"] = self.shm_prefix
        worker_server.env["VCL_APP_SCOPE_LOCAL"] = "true"
        worker_server.start()
        executable = "%s/vcl_test_client" % vcl_exe_dir
        worker_client = Worker(
            [executable, self.server_addr, self.server_port,
             "-E", "Hello, world!", "-X"], self.logger)
        worker_client.env["VCL_API_PREFIX"] = self.shm_prefix
        worker_client.env["VCL_APP_SCOPE_LOCAL"] = "true"
        worker_client.start()
        worker_client.join(timeout)
        self.logger.info("Client worker result is `%s'" % worker_client.result)
        error = False
        if worker_client.result is None:
            try:
                error = True
                self.logger.error(
                    "Timeout! Client worker did not finish in %ss" % timeout)
                os.killpg(os.getpgid(worker_client.process.pid),
                          signal.SIGTERM)
                worker_client.join()
            except:
                raise Exception("Couldn't kill client worker-spawned process")
        if error:
            os.killpg(os.getpgid(worker_server.process.pid), signal.SIGTERM)
            worker_server.join()
            raise Exception(
                "Timeout! Client worker did not finish in %ss" % timeout)
        self.assert_equal(worker_client.result, 0, "Binary test return code")


class VCLTHRUHSTestcase(VppTestCase):
    """ VCL Thru Hoststack Test """

    server_port = "22000"

    @classmethod
    def setUpClass(cls):
        super(VCLTHRUHSTestcase, cls).setUpClass()

    def setUp(self):
        super(VCLTHRUHSTestcase, self).setUp()

        self.vapi.session_enable_disable(is_enabled=1)
        self.create_loopback_interfaces(range(2))

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
        self.vapi.app_namespace_add(namespace_id="0",
                                    sw_if_index=self.loop0.sw_if_index)
        self.vapi.app_namespace_add(namespace_id="1",
                                    sw_if_index=self.loop1.sw_if_index)

    def tearDown(self):
        for i in self.lo_interfaces:
            i.unconfig_ip4()
            i.set_table_ip4(0)
            i.admin_down()

        super(VCLTHRUHSTestcase, self).tearDown()
        self.vapi.session_enable_disable(is_enabled=1)

    def test_vcl_thru_hoststack(self):
        """ run VCL thru hoststack test """
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

        timeout = 20
        var = "VPP_TEST_BUILD_DIR"
        build_dir = os.getenv(var, None)
        self.assertIsNotNone(build_dir,
                             "Environment variable `%s' not set" % var)
        vcl_exe_dir = "%s/vpp/.libs" % build_dir
        executable = "%s/vcl_test_server" % vcl_exe_dir
        worker_server = Worker([executable, self.server_port], self.logger)
        worker_server.env["VCL_API_PREFIX"] = self.shm_prefix
        worker_server.env["VCL_APP_SCOPE_GLOBAL"] = "true"
        worker_server.env["VCL_APP_NAMESPACE_ID"] = "0"
        worker_server.start()
        executable = "%s/vcl_test_client" % vcl_exe_dir
        worker_client = Worker(
            [executable, self.loop0.local_ip4, self.server_port,
             "-E", "Hello, world!", "-X"], self.logger)
        worker_client.env["VCL_API_PREFIX"] = self.shm_prefix
        worker_client.env["VCL_APP_SCOPE_GLOBAL"] = "true"
        worker_client.env["VCL_APP_NAMESPACE_ID"] = "1"
        worker_client.start()
        worker_client.join(timeout)
        self.logger.info("Client worker result is `%s'" % worker_client.result)
        error = False
        if worker_client.result is None:
            try:
                error = True
                self.logger.error(
                    "Timeout! Client worker did not finish in %ss" % timeout)
                os.killpg(os.getpgid(worker_client.process.pid),
                          signal.SIGTERM)
                worker_client.join()
            except:
                raise Exception("Couldn't kill client worker-spawned process")
        if error:
            os.killpg(os.getpgid(worker_server.process.pid), signal.SIGTERM)
            worker_server.join()
            raise Exception(
                "Timeout! Client worker did not finish in %ss" % timeout)
        self.assert_equal(worker_client.result, 0, "Binary test return code")

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
