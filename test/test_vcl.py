#!/usr/bin/env python
""" Vpp VCL tests """

import unittest
import os
import signal
from framework import VppTestCase, VppTestRunner, Worker
from vpp_ip_route import VppIpTable, VppIpRoute, VppRoutePath


class VclAppWorker(Worker):
    """ VCL Test Application Worker """

    def __init__(self, appname, args, logger, env={}):
        var = "VPP_TEST_BUILD_DIR"
        build_dir = os.getenv(var, None)
        if build_dir is None:
            raise Exception("Environment variable `%s' not set" % var)
        vcl_lib_dir = "%s/vpp/.libs" % build_dir
        app = "%s/%s" % (vcl_lib_dir, appname)
        if not os.path.isfile(app):
            app = "%s/vpp/%s" % (build_dir, appname)
            env.update({'LD_PRELOAD':
                        "%s/libvcl_ldpreload.so.0.0.0" % vcl_lib_dir})
        self.args = [app] + args
        super(VclAppWorker, self).__init__(self.args, logger, env)


class VclTestCase(VppTestCase):
    """ VCL Test Class """

    def __init__(self, methodName):
        self.server_addr = "127.0.0.1"
        self.server_port = "22000"
        self.timeout = 3
        self.echo_phrase = "Hello, world! Jenny is a friend of mine."

        super(VclTestCase, self).__init__(methodName)

    def cut_thru_setup(self):
        self.vapi.session_enable_disable(is_enabled=1)
        
    def cut_thru_tear_down(self):
        self.vapi.session_enable_disable(is_enabled=0)
        
    def cut_thru_test(self, server_appname, client_appname):
        self.env = {'VCL_API_PREFIX': self.shm_prefix,
                    'VCL_APP_SCOPE_LOCAL': "true"}

        worker_server = VclAppWorker(server_appname,
                                     [self.server_port],
                                     self.logger, self.env)
        worker_server.start()
        self.sleep(0.2)
        worker_client = VclAppWorker(client_appname,
                                     [self.server_addr, self.server_port,
                                      "-E", self.echo_phrase, "-X"],
                                     self.logger, self.env)
        worker_client.start()
        worker_client.join(self.timeout)
        self.validateResults(worker_client, worker_server, self.timeout)

    def thru_hoststack_setup(self):
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
        self.vapi.app_namespace_add(namespace_id="0", secret=1234,
                                    sw_if_index=self.loop0.sw_if_index)
        self.vapi.app_namespace_add(namespace_id="1", secret=5678,
                                    sw_if_index=self.loop1.sw_if_index)
        
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

            
    def thru_hoststack_tear_down(self):
        for i in self.lo_interfaces:
            i.unconfig_ip4()
            i.set_table_ip4(0)
            i.admin_down()
                
        self.vapi.session_enable_disable(is_enabled=0)

    def thru_hoststack_test(self, server_appname, client_appname):
        self.env = {'VCL_API_PREFIX': self.shm_prefix,
                    'VCL_APP_SCOPE_GLOBAL': "true",
                    'VCL_APP_NAMESPACE_ID': "0",
                    'VCL_APP_NAMESPACE_SECRET': "1234"}
        
        worker_server = VclAppWorker(server_appname,
                                     [self.server_port],
                                     self.logger, self.env)
        worker_server.start()
        self.sleep(0.2)

        self.env.update({'VCL_APP_NAMESPACE_ID': "1",
                         'VCL_APP_NAMESPACE_SECRET': "5678"})
        worker_client = VclAppWorker(client_appname,
                                     [self.loop0.local_ip4, self.server_port,
                                      "-E", self.echo_phrase, "-X"],
                                     self.logger, self.env)
        worker_client.start()
        worker_client.join(self.timeout)

        self.validateResults(worker_client, worker_server, self.timeout)

    def validateResults(self, worker_client, worker_server, timeout):
        self.logger.info("Client worker result is `%s'" % worker_client.result)
        error = False
        if worker_client.result is None:
            try:
                error = True
                self.logger.error(
                    "Timeout (%ss)! Killing client worker process" % timeout)
                os.killpg(os.getpgid(worker_client.process.pid),
                          signal.SIGTERM)
                worker_client.join()
                self.logger.error("DAW-1")
            except:
                self.logger.debug(
                    "Couldn't kill client worker process")
                raise
        if error:
            self.logger.error("DAW-2")
            os.killpg(os.getpgid(worker_server.process.pid), signal.SIGTERM)
            worker_server.join()
            self.logger.error("DAW-3")
            raise Exception(
                "Timeout! Client worker did not finish in %ss" % timeout)
            self.logger.error("DAW-4")
        self.assert_equal(worker_client.result, 0, "Binary test return code")


class VCLCUTTHRUTestCase(VclTestCase):
    """ VCL Cut Thru Tests """

    def setUp(self):
        super(VCLCUTTHRUTestCase, self).setUp()

        self.cut_thru_setup()
        
    def tearDown(self):
        self.cut_thru_tear_down()

        super(VCLCUTTHRUTestCase, self).tearDown()

    def test_ldp_cutthru(self):
        """ run LDP cut-thru test """

        self.cut_thru_test("sock_test_server", "sock_test_client")

    def test_vcl_cutthru(self):
        """ run VCL cut-thru test """

        self.cut_thru_test("vcl_test_server", "vcl_test_client")

class VCLTHRUHSTestcase(VclTestCase):
    """ VCL Thru Hoststack Tests """

    def setUp(self):
        super(VCLTHRUHSTestcase, self).setUp()

        self.thru_hoststack_setup()
        
    def tearDown(self):
        self.thru_hoststack_tear_down()

        super(VCLTHRUHSTestcase, self).tearDown()

    def test_ldp_thru_hoststack(self):
        """ run LDP thru hoststack test """

        self.thru_hoststack_test("sock_test_server", "sock_test_client")
# TBD: Remove this when VPP crash is fixed.
        self.thru_hoststack_test("vcl_test_server", "vcl_test_client")

    def test_vcl_thru_hoststack(self):
        """ run VCL thru hoststack test """

# TBD: Enable this when VPP crash is fixed.
#        self.thru_hoststack_test("vcl_test_server", "vcl_test_client")

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
