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

    def cut_thru_test(self, server_app, client_app, client_args):
        self.env = {'VCL_API_PREFIX': self.shm_prefix,
                    'VCL_APP_SCOPE_LOCAL': "true"}

        worker_server = VclAppWorker(server_app, [self.server_port],
                                     self.logger, self.env)
        worker_server.start()
        self.sleep(0.2)
        worker_client = VclAppWorker(client_app, client_args,
                                     self.logger, self.env)
        worker_client.start()
        worker_client.join(self.timeout)
        self.validateResults(worker_client, worker_server, self.timeout)

    def thru_host_stack_setup(self):
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

    def thru_host_stack_tear_down(self):
        for i in self.lo_interfaces:
            i.unconfig_ip4()
            i.set_table_ip4(0)
            i.admin_down()

        self.vapi.session_enable_disable(is_enabled=0)

    def thru_host_stack_test(self, server_app, client_app, client_args):
        self.env = {'VCL_API_PREFIX': self.shm_prefix,
                    'VCL_APP_SCOPE_GLOBAL': "true",
                    'VCL_APP_NAMESPACE_ID': "0",
                    'VCL_APP_NAMESPACE_SECRET': "1234"}

        worker_server = VclAppWorker(server_app, [self.server_port],
                                     self.logger, self.env)
        worker_server.start()
        self.sleep(0.2)

        self.env.update({'VCL_APP_NAMESPACE_ID': "1",
                         'VCL_APP_NAMESPACE_SECRET': "5678"})
        worker_client = VclAppWorker(client_app, client_args,
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
            except:
                self.logger.debug(
                    "Couldn't kill client worker process")
                raise
        if error:
            os.killpg(os.getpgid(worker_server.process.pid), signal.SIGTERM)
            worker_server.join()
            raise Exception(
                "Timeout! Client worker did not finish in %ss" % timeout)
        self.assert_equal(worker_client.result, 0, "Binary test return code")


class VCLCutThruTestCase(VclTestCase):
    """ VCL Cut Thru Tests """

    def setUp(self):
        super(VCLCutThruTestCase, self).setUp()

        self.cut_thru_setup()
        self.client_echo_test_args = [self.server_addr, self.server_port,
                                      "-E", self.echo_phrase, "-X"]

    def tearDown(self):
        self.cut_thru_tear_down()

        super(VCLCutThruTestCase, self).tearDown()

    def test_ldp_cut_thru_echo(self):
        """ run LDP cut thru echo test """

        self.cut_thru_test("sock_test_server", "sock_test_client",
                           self.client_echo_test_args)

    def test_vcl_cut_thru_echo(self):
        """ run VCL cut thru echo test """

        self.cut_thru_test("vcl_test_server", "vcl_test_client",
                           self.client_echo_test_args)


class VCLThruHostStackTestCase(VclTestCase):
    """ VCL Thru Host Stack Tests """

    def setUp(self):
        super(VCLThruHostStackTestCase, self).setUp()

        self.thru_host_stack_setup()
        self.client_echo_test_args = [self.loop0.local_ip4, self.server_port,
                                      "-E", self.echo_phrase, "-X"]

    def tearDown(self):
        self.thru_host_stack_tear_down()

        super(VCLThruHostStackTestCase, self).tearDown()

    def test_ldp_thru_host_stack_echo(self):
        """ run LDP thru host stack echo test """

        self.thru_host_stack_test("sock_test_server", "sock_test_client",
                                  self.client_echo_test_args)
        # TBD: Remove this when VPP crash is fixed.
        self.thru_host_stack_test("vcl_test_server", "vcl_test_client",
                                  self.client_echo_test_args)

    def test_vcl_thru_host_stack_echo(self):
        """ run VCL thru host stack echo test """

        # TBD: Enable this when VPP crash is fixed.
        # self.thru_host_stack_test("vcl_test_server", "vcl_test_client",
        #                           self.client_echo_test_args)

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
