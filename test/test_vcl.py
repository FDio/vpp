#!/usr/bin/env python
""" Vpp VCL tests """

import unittest
import os
import subprocess
import signal
from framework import VppTestCase, VppTestRunner, running_extended_tests, \
    Worker
from vpp_ip_route import VppIpTable, VppIpRoute, VppRoutePath, DpoProto


class VCLAppWorker(Worker):
    """ VCL Test Application Worker """

    def __init__(self, build_dir, appname, args, logger, env={}):
        vcl_lib_dir = "%s/vpp/lib" % build_dir
        if "iperf" in appname:
            app = appname
            env.update({'LD_PRELOAD':
                        "%s/libvcl_ldpreload.so" % vcl_lib_dir})
        elif "sock" in appname:
            app = "%s/vpp/bin/%s" % (build_dir, appname)
            env.update({'LD_PRELOAD':
                        "%s/libvcl_ldpreload.so" % vcl_lib_dir})
        else:
            app = "%s/vpp/bin/%s" % (build_dir, appname)
        self.args = [app] + args
        super(VCLAppWorker, self).__init__(self.args, logger, env)


class VCLTestCase(VppTestCase):
    """ VCL Test Class """

    def __init__(self, methodName):
        var = "VPP_BUILD_DIR"
        self.build_dir = os.getenv(var, None)
        if self.build_dir is None:
            raise EnvironmentError("Environment variable `%s' not set" % var)
        self.vppDebug = 'vpp_debug' in self.build_dir
        self.server_addr = "127.0.0.1"
        self.server_port = "22000"
        self.server_args = [self.server_port]
        self.server_ipv6_addr = "::1"
        self.server_ipv6_args = ["-6", self.server_port]
        self.timeout = 20
        self.echo_phrase = "Hello, world! Jenny is a friend of mine."
        self.pre_test_sleep = 0.3
        self.post_test_sleep = 0.2

        if os.path.isfile("/tmp/ldp_server_af_unix_socket"):
            os.remove("/tmp/ldp_server_af_unix_socket")

        super(VCLTestCase, self).__init__(methodName)

    def cut_thru_setup(self):
        self.vapi.session_enable_disable(is_enabled=1)

    def cut_thru_tear_down(self):
        self.vapi.session_enable_disable(is_enabled=0)

    def cut_thru_test(self, server_app, server_args, client_app, client_args):
        self.env = {'VCL_API_PREFIX': self.shm_prefix,
                    'VCL_APP_SCOPE_LOCAL': "true"}

        worker_server = VCLAppWorker(self.build_dir, server_app, server_args,
                                     self.logger, self.env)
        worker_server.start()
        self.sleep(self.pre_test_sleep)
        worker_client = VCLAppWorker(self.build_dir, client_app, client_args,
                                     self.logger, self.env)
        worker_client.start()
        worker_client.join(self.timeout)
        try:
            self.validateResults(worker_client, worker_server, self.timeout)
        except Exception as error:
            self.fail("Failed with %s" % error)
        self.sleep(self.post_test_sleep)

    def thru_host_stack_setup(self):
        self.vapi.session_enable_disable(is_enabled=1)
        self.create_loopback_interfaces(2)

        table_id = 1

        for i in self.lo_interfaces:
            i.admin_up()

            if table_id != 0:
                tbl = VppIpTable(self, table_id)
                tbl.add_vpp_config()

            i.set_table_ip4(table_id)
            i.config_ip4()
            table_id += 1

        # Configure namespaces
        self.vapi.app_namespace_add(namespace_id="1", secret=1234,
                                    sw_if_index=self.loop0.sw_if_index)
        self.vapi.app_namespace_add(namespace_id="2", secret=5678,
                                    sw_if_index=self.loop1.sw_if_index)

        # Add inter-table routes
        ip_t01 = VppIpRoute(self, self.loop1.local_ip4, 32,
                            [VppRoutePath("0.0.0.0",
                                          0xffffffff,
                                          nh_table_id=2)], table_id=1)
        ip_t10 = VppIpRoute(self, self.loop0.local_ip4, 32,
                            [VppRoutePath("0.0.0.0",
                                          0xffffffff,
                                          nh_table_id=1)], table_id=2)
        ip_t01.add_vpp_config()
        ip_t10.add_vpp_config()
        self.logger.debug(self.vapi.cli("show ip fib"))

    def thru_host_stack_tear_down(self):
        for i in self.lo_interfaces:
            i.unconfig_ip4()
            i.set_table_ip4(0)
            i.admin_down()

        self.vapi.session_enable_disable(is_enabled=0)

    def thru_host_stack_ipv6_setup(self):
        self.vapi.session_enable_disable(is_enabled=1)
        self.create_loopback_interfaces(2)

        table_id = 1

        for i in self.lo_interfaces:
            i.admin_up()

            tbl = VppIpTable(self, table_id, is_ip6=1)
            tbl.add_vpp_config()

            i.set_table_ip6(table_id)
            i.config_ip6()
            table_id += 1

        # Configure namespaces
        self.vapi.app_namespace_add(namespace_id="1", secret=1234,
                                    sw_if_index=self.loop0.sw_if_index)
        self.vapi.app_namespace_add(namespace_id="2", secret=5678,
                                    sw_if_index=self.loop1.sw_if_index)

        # Add inter-table routes
        ip_t01 = VppIpRoute(self, self.loop1.local_ip6, 128,
                            [VppRoutePath("::0", 0xffffffff,
                                          nh_table_id=2,
                                          proto=DpoProto.DPO_PROTO_IP6)],
                            table_id=1, is_ip6=1)
        ip_t10 = VppIpRoute(self, self.loop0.local_ip6, 128,
                            [VppRoutePath("::0", 0xffffffff,
                                          nh_table_id=1,
                                          proto=DpoProto.DPO_PROTO_IP6)],
                            table_id=2, is_ip6=1)
        ip_t01.add_vpp_config()
        ip_t10.add_vpp_config()
        self.logger.debug(self.vapi.cli("show interface addr"))
        self.logger.debug(self.vapi.cli("show ip6 fib"))

    def thru_host_stack_ipv6_tear_down(self):
        for i in self.lo_interfaces:
            i.unconfig_ip6()
            i.set_table_ip6(0)
            i.admin_down()

        self.vapi.session_enable_disable(is_enabled=0)

    def thru_host_stack_test(self, server_app, server_args,
                             client_app, client_args):
        self.env = {'VCL_API_PREFIX': self.shm_prefix,
                    'VCL_APP_SCOPE_GLOBAL': "true",
                    'VCL_APP_NAMESPACE_ID': "1",
                    'VCL_APP_NAMESPACE_SECRET': "1234"}

        worker_server = VCLAppWorker(self.build_dir, server_app, server_args,
                                     self.logger, self.env)
        worker_server.start()
        self.sleep(self.pre_test_sleep)

        self.env.update({'VCL_APP_NAMESPACE_ID': "2",
                         'VCL_APP_NAMESPACE_SECRET': "5678"})
        worker_client = VCLAppWorker(self.build_dir, client_app, client_args,
                                     self.logger, self.env)
        worker_client.start()
        worker_client.join(self.timeout)

        try:
            self.validateResults(worker_client, worker_server, self.timeout)
        except Exception as error:
            self.fail("Failed with %s" % error)
        self.sleep(self.post_test_sleep)

    def validateResults(self, worker_client, worker_server, timeout):
        if os.path.isdir('/proc/{}'.format(worker_server.process.pid)):
            self.logger.info("Killing server worker process (pid %d)" %
                             worker_server.process.pid)
            os.killpg(os.getpgid(worker_server.process.pid), signal.SIGKILL)
            worker_server.join()
        self.logger.info("Client worker result is `%s'" % worker_client.result)
        error = False
        if worker_client.result is None:
            try:
                error = True
                self.logger.error(
                    "Timeout: %ss! Killing client worker process (pid %d)" %
                    (timeout, worker_client.process.pid))
                os.killpg(os.getpgid(worker_client.process.pid),
                          signal.SIGKILL)
                worker_client.join()
            except:
                self.logger.debug(
                    "Couldn't kill client worker process")
                raise
        if error:
            raise Exception(
                "Timeout! Client worker did not finish in %ss" % timeout)
        self.assert_equal(worker_client.result, 0, "Binary test return code")


class LDPCutThruTestCase(VCLTestCase):
    """ LDP Cut Thru Tests """

    def setUp(self):
        super(LDPCutThruTestCase, self).setUp()

        self.cut_thru_setup()
        self.client_echo_test_args = ["-E", self.echo_phrase, "-X",
                                      self.server_addr, self.server_port]
        self.client_iperf3_timeout = 20
        self.client_iperf3_args = ["-V4d", "-t 2", "-c", self.server_addr]
        self.server_iperf3_args = ["-V4d", "-s"]
        self.client_uni_dir_nsock_timeout = 20
        self.client_uni_dir_nsock_test_args = ["-N", "1000", "-U", "-X",
                                               "-I", "2",
                                               self.server_addr,
                                               self.server_port]
        self.client_bi_dir_nsock_timeout = 20
        self.client_bi_dir_nsock_test_args = ["-N", "1000", "-B", "-X",
                                              "-I", "2",
                                              self.server_addr,
                                              self.server_port]

    def tearDown(self):
        self.cut_thru_tear_down()

        super(LDPCutThruTestCase, self).tearDown()

    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_ldp_cut_thru_echo(self):
        """ run LDP cut thru echo test """

        self.cut_thru_test("sock_test_server", self.server_args,
                           "sock_test_client", self.client_echo_test_args)

    def test_ldp_cut_thru_iperf3(self):
        """ run LDP cut thru iperf3 test """

        try:
            subprocess.check_output(['iperf3', '-v'])
        except subprocess.CalledProcessError:
            self.logger.error("WARNING: 'iperf3' is not installed,")
            self.logger.error("         'test_ldp_cut_thru_iperf3' not run!")
            return

        self.timeout = self.client_iperf3_timeout
        self.cut_thru_test("iperf3", self.server_iperf3_args,
                           "iperf3", self.client_iperf3_args)

    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_ldp_cut_thru_uni_dir_nsock(self):
        """ run LDP cut thru uni-directional (multiple sockets) test """

        self.timeout = self.client_uni_dir_nsock_timeout
        self.cut_thru_test("sock_test_server", self.server_args,
                           "sock_test_client",
                           self.client_uni_dir_nsock_test_args)

    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_ldp_cut_thru_bi_dir_nsock(self):
        """ run LDP cut thru bi-directional (multiple sockets) test """

        self.timeout = self.client_bi_dir_nsock_timeout
        self.cut_thru_test("sock_test_server", self.server_args,
                           "sock_test_client",
                           self.client_bi_dir_nsock_test_args)


class VCLCutThruTestCase(VCLTestCase):
    """ VCL Cut Thru Tests """

    def setUp(self):
        super(VCLCutThruTestCase, self).setUp()

        self.cut_thru_setup()
        self.client_echo_test_args = ["-E", self.echo_phrase, "-X",
                                      self.server_addr, self.server_port]

        self.client_uni_dir_nsock_timeout = 20
        self.client_uni_dir_nsock_test_args = ["-N", "1000", "-U", "-X",
                                               "-I", "2",
                                               self.server_addr,
                                               self.server_port]
        self.client_bi_dir_nsock_timeout = 20
        self.client_bi_dir_nsock_test_args = ["-N", "1000", "-B", "-X",
                                              "-I", "2",
                                              self.server_addr,
                                              self.server_port]

    def tearDown(self):
        self.cut_thru_tear_down()

        super(VCLCutThruTestCase, self).tearDown()

    def test_vcl_cut_thru_echo(self):
        """ run VCL cut thru echo test """

        self.cut_thru_test("vcl_test_server", self.server_args,
                           "vcl_test_client", self.client_echo_test_args)

    def test_vcl_cut_thru_uni_dir_nsock(self):
        """ run VCL cut thru uni-directional (multiple sockets) test """

        self.timeout = self.client_uni_dir_nsock_timeout
        self.cut_thru_test("vcl_test_server", self.server_args,
                           "vcl_test_client",
                           self.client_uni_dir_nsock_test_args)

    def test_vcl_cut_thru_bi_dir_nsock(self):
        """ run VCL cut thru bi-directional (multiple sockets) test """

        self.timeout = self.client_bi_dir_nsock_timeout
        self.cut_thru_test("vcl_test_server", self.server_args,
                           "vcl_test_client",
                           self.client_bi_dir_nsock_test_args)


class LDPThruHostStackEcho(VCLTestCase):
    """ LDP Thru Host Stack Echo """

    def setUp(self):
        super(LDPThruHostStackEcho, self).setUp()

        self.thru_host_stack_setup()
        self.client_echo_test_args = ["-E", self.echo_phrase, "-X",
                                      self.loop0.local_ip4,
                                      self.server_port]

    def tearDown(self):
        self.thru_host_stack_tear_down()
        super(LDPThruHostStackEcho, self).tearDown()

    def test_ldp_thru_host_stack_echo(self):
        """ run LDP thru host stack echo test """

        self.thru_host_stack_test("sock_test_server", self.server_args,
                                  "sock_test_client",
                                  self.client_echo_test_args)


class VCLThruHostStackEcho(VCLTestCase):
    """ VCL Thru Host Stack Echo """

    def setUp(self):
        super(VCLThruHostStackEcho, self).setUp()

        self.thru_host_stack_setup()
        self.client_bi_dir_nsock_timeout = 20
        self.client_bi_dir_nsock_test_args = ["-N", "1000", "-B", "-X",
                                              "-I", "2",
                                              self.loop0.local_ip4,
                                              self.server_port]
        self.client_echo_test_args = ["-E", self.echo_phrase, "-X",
                                      self.loop0.local_ip4,
                                      self.server_port]

    def tearDown(self):
        self.logger.debug(self.vapi.cli("show app server"))
        self.logger.debug(self.vapi.cli("show session verbose"))
        self.thru_host_stack_tear_down()
        super(VCLThruHostStackEcho, self).tearDown()


class VCLThruHostStackBidirNsock(VCLTestCase):
    """ VCL Thru Host Stack Bidir Nsock """

    def setUp(self):
        super(VCLThruHostStackBidirNsock, self).setUp()

        self.thru_host_stack_setup()
        self.client_bi_dir_nsock_timeout = 20
        self.client_bi_dir_nsock_test_args = ["-N", "1000", "-B", "-X",
                                              "-I", "2",
                                              self.loop0.local_ip4,
                                              self.server_port]
        self.client_echo_test_args = ["-E", self.echo_phrase, "-X",
                                      self.loop0.local_ip4,
                                      self.server_port]

    def tearDown(self):
        self.thru_host_stack_tear_down()
        super(VCLThruHostStackBidirNsock, self).tearDown()

    def test_vcl_thru_host_stack_bi_dir_nsock(self):
        """ run VCL thru host stack bi-directional (multiple sockets) test """

        self.timeout = self.client_bi_dir_nsock_timeout
        self.thru_host_stack_test("vcl_test_server", self.server_args,
                                  "vcl_test_client",
                                  self.client_bi_dir_nsock_test_args)


class LDPThruHostStackBidirNsock(VCLTestCase):
    """ LDP Thru Host Stack Bidir Nsock """

    def setUp(self):
        super(LDPThruHostStackBidirNsock, self).setUp()

        self.thru_host_stack_setup()
        if self.vppDebug:
            self.client_bi_dir_nsock_timeout = 20
            self.client_bi_dir_nsock_test_args = ["-N", "1000", "-B", "-X",
                                                  # OUCH! Host Stack Bug?
                                                  # "-I", "2",
                                                  self.loop0.local_ip4,
                                                  self.server_port]
        else:
            self.client_bi_dir_nsock_timeout = 20
            self.client_bi_dir_nsock_test_args = ["-N", "1000", "-B", "-X",
                                                  # OUCH! Host Stack Bug?
                                                  # "-I", "2",
                                                  self.loop0.local_ip4,
                                                  self.server_port]

    def tearDown(self):
        self.thru_host_stack_tear_down()
        super(LDPThruHostStackBidirNsock, self).tearDown()

    def test_ldp_thru_host_stack_bi_dir_nsock(self):
        """ run LDP thru host stack bi-directional (multiple sockets) test """

        self.timeout = self.client_bi_dir_nsock_timeout
        self.thru_host_stack_test("sock_test_server", self.server_args,
                                  "sock_test_client",
                                  self.client_bi_dir_nsock_test_args)


class LDPThruHostStackNsock(VCLTestCase):
    """ LDP Thru Host Stack Nsock """

    def setUp(self):
        super(LDPThruHostStackNsock, self).setUp()

        self.thru_host_stack_setup()
        if self.vppDebug:
            self.client_uni_dir_nsock_timeout = 20
            self.numSockets = "2"
        else:
            self.client_uni_dir_nsock_timeout = 20
            self.numSockets = "5"

        self.client_uni_dir_nsock_test_args = ["-N", "1000", "-U", "-X",
                                               "-I", self.numSockets,
                                               self.loop0.local_ip4,
                                               self.server_port]

    def tearDown(self):
        self.thru_host_stack_tear_down()
        super(LDPThruHostStackNsock, self).tearDown()

    def test_ldp_thru_host_stack_uni_dir_nsock(self):
        """ run LDP thru host stack uni-directional (multiple sockets) test """

        self.timeout = self.client_uni_dir_nsock_timeout
        self.thru_host_stack_test("sock_test_server", self.server_args,
                                  "sock_test_client",
                                  self.client_uni_dir_nsock_test_args)


class VCLThruHostStackNsock(VCLTestCase):
    """ VCL Thru Host Stack Nsock """

    def setUp(self):
        super(VCLThruHostStackNsock, self).setUp()

        self.thru_host_stack_setup()
        if self.vppDebug:
            self.client_uni_dir_nsock_timeout = 20
            self.numSockets = "2"
        else:
            self.client_uni_dir_nsock_timeout = 20
            self.numSockets = "5"

        self.client_uni_dir_nsock_test_args = ["-N", "1000", "-U", "-X",
                                               "-I", self.numSockets,
                                               self.loop0.local_ip4,
                                               self.server_port]

    def tearDown(self):
        self.thru_host_stack_tear_down()
        super(VCLThruHostStackNsock, self).tearDown()

    def test_vcl_thru_host_stack_uni_dir_nsock(self):
        """ run VCL thru host stack uni-directional (multiple sockets) test """

        self.timeout = self.client_uni_dir_nsock_timeout
        self.thru_host_stack_test("vcl_test_server", self.server_args,
                                  "vcl_test_client",
                                  self.client_uni_dir_nsock_test_args)


class LDPThruHostStackIperf(VCLTestCase):
    """ LDP Thru Host Stack Iperf  """

    def setUp(self):
        super(LDPThruHostStackIperf, self).setUp()

        self.thru_host_stack_setup()
        self.client_iperf3_timeout = 20
        self.client_iperf3_args = ["-V4d", "-t 2", "-c", self.loop0.local_ip4]
        self.server_iperf3_args = ["-V4d", "-s"]

    def tearDown(self):
        self.thru_host_stack_tear_down()
        super(LDPThruHostStackIperf, self).tearDown()

    def test_ldp_thru_host_stack_iperf3(self):
        """ run LDP thru host stack iperf3 test """

        try:
            subprocess.check_output(['iperf3', '-v'])
        except subprocess.CalledProcessError:
            self.logger.error("WARNING: 'iperf3' is not installed,")
            self.logger.error(
                "         'test_ldp_thru_host_stack_iperf3' not run!")
            return

        self.timeout = self.client_iperf3_timeout
        self.thru_host_stack_test("iperf3", self.server_iperf3_args,
                                  "iperf3", self.client_iperf3_args)


class LDPIpv6CutThruTestCase(VCLTestCase):
    """ LDP IPv6 Cut Thru Tests """

    def setUp(self):
        super(LDPIpv6CutThruTestCase, self).setUp()

        self.cut_thru_setup()
        self.client_iperf3_timeout = 20
        self.client_uni_dir_nsock_timeout = 20
        self.client_bi_dir_nsock_timeout = 20
        self.client_ipv6_echo_test_args = ["-6", "-E", self.echo_phrase, "-X",
                                           self.server_ipv6_addr,
                                           self.server_port]
        self.client_ipv6_iperf3_args = ["-V6d", "-t 2", "-c",
                                        self.server_ipv6_addr]
        self.server_ipv6_iperf3_args = ["-V6d", "-s"]
        self.client_ipv6_uni_dir_nsock_test_args = ["-N", "1000", "-U", "-X",
                                                    "-6",
                                                    "-I", "2",
                                                    self.server_ipv6_addr,
                                                    self.server_port]
        self.client_ipv6_bi_dir_nsock_test_args = ["-N", "1000", "-B", "-X",
                                                   "-6",
                                                   "-I", "2",
                                                   self.server_ipv6_addr,
                                                   self.server_port]

    def tearDown(self):
        self.cut_thru_tear_down()

        super(LDPIpv6CutThruTestCase, self).tearDown()

    def test_ldp_ipv6_cut_thru_echo(self):
        """ run LDP IPv6 cut thru echo test """

        self.cut_thru_test("sock_test_server",
                           self.server_ipv6_args,
                           "sock_test_client",
                           self.client_ipv6_echo_test_args)

    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_ldp_ipv6_cut_thru_iperf3(self):
        """ run LDP IPv6 cut thru iperf3 test """

        try:
            subprocess.check_output(['iperf3', '-v'])
        except:
            self.logger.error("WARNING: 'iperf3' is not installed,")
            self.logger.error(
                "         'test_ldp_ipv6_cut_thru_iperf3' not run!")
            return

        self.timeout = self.client_iperf3_timeout
        self.cut_thru_test("iperf3", self.server_ipv6_iperf3_args,
                           "iperf3", self.client_ipv6_iperf3_args)

    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_ldp_ipv6_cut_thru_uni_dir_nsock(self):
        """ run LDP IPv6 cut thru uni-directional (multiple sockets) test """

        self.timeout = self.client_uni_dir_nsock_timeout
        self.cut_thru_test("sock_test_server", self.server_ipv6_args,
                           "sock_test_client",
                           self.client_ipv6_uni_dir_nsock_test_args)

    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_ldp_ipv6_cut_thru_bi_dir_nsock(self):
        """ run LDP IPv6 cut thru bi-directional (multiple sockets) test """

        self.timeout = self.client_bi_dir_nsock_timeout
        self.cut_thru_test("sock_test_server", self.server_ipv6_args,
                           "sock_test_client",
                           self.client_ipv6_bi_dir_nsock_test_args)


class VCLIpv6CutThruTestCase(VCLTestCase):
    """ VCL IPv6 Cut Thru Tests """

    def setUp(self):
        super(VCLIpv6CutThruTestCase, self).setUp()

        self.cut_thru_setup()
        self.client_uni_dir_nsock_timeout = 20
        self.client_bi_dir_nsock_timeout = 20
        self.client_ipv6_echo_test_args = ["-6", "-E", self.echo_phrase, "-X",
                                           self.server_ipv6_addr,
                                           self.server_port]
        self.client_ipv6_uni_dir_nsock_test_args = ["-N", "1000", "-U", "-X",
                                                    "-6",
                                                    "-I", "2",
                                                    self.server_ipv6_addr,
                                                    self.server_port]
        self.client_ipv6_bi_dir_nsock_test_args = ["-N", "1000", "-B", "-X",
                                                   "-6",
                                                   "-I", "2",
                                                   self.server_ipv6_addr,
                                                   self.server_port]

    def tearDown(self):
        self.cut_thru_tear_down()

        super(VCLIpv6CutThruTestCase, self).tearDown()

    def test_vcl_ipv6_cut_thru_echo(self):
        """ run VCL IPv6 cut thru echo test """

        self.cut_thru_test("vcl_test_server",
                           self.server_ipv6_args,
                           "vcl_test_client",
                           self.client_ipv6_echo_test_args)

    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_vcl_ipv6_cut_thru_uni_dir_nsock(self):
        """ run VCL IPv6 cut thru uni-directional (multiple sockets) test """

        self.timeout = self.client_uni_dir_nsock_timeout
        self.cut_thru_test("vcl_test_server", self.server_ipv6_args,
                           "vcl_test_client",
                           self.client_ipv6_uni_dir_nsock_test_args)

    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_vcl_ipv6_cut_thru_bi_dir_nsock(self):
        """ run VCL IPv6 cut thru bi-directional (multiple sockets) test """

        self.timeout = self.client_bi_dir_nsock_timeout
        self.cut_thru_test("vcl_test_server", self.server_ipv6_args,
                           "vcl_test_client",
                           self.client_ipv6_bi_dir_nsock_test_args)


class VCLIpv6ThruHostStackEcho(VCLTestCase):
    """ VCL IPv6 Thru Host Stack Echo """

    def setUp(self):
        super(VCLIpv6ThruHostStackEcho, self).setUp()

        self.thru_host_stack_ipv6_setup()
        self.client_ipv6_echo_test_args = ["-6", "-E", self.echo_phrase, "-X",
                                           self.loop0.local_ip6,
                                           self.server_port]

    def tearDown(self):
        self.thru_host_stack_ipv6_tear_down()
        super(VCLIpv6ThruHostStackEcho, self).tearDown()

    def test_vcl_ipv6_thru_host_stack_echo(self):
        """ run VCL IPv6 thru host stack echo test """

        self.thru_host_stack_test("vcl_test_server",
                                  self.server_ipv6_args,
                                  "vcl_test_client",
                                  self.client_ipv6_echo_test_args)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
