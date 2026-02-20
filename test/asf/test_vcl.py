#!/usr/bin/env python3
"""Vpp VCL tests"""

import unittest
import os
import subprocess
import signal
import glob
from config import config
from asfframework import (
    VppAsfTestCase,
    VppTestRunner,
    Worker,
    tag_fixme_asan,
    tag_fixme_debian12,
)
from vpp_ip_route import VppIpTable, VppIpRoute, VppRoutePath

iperf3 = "/usr/bin/iperf3"


def have_app(app):
    try:
        subprocess.check_output([app, "-v"])
    except (subprocess.CalledProcessError, OSError):
        return False
    return True


_have_iperf3 = have_app(iperf3)


class VCLAppWorker(Worker):
    """VCL Test Application Worker"""

    libname = "libvcl_ldpreload.so"

    class LibraryNotFound(Exception):
        pass

    def __init__(
        self, appname, executable_args, logger, env=None, role=None, *args, **kwargs
    ):
        self.role = role
        vcl_ldpreload_glob = f"{config.vpp_install_dir}/**/{self.libname}"
        vcl_ldpreload_so = glob.glob(vcl_ldpreload_glob, recursive=True)

        if len(vcl_ldpreload_so) < 1:
            raise LibraryNotFound("cannot locate library: {}".format(self.libname))

        vcl_ldpreload_so = vcl_ldpreload_so[0]

        if env is None:
            env = {}
        if "iperf" in appname:
            app = appname
            env.update({"LD_PRELOAD": vcl_ldpreload_so})
        elif "sock" in appname:
            app = f"{config.vpp_build_dir}/vpp/bin/{appname}"
            env.update({"LD_PRELOAD": vcl_ldpreload_so})
        else:
            app = f"{config.vpp_build_dir}/vpp/bin/{appname}"
        self.args = [app] + executable_args
        super(VCLAppWorker, self).__init__(self.args, logger, env, *args, **kwargs)


@tag_fixme_debian12
class VCLTestCase(VppAsfTestCase):
    """VCL Test Class"""

    session_startup = ["poll-main", "use-app-socket-api"]

    @classmethod
    def setUpClass(cls):
        if cls.session_startup:
            conf = "session {" + " ".join(cls.session_startup) + "}"
            cls.extra_vpp_config = [conf]
        super(VCLTestCase, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(VCLTestCase, cls).tearDownClass()

    def setUp(self):
        self.vppDebug = "vpp_debug" in config.vpp_install_dir
        self.server_addr = "127.0.0.1"
        self.server_port = "22000"
        self.server_args = [self.server_port]
        self.server_ipv6_addr = "::1"
        self.server_ipv6_args = ["-6", self.server_port]
        self.timeout = 20
        self.echo_phrase = "Hello, world! Jenny is a friend of mine."
        self.pre_test_sleep = 0.3
        self.post_test_sleep = 1
        self.sapi_client_sock = "default"
        self.sapi_server_sock = "default"

        if os.path.isfile("/tmp/ldp_server_af_unix_socket"):
            os.remove("/tmp/ldp_server_af_unix_socket")

        super(VCLTestCase, self).setUp()

    def update_vcl_app_env(self, ns_id, ns_secret, attach_sock):
        if not ns_id:
            if "VCL_APP_NAMESPACE_ID" in self.vcl_app_env:
                del self.vcl_app_env["VCL_APP_NAMESPACE_ID"]
        else:
            self.vcl_app_env["VCL_APP_NAMESPACE_ID"] = ns_id

        if not ns_secret:
            if "VCL_APP_NAMESPACE_SECRET" in self.vcl_app_env:
                del self.vcl_app_env["VCL_APP_NAMESPACE_SECRET"]
        else:
            self.vcl_app_env["VCL_APP_NAMESPACE_SECRET"] = ns_secret

        if not attach_sock:
            self.vcl_app_env["VCL_VPP_API_SOCKET"] = self.get_api_sock_path()
            if "VCL_VPP_SAPI_SOCKET" in self.vcl_app_env:
                del self.vcl_app_env["VCL_VPP_SAPI_SOCKET"]
        else:
            sapi_sock = "%s/app_ns_sockets/%s" % (self.tempdir, attach_sock)
            self.vcl_app_env["VCL_VPP_SAPI_SOCKET"] = sapi_sock
            if "VCL_VPP_API_SOCKET" in self.vcl_app_env:
                del self.vcl_app_env["VCL_VPP_API_SOCKET"]

    def cut_thru_setup(self):
        self.vapi.session_enable_disable(is_enable=1)

    def cut_thru_tear_down(self):
        self.vapi.session_enable_disable(is_enable=0)

    def cut_thru_test(self, server_app, server_args, client_app, client_args):
        self.vcl_app_env = {"VCL_APP_SCOPE_LOCAL": "true"}

        self.update_vcl_app_env("", "", self.sapi_server_sock)
        worker_server = VCLAppWorker(
            server_app, server_args, self.logger, self.vcl_app_env, "server"
        )
        worker_server.start()
        self.sleep(self.pre_test_sleep)

        self.update_vcl_app_env("", "", self.sapi_client_sock)
        worker_client = VCLAppWorker(
            client_app, client_args, self.logger, self.vcl_app_env, "client"
        )
        worker_client.start()
        worker_client.join(self.timeout)
        try:
            self.validateResults(worker_client, worker_server, self.timeout)
        except Exception as error:
            self.fail("Failed with %s" % error)
        self.sleep(self.post_test_sleep)

    def thru_host_stack_setup(self):
        self.vapi.session_enable_disable(is_enable=1)
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
        self.vapi.app_namespace_add_del_v4(
            namespace_id="1", secret=1234, sw_if_index=self.loop0.sw_if_index
        )
        self.vapi.app_namespace_add_del_v4(
            namespace_id="2", secret=5678, sw_if_index=self.loop1.sw_if_index
        )

        # Add inter-table routes
        ip_t01 = VppIpRoute(
            self,
            self.loop1.local_ip4,
            32,
            [VppRoutePath("0.0.0.0", 0xFFFFFFFF, nh_table_id=2)],
            table_id=1,
        )
        ip_t10 = VppIpRoute(
            self,
            self.loop0.local_ip4,
            32,
            [VppRoutePath("0.0.0.0", 0xFFFFFFFF, nh_table_id=1)],
            table_id=2,
        )
        ip_t01.add_vpp_config()
        ip_t10.add_vpp_config()
        self.logger.debug(self.vapi.cli("show ip fib"))
        self.sapi_server_sock = "1"
        self.sapi_client_sock = "2"

    def thru_host_stack_tear_down(self):
        self.vapi.app_namespace_add_del_v4(
            is_add=0, namespace_id="1", secret=1234, sw_if_index=self.loop0.sw_if_index
        )
        self.vapi.app_namespace_add_del_v4(
            is_add=0, namespace_id="2", secret=5678, sw_if_index=self.loop1.sw_if_index
        )
        for i in self.lo_interfaces:
            i.unconfig_ip4()
            i.set_table_ip4(0)
            i.admin_down()
            i.remove_vpp_config()

    def thru_host_stack_ipv6_setup(self):
        self.vapi.session_enable_disable(is_enable=1)
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
        self.vapi.app_namespace_add_del_v4(
            namespace_id="1", secret=1234, sw_if_index=self.loop0.sw_if_index
        )
        self.vapi.app_namespace_add_del_v4(
            namespace_id="2", secret=5678, sw_if_index=self.loop1.sw_if_index
        )

        # Add inter-table routes
        ip_t01 = VppIpRoute(
            self,
            self.loop1.local_ip6,
            128,
            [VppRoutePath("::0", 0xFFFFFFFF, nh_table_id=2)],
            table_id=1,
        )
        ip_t10 = VppIpRoute(
            self,
            self.loop0.local_ip6,
            128,
            [VppRoutePath("::0", 0xFFFFFFFF, nh_table_id=1)],
            table_id=2,
        )
        ip_t01.add_vpp_config()
        ip_t10.add_vpp_config()
        self.logger.debug(self.vapi.cli("show interface addr"))
        self.logger.debug(self.vapi.cli("show ip6 fib"))
        self.sapi_server_sock = "1"
        self.sapi_client_sock = "2"

    def thru_host_stack_ipv6_tear_down(self):
        self.vapi.app_namespace_add_del_v4(
            is_add=0, namespace_id="1", secret=1234, sw_if_index=self.loop0.sw_if_index
        )
        self.vapi.app_namespace_add_del_v4(
            is_add=0, namespace_id="2", secret=5678, sw_if_index=self.loop1.sw_if_index
        )
        for i in self.lo_interfaces:
            i.unconfig_ip6()
            i.set_table_ip6(0)
            i.admin_down()

        self.vapi.session_enable_disable(is_enable=0)

    @unittest.skipUnless(_have_iperf3, "'%s' not found, Skipping.")
    def thru_host_stack_test(self, server_app, server_args, client_app, client_args):
        self.vcl_app_env = {"VCL_APP_SCOPE_GLOBAL": "true"}

        self.update_vcl_app_env("1", "1234", self.sapi_server_sock)
        worker_server = VCLAppWorker(
            server_app, server_args, self.logger, self.vcl_app_env, "server"
        )
        worker_server.start()
        self.sleep(self.pre_test_sleep)

        self.update_vcl_app_env("2", "5678", self.sapi_client_sock)
        worker_client = VCLAppWorker(
            client_app, client_args, self.logger, self.vcl_app_env, "client"
        )
        worker_client.start()
        worker_client.join(self.timeout)

        try:
            self.validateResults(worker_client, worker_server, self.timeout)
        except Exception as error:
            self.fail("Failed with %s" % error)
        self.sleep(self.post_test_sleep)

    def validateResults(self, worker_client, worker_server, timeout):
        if worker_server.process is None:
            raise RuntimeError("worker_server is not running.")
        if os.path.isdir("/proc/{}".format(worker_server.process.pid)):
            self.logger.info(
                "Killing server worker process (pid %d)" % worker_server.process.pid
            )
            try:
                os.killpg(os.getpgid(worker_server.process.pid), signal.SIGTERM)
            except ProcessLookupError:
                self.logger.debug("Server worker process already exited")
            worker_server.join()
        self.logger.info("Client worker result is `%s'" % worker_client.result)
        error = False
        if worker_client.result is None:
            try:
                error = True
                self.logger.error(
                    "Timeout: %ss! Killing client worker process (pid %d)"
                    % (timeout, worker_client.process.pid)
                )
                os.killpg(os.getpgid(worker_client.process.pid), signal.SIGKILL)
                worker_client.join()
            except OSError:
                self.logger.debug("Couldn't kill client worker process")
                raise
        if error:
            raise RuntimeError("Timeout! Client worker did not finish in %ss" % timeout)
        self.assert_equal(worker_client.result, 0, "Binary test return code")


@tag_fixme_asan
class LDPCutThruTestCase(VCLTestCase):
    """LDP Cut Thru Tests"""

    @classmethod
    def setUpClass(cls):
        super(LDPCutThruTestCase, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(LDPCutThruTestCase, cls).tearDownClass()

    def setUp(self):
        super(LDPCutThruTestCase, self).setUp()

        self.cut_thru_setup()
        self.client_echo_test_args = [
            "-E",
            self.echo_phrase,
            "-X",
            self.server_addr,
            self.server_port,
        ]
        self.client_iperf3_timeout = 20
        self.client_iperf3_args = ["-4", "-t 2", "-c", self.server_addr]
        self.server_iperf3_args = ["-4", "-s"]
        self.client_uni_dir_nsock_timeout = 20
        self.client_uni_dir_nsock_test_args = [
            "-N",
            "1000",
            "-U",
            "-X",
            "-I",
            "2",
            self.server_addr,
            self.server_port,
        ]
        self.client_bi_dir_nsock_timeout = 20
        self.client_bi_dir_nsock_test_args = [
            "-N",
            "1000",
            "-B",
            "-X",
            "-I",
            "2",
            self.server_addr,
            self.server_port,
        ]
        self.sapi_client_sock = "default"
        self.sapi_server_sock = "default"

    def tearDown(self):
        super(LDPCutThruTestCase, self).tearDown()
        self.cut_thru_tear_down()

    def show_commands_at_teardown(self):
        self.logger.debug(self.vapi.cli("show session verbose 2"))
        self.logger.debug(self.vapi.cli("show app mq"))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_ldp_cut_thru_echo(self):
        """run LDP cut thru echo test"""

        self.cut_thru_test(
            "sock_test_server",
            self.server_args,
            "sock_test_client",
            self.client_echo_test_args,
        )

    def test_ldp_cut_thru_iperf3(self):
        """run LDP cut thru iperf3 test"""

        self.timeout = self.client_iperf3_timeout
        self.cut_thru_test(
            iperf3, self.server_iperf3_args, iperf3, self.client_iperf3_args
        )

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_ldp_cut_thru_uni_dir_nsock(self):
        """run LDP cut thru uni-directional (multiple sockets) test"""

        self.timeout = self.client_uni_dir_nsock_timeout
        self.cut_thru_test(
            "sock_test_server",
            self.server_args,
            "sock_test_client",
            self.client_uni_dir_nsock_test_args,
        )

    @unittest.skipUnless(config.extended, "part of extended tests")
    @unittest.skip("sock test apps need to be improved")
    def test_ldp_cut_thru_bi_dir_nsock(self):
        """run LDP cut thru bi-directional (multiple sockets) test"""

        self.timeout = self.client_bi_dir_nsock_timeout
        self.cut_thru_test(
            "sock_test_server",
            self.server_args,
            "sock_test_client",
            self.client_bi_dir_nsock_test_args,
        )


@unittest.skipIf(
    "hs_apps" in config.excluded_plugins, "Exclude tests requiring hs_apps plugin"
)
class VCLCutThruTestCase(VCLTestCase):
    """VCL Cut Thru Tests"""

    @classmethod
    def setUpClass(cls):
        super(VCLCutThruTestCase, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(VCLCutThruTestCase, cls).tearDownClass()

    def setUp(self):
        super(VCLCutThruTestCase, self).setUp()

        self.cut_thru_setup()
        self.client_echo_test_args = [
            "-E",
            self.echo_phrase,
            "-X",
            self.server_addr,
            self.server_port,
        ]

        self.client_uni_dir_nsock_timeout = 20
        self.client_uni_dir_nsock_test_args = [
            "-N",
            "1000",
            "-U",
            "-X",
            "-I",
            "2",
            self.server_addr,
            self.server_port,
        ]
        self.client_bi_dir_nsock_timeout = 20
        self.client_bi_dir_nsock_test_args = [
            "-N",
            "1000",
            "-B",
            "-X",
            "-I",
            "2",
            self.server_addr,
            self.server_port,
        ]

    def tearDown(self):
        super(VCLCutThruTestCase, self).tearDown()

    def show_commands_at_teardown(self):
        self.logger.debug(self.vapi.cli("show session verbose 2"))
        self.logger.debug(self.vapi.cli("show app mq"))

    def test_vcl_cut_thru_echo(self):
        """run VCL cut thru echo test"""

        self.cut_thru_test(
            "vcl_test_server",
            self.server_args,
            "vcl_test_client",
            self.client_echo_test_args,
        )

    def test_vcl_cut_thru_uni_dir_nsock(self):
        """run VCL cut thru uni-directional (multiple sockets) test"""

        self.timeout = self.client_uni_dir_nsock_timeout
        self.cut_thru_test(
            "vcl_test_server",
            self.server_args,
            "vcl_test_client",
            self.client_uni_dir_nsock_test_args,
        )

    def test_vcl_cut_thru_bi_dir_nsock(self):
        """run VCL cut thru bi-directional (multiple sockets) test"""

        self.timeout = self.client_bi_dir_nsock_timeout
        self.cut_thru_test(
            "vcl_test_server",
            self.server_args,
            "vcl_test_client",
            self.client_bi_dir_nsock_test_args,
        )


@unittest.skipIf(
    "hs_apps" in config.excluded_plugins, "Exclude tests requiring hs_apps plugin"
)
class VCLThruHostStackEcho(VCLTestCase):
    """VCL Thru Host Stack Echo"""

    @classmethod
    def setUpClass(cls):
        super(VCLThruHostStackEcho, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(VCLThruHostStackEcho, cls).tearDownClass()

    def setUp(self):
        super(VCLThruHostStackEcho, self).setUp()

        self.thru_host_stack_setup()
        self.client_bi_dir_nsock_timeout = 20
        self.client_bi_dir_nsock_test_args = [
            "-N",
            "1000",
            "-B",
            "-X",
            "-I",
            "2",
            self.loop0.local_ip4,
            self.server_port,
        ]
        self.client_echo_test_args = [
            "-E",
            self.echo_phrase,
            "-X",
            self.loop0.local_ip4,
            self.server_port,
        ]

    def tearDown(self):
        self.thru_host_stack_tear_down()
        super(VCLThruHostStackEcho, self).tearDown()

    def test_vcl_thru_host_stack_echo(self):
        """run VCL IPv4 thru host stack echo test"""

        self.thru_host_stack_test(
            "vcl_test_server",
            self.server_args,
            "vcl_test_client",
            self.client_echo_test_args,
        )

    def show_commands_at_teardown(self):
        self.logger.debug(self.vapi.cli("show app server"))
        self.logger.debug(self.vapi.cli("show session verbose"))
        self.logger.debug(self.vapi.cli("show app mq"))


@unittest.skipIf(
    "hs_apps" in config.excluded_plugins, "Exclude tests requiring hs_apps plugin"
)
class VCLThruHostStackCLUDPEcho(VCLTestCase):
    """VCL Thru Host Stack CL UDP Echo"""

    @classmethod
    def setUpClass(cls):
        super(VCLThruHostStackCLUDPEcho, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(VCLThruHostStackCLUDPEcho, cls).tearDownClass()

    def setUp(self):
        super(VCLThruHostStackCLUDPEcho, self).setUp()

        self.sapi_server_sock = "1"
        self.sapi_client_sock = "2"
        self.thru_host_stack_setup()
        self.pre_test_sleep = 2
        self.timeout = 5

    def tearDown(self):
        self.thru_host_stack_tear_down()
        super(VCLThruHostStackCLUDPEcho, self).tearDown()

    def test_vcl_thru_host_stack_cl_udp_echo(self):
        """run VCL IPv4 thru host stack CL UDP echo test"""
        server_args = ["-s", self.loop0.local_ip4]
        client_args = ["-c", self.loop0.local_ip4]
        self.thru_host_stack_test(
            "vcl_test_cl_udp",
            server_args,
            "vcl_test_cl_udp",
            client_args,
        )

    def test_vcl_thru_host_stack_cl_udp_mt_echo(self):
        """run VCL IPv4 thru host stack CL UDP MT echo test"""
        server_args = ["-s", self.loop0.local_ip4, "-w", "2"]
        client_args = ["-c", self.loop0.local_ip4, "-w", "2"]
        self.thru_host_stack_test(
            "vcl_test_cl_udp",
            server_args,
            "vcl_test_cl_udp",
            client_args,
        )

    def show_commands_at_teardown(self):
        self.logger.debug(self.vapi.cli("show app server"))
        self.logger.debug(self.vapi.cli("show session verbose"))
        self.logger.debug(self.vapi.cli("show app mq"))


@unittest.skipIf(
    "hs_apps" in config.excluded_plugins, "Exclude tests requiring hs_apps plugin"
)
class VCLProgrammaticConfig(VCLTestCase):
    """VCL Programmatic Configuration Tests"""

    @classmethod
    def setUpClass(cls):
        super(VCLProgrammaticConfig, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(VCLProgrammaticConfig, cls).tearDownClass()

    def setUp(self):
        self.sapi_server_sock = "default"
        self.cfg_timeout = "3"
        self.test_timeout = 5

        self.vapi.session_enable_disable(is_enable=1)
        self.create_loopback_interfaces(2)
        for i in self.lo_interfaces:
            i.admin_up()
            i.config_ip4()

    def tearDown(self):
        for i in self.lo_interfaces:
            i.unconfig_ip4()
            i.admin_down()
            i.remove_vpp_config()
        super(VCLProgrammaticConfig, self).tearDown()

    def test_vcl_cfg_test_programmatic_config(self):
        """run VCL configuration test with programmatic config and session creation"""
        # Test the vcl_cfg_test application which uses programmatic VCL configuration
        # and creates a session to test the configuration-based app creation

        # Set up minimal VCL environment - let vcl_cfg_test handle all configs programmatically
        sapi_sock = "%s/app_ns_sockets/%s" % (self.tempdir, self.sapi_server_sock)
        server_args = [
            "-s",
            self.loop0.local_ip4,
            "-t",
            self.cfg_timeout,
            "-a",
            sapi_sock,
            "-d",
            "2",
        ]

        worker_cfg_test = VCLAppWorker(
            "vcl_cfg_test", server_args, self.logger, None, "server"
        )
        worker_cfg_test.start()
        self.sleep(0.5)

        # Check with VPP CLI that the session is bound in VPP
        session_output = self.vapi.cli("show session verbose")
        self.logger.debug(session_output)
        self.assertIn(self.loop0.local_ip4, session_output)
        self.assertIn("[U]", session_output)
        self.assertIn("LISTEN", session_output)

        worker_cfg_test.join(self.test_timeout)


@unittest.skipIf(
    "hs_apps" in config.excluded_plugins, "Exclude tests requiring hs_apps plugin"
)
class VCLThruHostStackCLUDPBinds(VCLTestCase):
    """VCL Thru Host Stack CL UDP Binds"""

    @classmethod
    def setUpClass(cls):
        super(VCLThruHostStackCLUDPBinds, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(VCLThruHostStackCLUDPBinds, cls).tearDownClass()

    def setUp(self):
        super(VCLThruHostStackCLUDPBinds, self).setUp()

        self.sapi_server_sock = "default"
        self.timeout = 5

        self.vapi.session_enable_disable(is_enable=1)
        self.create_loopback_interfaces(2)
        for i in self.lo_interfaces:
            i.admin_up()
            i.config_ip4()

    def tearDown(self):
        for i in self.lo_interfaces:
            i.unconfig_ip4()
            i.admin_down()
            i.remove_vpp_config()
        super(VCLThruHostStackCLUDPBinds, self).tearDown()

    def test_vcl_thru_host_stack_cl_udp_multiple_binds(self):
        """run VCL IPv4 thru host stack CL UDP multiple binds test"""

        # 2 CL UDP servers bound to the same port but different IPs
        server1_args = ["-s", self.loop0.local_ip4, "-w", "2"]
        server2_args = ["-s", self.loop1.local_ip4, "-w", "2"]

        sapi_sock = "%s/app_ns_sockets/%s" % (self.tempdir, self.sapi_server_sock)
        self.vcl_app_env = {
            "VCL_APP_SCOPE_GLOBAL": "true",
            "VCL_VPP_SAPI_SOCKET": sapi_sock,
        }

        worker_server1 = VCLAppWorker(
            "vcl_test_cl_udp", server1_args, self.logger, self.vcl_app_env, "server1"
        )
        worker_server1.start()
        self.sleep(0.5)

        worker_server2 = VCLAppWorker(
            "vcl_test_cl_udp", server2_args, self.logger, self.vcl_app_env, "server2"
        )
        worker_server2.start()
        self.sleep(0.5)

        session_output = self.vapi.cli("show session verbose")
        self.logger.debug(session_output)
        self.assertIn(self.loop0.local_ip4, session_output)
        self.assertIn(self.loop1.local_ip4, session_output)
        self.assertIn("[U]", session_output)
        self.assertIn("LISTEN", session_output)

        try:
            worker_server1.process.send_signal(signal.SIGUSR1)
            worker_server2.process.send_signal(signal.SIGUSR1)
        except (AttributeError, OSError) as e:
            self.logger.warning(f"Failed to send SIGUSR1: {e}")

        self.sleep(0.5)

        worker_server2.join(self.timeout)

    def show_commands_at_teardown(self):
        self.logger.debug(self.vapi.cli("show app server"))
        self.logger.debug(self.vapi.cli("show session verbose"))
        self.logger.debug(self.vapi.cli("show app mq"))


@unittest.skipIf(
    "hs_apps" in config.excluded_plugins, "Exclude tests requiring hs_apps plugin"
)
class VCLThruHostStackTLS(VCLTestCase):
    """VCL Thru Host Stack TLS"""

    @classmethod
    def setUpClass(cls):
        super(VCLThruHostStackTLS, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(VCLThruHostStackTLS, cls).tearDownClass()

    def setUp(self):
        super(VCLThruHostStackTLS, self).setUp()

        self.thru_host_stack_setup()
        self.client_uni_dir_tls_timeout = 20
        self.server_tls_args = ["-L", self.server_port]
        self.client_uni_dir_tls_test_args = [
            "-N",
            "1000",
            "-U",
            "-X",
            "-L",
            self.loop0.local_ip4,
            self.server_port,
        ]
        self.sapi_server_sock = "1"
        self.sapi_client_sock = "2"

    def test_vcl_thru_host_stack_tls_uni_dir(self):
        """run VCL thru host stack uni-directional TLS test"""

        self.timeout = self.client_uni_dir_tls_timeout
        self.thru_host_stack_test(
            "vcl_test_server",
            self.server_tls_args,
            "vcl_test_client",
            self.client_uni_dir_tls_test_args,
        )

    def tearDown(self):
        self.thru_host_stack_tear_down()
        super(VCLThruHostStackTLS, self).tearDown()

    def show_commands_at_teardown(self):
        self.logger.debug(self.vapi.cli("show app server"))
        self.logger.debug(self.vapi.cli("show session verbose 2"))
        self.logger.debug(self.vapi.cli("show app mq"))


@unittest.skipIf(
    "hs_apps" in config.excluded_plugins, "Exclude tests requiring hs_apps plugin"
)
class VCLThruHostStackEchoInterruptMode(VCLThruHostStackEcho):
    """VCL Thru Host Stack Echo interrupt mode"""

    @classmethod
    def setUpClass(cls):
        cls.session_startup = ["use-private-rx-mqs", "use-app-socket-api"]
        super(VCLThruHostStackEcho, cls).setUpClass()

    def test_vcl_thru_host_stack_echo(self):
        """run VCL IPv4 thru host stack echo test interrupt mode"""

        self.sapi_server_sock = "1"
        self.sapi_client_sock = "2"

        self.thru_host_stack_test(
            "vcl_test_server",
            self.server_args,
            "vcl_test_client",
            self.client_echo_test_args,
        )


class VCLThruHostStackTLSInterruptMode(VCLThruHostStackTLS):
    """VCL Thru Host Stack TLS interrupt mode"""

    @classmethod
    def setUpClass(cls):
        cls.session_startup = ["poll-main", "use-app-socket-api", "use-private-rx-mqs"]
        super(VCLThruHostStackTLS, cls).setUpClass()


@unittest.skipIf(
    "hs_apps" in config.excluded_plugins, "Exclude tests requiring hs_apps plugin"
)
class VCLThruHostStackDTLS(VCLTestCase):
    """VCL Thru Host Stack DTLS"""

    @classmethod
    def setUpClass(cls):
        super(VCLThruHostStackDTLS, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(VCLThruHostStackDTLS, cls).tearDownClass()

    def setUp(self):
        super(VCLThruHostStackDTLS, self).setUp()

        self.thru_host_stack_setup()
        self.client_uni_dir_dtls_timeout = 20
        self.server_dtls_args = ["-p", "dtls", self.server_port]
        self.client_uni_dir_dtls_test_args = [
            "-N",
            "1000",
            "-U",
            "-X",
            "-p",
            "dtls",
            "-T 1400",
            self.loop0.local_ip4,
            self.server_port,
        ]

    def test_vcl_thru_host_stack_dtls_uni_dir(self):
        """run VCL thru host stack uni-directional DTLS test"""

        self.timeout = self.client_uni_dir_dtls_timeout
        self.thru_host_stack_test(
            "vcl_test_server",
            self.server_dtls_args,
            "vcl_test_client",
            self.client_uni_dir_dtls_test_args,
        )

    def tearDown(self):
        self.thru_host_stack_tear_down()
        super(VCLThruHostStackDTLS, self).tearDown()

    def show_commands_at_teardown(self):
        self.logger.debug(self.vapi.cli("show app server"))
        self.logger.debug(self.vapi.cli("show session verbose 2"))
        self.logger.debug(self.vapi.cli("show app mq"))


@unittest.skipIf(
    "hs_apps" in config.excluded_plugins, "Exclude tests requiring hs_apps plugin"
)
class VCLThruHostStackQUIC(VCLTestCase):
    """VCL Thru Host Stack QUIC"""

    @classmethod
    def setUpClass(cls):
        cls.extra_vpp_plugin_config.append("plugin quic_plugin.so { enable }")
        cls.extra_vpp_plugin_config.append("plugin quic_quicly_plugin.so { enable }")
        super(VCLThruHostStackQUIC, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(VCLThruHostStackQUIC, cls).tearDownClass()

    def setUp(self):
        super(VCLThruHostStackQUIC, self).setUp()

        self.thru_host_stack_setup()
        self.client_uni_dir_quic_timeout = 20
        self.server_quic_args = ["-p", "quic", self.server_port]
        self.client_uni_dir_quic_test_args = [
            "-N",
            "1000",
            "-U",
            "-X",
            "-p",
            "quic",
            self.loop0.local_ip4,
            self.server_port,
        ]
        self.client_bi_dir_multi_stream_quic_test_args = [
            "-N",
            "1000",
            "-B",
            "-X",
            "-p",
            "quic",
            "-s",
            "10",
            "-q",
            "10",
            self.loop0.local_ip4,
            self.server_port,
        ]

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_vcl_thru_host_stack_quic_uni_dir(self):
        """run VCL thru host stack uni-directional QUIC test"""

        self.timeout = self.client_uni_dir_quic_timeout
        self.thru_host_stack_test(
            "vcl_test_server",
            self.server_quic_args,
            "vcl_test_client",
            self.client_uni_dir_quic_test_args,
        )

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_vcl_thru_host_stack_quic_bi_dir_multi_stream(self):
        """run VCL thru host stack bi-directional multi stream QUIC test"""

        self.timeout = self.client_uni_dir_quic_timeout
        self.thru_host_stack_test(
            "vcl_test_server",
            self.server_quic_args,
            "vcl_test_client",
            self.client_bi_dir_multi_stream_quic_test_args,
        )

    def tearDown(self):
        self.thru_host_stack_tear_down()
        super(VCLThruHostStackQUIC, self).tearDown()

    def show_commands_at_teardown(self):
        self.logger.debug(self.vapi.cli("show app server"))
        self.logger.debug(self.vapi.cli("show session verbose 2"))
        self.logger.debug(self.vapi.cli("show app mq"))


@unittest.skipIf(
    "hs_apps" in config.excluded_plugins, "Exclude tests requiring hs_apps plugin"
)
class VCLThruHostStackHTTPPost(VCLTestCase):
    """VCL Thru Host Stack HTTP Post"""

    @classmethod
    def setUpClass(cls):
        cls.extra_vpp_plugin_config.append("plugin http_plugin.so { enable }")
        super(VCLThruHostStackHTTPPost, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(VCLThruHostStackHTTPPost, cls).tearDownClass()

    def setUp(self):
        super(VCLThruHostStackHTTPPost, self).setUp()

        self.thru_host_stack_setup()
        self.client_uni_dir_http_post_timeout = 20
        self.server_http_post_args = ["-p", "http", self.server_port]
        self.client_uni_dir_http_post_test_args = [
            "-N",
            "10000",
            "-U",
            "-X",
            "-p",
            "http",
            self.loop0.local_ip4,
            self.server_port,
        ]

    def test_vcl_thru_host_stack_http_post_uni_dir(self):
        """run VCL thru host stack uni-directional HTTP POST test"""

        self.timeout = self.client_uni_dir_http_post_timeout
        self.thru_host_stack_test(
            "vcl_test_server",
            self.server_http_post_args,
            "vcl_test_client",
            self.client_uni_dir_http_post_test_args,
        )

    def tearDown(self):
        self.thru_host_stack_tear_down()
        super(VCLThruHostStackHTTPPost, self).tearDown()

    def show_commands_at_teardown(self):
        self.logger.debug(self.vapi.cli("show app server"))
        self.logger.debug(self.vapi.cli("show session verbose 2"))
        self.logger.debug(self.vapi.cli("show app mq"))


@unittest.skipIf(
    "hs_apps" in config.excluded_plugins, "Exclude tests requiring hs_apps plugin"
)
class VCLThruHostStackBidirNsock(VCLTestCase):
    """VCL Thru Host Stack Bidir Nsock"""

    @classmethod
    def setUpClass(cls):
        super(VCLThruHostStackBidirNsock, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(VCLThruHostStackBidirNsock, cls).tearDownClass()

    def setUp(self):
        super(VCLThruHostStackBidirNsock, self).setUp()

        self.thru_host_stack_setup()
        self.client_bi_dir_nsock_timeout = 20
        self.client_bi_dir_nsock_test_args = [
            "-N",
            "1000",
            "-B",
            "-X",
            "-I",
            "2",
            self.loop0.local_ip4,
            self.server_port,
        ]
        self.client_echo_test_args = [
            "-E",
            self.echo_phrase,
            "-X",
            self.loop0.local_ip4,
            self.server_port,
        ]

    def tearDown(self):
        self.thru_host_stack_tear_down()
        super(VCLThruHostStackBidirNsock, self).tearDown()

    def show_commands_at_teardown(self):
        self.logger.debug(self.vapi.cli("show session verbose 2"))
        self.logger.debug(self.vapi.cli("show app mq"))

    def test_vcl_thru_host_stack_bi_dir_nsock(self):
        """run VCL thru host stack bi-directional (multiple sockets) test"""

        self.timeout = self.client_bi_dir_nsock_timeout
        self.thru_host_stack_test(
            "vcl_test_server",
            self.server_args,
            "vcl_test_client",
            self.client_bi_dir_nsock_test_args,
        )


@tag_fixme_asan
@unittest.skipIf(
    "hs_apps" in config.excluded_plugins, "Exclude tests requiring hs_apps plugin"
)
class LDPThruHostStackBidirNsock(VCLTestCase):
    """LDP Thru Host Stack Bidir Nsock"""

    @classmethod
    def setUpClass(cls):
        super(LDPThruHostStackBidirNsock, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(LDPThruHostStackBidirNsock, cls).tearDownClass()

    def setUp(self):
        super(LDPThruHostStackBidirNsock, self).setUp()

        self.thru_host_stack_setup()
        self.client_bi_dir_nsock_timeout = 20
        self.client_bi_dir_nsock_test_args = [
            "-N",
            "1000",
            "-B",
            "-X",
            # OUCH! Host Stack Bug?
            # Only fails when running
            # 'make test TEST_JOBS=auto'
            # or TEST_JOBS > 1
            # "-I", "2",
            self.loop0.local_ip4,
            self.server_port,
        ]

    def tearDown(self):
        self.thru_host_stack_tear_down()
        super(LDPThruHostStackBidirNsock, self).tearDown()

    def show_commands_at_teardown(self):
        self.logger.debug(self.vapi.cli("show session verbose 2"))
        self.logger.debug(self.vapi.cli("show app mq"))

    def test_ldp_thru_host_stack_bi_dir_nsock(self):
        """run LDP thru host stack bi-directional (multiple sockets) test"""

        self.timeout = self.client_bi_dir_nsock_timeout
        self.thru_host_stack_test(
            "sock_test_server",
            self.server_args,
            "sock_test_client",
            self.client_bi_dir_nsock_test_args,
        )


@tag_fixme_asan
@unittest.skipIf(
    "hs_apps" in config.excluded_plugins, "Exclude tests requiring hs_apps plugin"
)
class LDPThruHostStackNsock(VCLTestCase):
    """LDP Thru Host Stack Nsock"""

    @classmethod
    def setUpClass(cls):
        super(LDPThruHostStackNsock, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(LDPThruHostStackNsock, cls).tearDownClass()

    def setUp(self):
        super(LDPThruHostStackNsock, self).setUp()

        self.thru_host_stack_setup()
        if self.vppDebug:
            self.client_uni_dir_nsock_timeout = 20
            self.numSockets = "2"
        else:
            self.client_uni_dir_nsock_timeout = 20
            self.numSockets = "5"

        self.client_uni_dir_nsock_test_args = [
            "-N",
            "1000",
            "-U",
            "-X",
            "-I",
            self.numSockets,
            self.loop0.local_ip4,
            self.server_port,
        ]

    def tearDown(self):
        self.thru_host_stack_tear_down()
        super(LDPThruHostStackNsock, self).tearDown()

    def test_ldp_thru_host_stack_uni_dir_nsock(self):
        """run LDP thru host stack uni-directional (multiple sockets) test"""

        self.timeout = self.client_uni_dir_nsock_timeout
        self.thru_host_stack_test(
            "sock_test_server",
            self.server_args,
            "sock_test_client",
            self.client_uni_dir_nsock_test_args,
        )


@unittest.skipIf(
    "hs_apps" in config.excluded_plugins, "Exclude tests requiring hs_apps plugin"
)
class VCLThruHostStackNsock(VCLTestCase):
    """VCL Thru Host Stack Nsock"""

    @classmethod
    def setUpClass(cls):
        super(VCLThruHostStackNsock, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(VCLThruHostStackNsock, cls).tearDownClass()

    def setUp(self):
        super(VCLThruHostStackNsock, self).setUp()

        self.thru_host_stack_setup()
        if self.vppDebug:
            self.client_uni_dir_nsock_timeout = 20
            self.numSockets = "2"
        else:
            self.client_uni_dir_nsock_timeout = 20
            self.numSockets = "5"

        self.client_uni_dir_nsock_test_args = [
            "-N",
            "1000",
            "-U",
            "-X",
            "-I",
            self.numSockets,
            self.loop0.local_ip4,
            self.server_port,
        ]

    def tearDown(self):
        self.thru_host_stack_tear_down()
        super(VCLThruHostStackNsock, self).tearDown()

    def test_vcl_thru_host_stack_uni_dir_nsock(self):
        """run VCL thru host stack uni-directional (multiple sockets) test"""

        self.timeout = self.client_uni_dir_nsock_timeout
        self.thru_host_stack_test(
            "vcl_test_server",
            self.server_args,
            "vcl_test_client",
            self.client_uni_dir_nsock_test_args,
        )


@tag_fixme_asan
class LDPThruHostStackIperf(VCLTestCase):
    """LDP Thru Host Stack Iperf"""

    @classmethod
    def setUpClass(cls):
        super(LDPThruHostStackIperf, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(LDPThruHostStackIperf, cls).tearDownClass()

    def setUp(self):
        super(LDPThruHostStackIperf, self).setUp()

        self.thru_host_stack_setup()
        self.client_iperf3_timeout = 20
        self.client_iperf3_args = ["-4", "-t 2", "-c", self.loop0.local_ip4]
        self.server_iperf3_args = ["-4", "-s"]

    def tearDown(self):
        self.thru_host_stack_tear_down()
        super(LDPThruHostStackIperf, self).tearDown()

    def show_commands_at_teardown(self):
        self.logger.debug(self.vapi.cli("show session verbose 2"))
        self.logger.debug(self.vapi.cli("show app mq"))

    @unittest.skipUnless(_have_iperf3, "'%s' not found, Skipping.")
    def test_ldp_thru_host_stack_iperf3(self):
        """run LDP thru host stack iperf3 test"""

        self.timeout = self.client_iperf3_timeout
        self.thru_host_stack_test(
            iperf3, self.server_iperf3_args, iperf3, self.client_iperf3_args
        )

    @unittest.skipUnless(_have_iperf3, "'%s' not found, Skipping.")
    def test_ldp_thru_host_stack_iperf3_mss(self):
        """run LDP thru host stack iperf3 test with mss option"""

        self.timeout = self.client_iperf3_timeout
        self.client_iperf3_args.append("-M 1000")
        self.thru_host_stack_test(
            iperf3, self.server_iperf3_args, iperf3, self.client_iperf3_args
        )


@tag_fixme_asan
class LDPThruHostStackIperfUdp(VCLTestCase):
    """LDP Thru Host Stack Iperf UDP"""

    @classmethod
    def setUpClass(cls):
        super(LDPThruHostStackIperfUdp, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(LDPThruHostStackIperfUdp, cls).tearDownClass()

    def setUp(self):
        super(LDPThruHostStackIperfUdp, self).setUp()

        self.thru_host_stack_setup()
        self.client_iperf3_timeout = 20
        self.client_iperf3_args = [
            "-4",
            "-t 2",
            "-u",
            "-l 1400",
            "-P 2",
            "-c",
            self.loop0.local_ip4,
        ]
        self.server_iperf3_args = ["-4", "-s"]

    def tearDown(self):
        self.thru_host_stack_tear_down()
        super(LDPThruHostStackIperfUdp, self).tearDown()

    def show_commands_at_teardown(self):
        self.logger.debug(self.vapi.cli("show session verbose 2"))
        self.logger.debug(self.vapi.cli("show app mq"))

    @unittest.skipUnless(_have_iperf3, "'%s' not found, Skipping.")
    def test_ldp_thru_host_stack_iperf3_udp(self):
        """run LDP thru host stack iperf3 UDP test"""

        self.timeout = self.client_iperf3_timeout
        self.thru_host_stack_test(
            iperf3, self.server_iperf3_args, iperf3, self.client_iperf3_args
        )


@tag_fixme_asan
class LDPIpv6CutThruTestCase(VCLTestCase):
    """LDP IPv6 Cut Thru Tests"""

    @classmethod
    def setUpClass(cls):
        super(LDPIpv6CutThruTestCase, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(LDPIpv6CutThruTestCase, cls).tearDownClass()

    def show_commands_at_teardown(self):
        self.logger.debug(self.vapi.cli("show session verbose 2"))
        self.logger.debug(self.vapi.cli("show app mq"))

    def setUp(self):
        super(LDPIpv6CutThruTestCase, self).setUp()

        self.cut_thru_setup()
        self.client_iperf3_timeout = 20
        self.client_uni_dir_nsock_timeout = 20
        self.client_bi_dir_nsock_timeout = 20
        self.client_ipv6_echo_test_args = [
            "-6",
            "-E",
            self.echo_phrase,
            "-X",
            self.server_ipv6_addr,
            self.server_port,
        ]
        self.client_ipv6_iperf3_args = ["-6", "-t 2", "-c", self.server_ipv6_addr]
        self.server_ipv6_iperf3_args = ["-6", "-s"]
        self.client_ipv6_uni_dir_nsock_test_args = [
            "-N",
            "1000",
            "-U",
            "-X",
            "-6",
            "-I",
            "2",
            self.server_ipv6_addr,
            self.server_port,
        ]
        self.client_ipv6_bi_dir_nsock_test_args = [
            "-N",
            "1000",
            "-B",
            "-X",
            "-6",
            "-I",
            "2",
            self.server_ipv6_addr,
            self.server_port,
        ]

    def tearDown(self):
        super(LDPIpv6CutThruTestCase, self).tearDown()
        self.cut_thru_tear_down()

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_ldp_ipv6_cut_thru_echo(self):
        """run LDP IPv6 cut thru echo test"""

        self.cut_thru_test(
            "sock_test_server",
            self.server_ipv6_args,
            "sock_test_client",
            self.client_ipv6_echo_test_args,
        )

    @unittest.skipUnless(_have_iperf3, "'%s' not found, Skipping.")
    def test_ldp_ipv6_cut_thru_iperf3(self):
        """run LDP IPv6 cut thru iperf3 test"""

        self.timeout = self.client_iperf3_timeout
        self.cut_thru_test(
            iperf3, self.server_ipv6_iperf3_args, iperf3, self.client_ipv6_iperf3_args
        )

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_ldp_ipv6_cut_thru_uni_dir_nsock(self):
        """run LDP IPv6 cut thru uni-directional (multiple sockets) test"""

        self.timeout = self.client_uni_dir_nsock_timeout
        self.cut_thru_test(
            "sock_test_server",
            self.server_ipv6_args,
            "sock_test_client",
            self.client_ipv6_uni_dir_nsock_test_args,
        )

    @unittest.skipUnless(config.extended, "part of extended tests")
    @unittest.skip("sock test apps need to be improved")
    def test_ldp_ipv6_cut_thru_bi_dir_nsock(self):
        """run LDP IPv6 cut thru bi-directional (multiple sockets) test"""

        self.timeout = self.client_bi_dir_nsock_timeout
        self.cut_thru_test(
            "sock_test_server",
            self.server_ipv6_args,
            "sock_test_client",
            self.client_ipv6_bi_dir_nsock_test_args,
        )


@unittest.skipIf(
    "hs_apps" in config.excluded_plugins, "Exclude tests requiring hs_apps plugin"
)
class VCLIpv6CutThruTestCase(VCLTestCase):
    """VCL IPv6 Cut Thru Tests"""

    @classmethod
    def setUpClass(cls):
        super(VCLIpv6CutThruTestCase, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(VCLIpv6CutThruTestCase, cls).tearDownClass()

    def show_commands_at_teardown(self):
        self.logger.debug(self.vapi.cli("show session verbose 2"))
        self.logger.debug(self.vapi.cli("show app mq"))

    def setUp(self):
        super(VCLIpv6CutThruTestCase, self).setUp()

        self.cut_thru_setup()
        self.client_uni_dir_nsock_timeout = 20
        self.client_bi_dir_nsock_timeout = 20
        self.client_ipv6_echo_test_args = [
            "-6",
            "-E",
            self.echo_phrase,
            "-X",
            self.server_ipv6_addr,
            self.server_port,
        ]
        self.client_ipv6_uni_dir_nsock_test_args = [
            "-N",
            "1000",
            "-U",
            "-X",
            "-6",
            "-I",
            "2",
            self.server_ipv6_addr,
            self.server_port,
        ]
        self.client_ipv6_bi_dir_nsock_test_args = [
            "-N",
            "1000",
            "-B",
            "-X",
            "-6",
            "-I",
            "2",
            self.server_ipv6_addr,
            self.server_port,
        ]

    def tearDown(self):
        super(VCLIpv6CutThruTestCase, self).tearDown()
        self.cut_thru_tear_down()

    def show_commands_at_teardown(self):
        self.logger.debug(self.vapi.cli("show session verbose 2"))
        self.logger.debug(self.vapi.cli("show app mq"))

    def test_vcl_ipv6_cut_thru_echo(self):
        """run VCL IPv6 cut thru echo test"""

        self.cut_thru_test(
            "vcl_test_server",
            self.server_ipv6_args,
            "vcl_test_client",
            self.client_ipv6_echo_test_args,
        )

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_vcl_ipv6_cut_thru_uni_dir_nsock(self):
        """run VCL IPv6 cut thru uni-directional (multiple sockets) test"""

        self.timeout = self.client_uni_dir_nsock_timeout
        self.cut_thru_test(
            "vcl_test_server",
            self.server_ipv6_args,
            "vcl_test_client",
            self.client_ipv6_uni_dir_nsock_test_args,
        )

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_vcl_ipv6_cut_thru_bi_dir_nsock(self):
        """run VCL IPv6 cut thru bi-directional (multiple sockets) test"""

        self.timeout = self.client_bi_dir_nsock_timeout
        self.cut_thru_test(
            "vcl_test_server",
            self.server_ipv6_args,
            "vcl_test_client",
            self.client_ipv6_bi_dir_nsock_test_args,
        )


@unittest.skipIf(
    "hs_apps" in config.excluded_plugins, "Exclude tests requiring hs_apps plugin"
)
class VCLIpv6ThruHostStackEcho(VCLTestCase):
    """VCL IPv6 Thru Host Stack Echo"""

    @classmethod
    def setUpClass(cls):
        super(VCLIpv6ThruHostStackEcho, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(VCLIpv6ThruHostStackEcho, cls).tearDownClass()

    def setUp(self):
        super(VCLIpv6ThruHostStackEcho, self).setUp()

        self.thru_host_stack_ipv6_setup()
        self.client_ipv6_echo_test_args = [
            "-6",
            "-E",
            self.echo_phrase,
            "-X",
            self.loop0.local_ip6,
            self.server_port,
        ]

    def tearDown(self):
        self.thru_host_stack_ipv6_tear_down()
        super(VCLIpv6ThruHostStackEcho, self).tearDown()

    def test_vcl_ipv6_thru_host_stack_echo(self):
        """run VCL IPv6 thru host stack echo test"""

        self.thru_host_stack_test(
            "vcl_test_server",
            self.server_ipv6_args,
            "vcl_test_client",
            self.client_ipv6_echo_test_args,
        )


@unittest.skipIf(
    "hs_apps" in config.excluded_plugins, "Exclude tests requiring hs_apps plugin"
)
class VCLCutThruTestCaseBAPI(VCLTestCase):
    """VCL Cut Thru BAPI Test"""

    @classmethod
    def setUpClass(cls):
        cls.session_startup = ["poll-main", "use-bapi-socket-api"]
        super(VCLCutThruTestCaseBAPI, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(VCLCutThruTestCaseBAPI, cls).tearDownClass()

    def setUp(self):
        super(VCLCutThruTestCaseBAPI, self).setUp()

        self.cut_thru_setup()
        self.client_uni_dir_test_args = [
            "-N",
            "1000",
            self.server_addr,
            self.server_port,
        ]
        self.sapi_client_sock = ""
        self.sapi_server_sock = ""

    def tearDown(self):
        super(VCLCutThruTestCaseBAPI, self).tearDown()

    def show_commands_at_teardown(self):
        self.logger.debug(self.vapi.cli("show session verbose 2"))
        self.logger.debug(self.vapi.cli("show app mq"))

    def test_vcl_cut_thru_tcp_bapi(self):
        """run VCL cut thru tcp test bapi"""

        # Single binary api test after switching to app socket api as default
        self.cut_thru_test(
            "vcl_test_server",
            self.server_args,
            "vcl_test_client",
            self.client_uni_dir_test_args,
        )


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
