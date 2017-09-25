#!/usr/bin/env python

import os
import subprocess

from framework import VppTestCase

# Api files path
API_FILES_PATH = "vpp/vpp-api/java"

# Registry jar file name prefix
REGISTRY_JAR_PREFIX = "jvpp-registry"


class TestJVpp(VppTestCase):
    """ JVPP Core Test Case """

    def invoke_for_jvpp_core(self, api_jar_name, test_class_name):
        self.jvpp_connection_test(api_jar_name=api_jar_name,
                                  test_class_name=test_class_name,
                                  timeout=10)

    def test_vpp_core_callback_api(self):
        """ JVPP Core Callback Api Test Case """
        self.invoke_for_jvpp_core(api_jar_name="jvpp-core",
                                  test_class_name="io.fd.vpp.jvpp.core.test."
                                                  "CallbackApiTest")

    def test_vpp_core_future_api(self):
        """JVPP Core Future Api Test Case"""
        self.invoke_for_jvpp_core(api_jar_name="jvpp-core",
                                  test_class_name="io.fd.vpp.jvpp.core.test."
                                                  "FutureApiTest")

    def test_vpp_acl_callback_api(self):
        """ JVPP Acl Callback Api Test Case """
        self.invoke_for_jvpp_core(api_jar_name="jvpp-acl",
                                  test_class_name="io.fd.vpp.jvpp.acl.test."
                                                  "CallbackApiTest")

    def test_vpp_acl_future_api(self):
        """JVPP Acl Future Api Test Case"""
        self.invoke_for_jvpp_core(api_jar_name="jvpp-acl",
                                  test_class_name="io.fd.vpp.jvpp.acl.test."
                                                  "FutureApiTest")

    def test_vpp_ioamexport_callback_api(self):
        """ JVPP Ioamexport Callback Api Test Case """
        self.invoke_for_jvpp_core(api_jar_name="jvpp-ioamexport",
                                  test_class_name="io.fd.vpp.jvpp.ioamexport."
                                                  "test.CallbackApiTest")

    def test_vpp_ioamexport_future_api(self):
        """JVPP Ioamexport Future Api Test Case"""
        self.invoke_for_jvpp_core(api_jar_name="jvpp-ioamexport",
                                  test_class_name="io.fd.vpp.jvpp.ioamexport."
                                                  "test.FutureApiTest")

    def test_vpp_ioampot_callback_api(self):
        """ JVPP Ioampot Callback Api Test Case """
        self.invoke_for_jvpp_core(api_jar_name="jvpp-ioampot",
                                  test_class_name="io.fd.vpp.jvpp.ioampot."
                                                  "test.CallbackApiTest")

    def test_vpp_ioampot_future_api(self):
        """JVPP Ioampot Future Api Test Case"""
        self.invoke_for_jvpp_core(api_jar_name="jvpp-ioampot",
                                  test_class_name="io.fd.vpp.jvpp.ioampot."
                                                  "test.FutureApiTest")

    def test_vpp_ioamtrace_callback_api(self):
        """ JVPP Ioamtrace Callback Api Test Case """
        self.invoke_for_jvpp_core(api_jar_name="jvpp-ioamtrace",
                                  test_class_name="io.fd.vpp.jvpp.ioamtrace."
                                                  "test.CallbackApiTest")

    def test_vpp_ioamtrace_future_api(self):
        """JVPP Ioamtrace Future Api Test Case"""
        self.invoke_for_jvpp_core(api_jar_name="jvpp-ioamtrace",
                                  test_class_name="io.fd.vpp.jvpp.ioamtrace."
                                                  "test.FutureApiTest")

    def test_vpp_snat_callback_api(self):
        """ JVPP Snat Callback Api Test Case """
        self.invoke_for_jvpp_core(api_jar_name="jvpp-nat",
                                  test_class_name="io.fd.vpp.jvpp.nat.test."
                                                  "CallbackApiTest")

    def test_vpp_snat_future_api(self):
        """JVPP Snat Future Api Test Case"""
        self.invoke_for_jvpp_core(api_jar_name="jvpp-nat",
                                  test_class_name="io.fd.vpp.jvpp.nat.test."
                                                  "FutureApiTest")

    def full_jar_name(self, install_dir, jar_name, version):
        return os.path.join(install_dir, API_FILES_PATH,
                            "{0}-{1}.jar".format(jar_name, version))

    def jvpp_connection_test(self, api_jar_name, test_class_name, timeout):
        install_dir = os.getenv('VPP_TEST_BUILD_DIR')
        self.logger.info("Install directory : {0}".format(install_dir))

        version_reply = self.vapi.show_version()
        version = version_reply.version.split("-")[0]
        registry_jar_path = self.full_jar_name(install_dir,
                                               REGISTRY_JAR_PREFIX, version)
        self.logger.info("JVpp Registry jar path : {0}"
                         .format(registry_jar_path))

        api_jar_path = self.full_jar_name(install_dir, api_jar_name, version)
        self.logger.info("Api jar path : {0}".format(api_jar_path))

        # passes shm prefix as parameter to create connection with same value
        command = ["java", "-cp",
                   "{0}:{1}".format(registry_jar_path, api_jar_path),
                   test_class_name, "/{0}-vpe-api".format(self.shm_prefix)]
        self.logger.info("Test Command : {0}, Timeout : {1}".
                         format(command, timeout))

        self.process = subprocess.Popen(command, shell=False,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, bufsize=1,
                                        universal_newlines=True)

        out, err = self.process.communicate()
        self.logger.info("Process output : {0}{1}".format(os.linesep, out))
        self.logger.info("Process error output : {0}{1}"
                         .format(os.linesep, err))
        self.assert_equal(self.process.returncode, 0, "process return code")

    def tearDown(self):
        self.logger.info("Tearing down jvpp test")
        super(TestJVpp, self).tearDown()
        if hasattr(self, 'process') and self.process.poll() is None:
            self.process.kill()
