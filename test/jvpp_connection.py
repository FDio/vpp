#!/usr/bin/env python
import os
import subprocess
from vpp_papi_provider import VppPapiProvider
from threading import Timer

from framework import VppTestCase

# Api files path
API_FILES_PATH = "vpp/vpp-api/java"

# Registry jar file name prefix
REGISTRY_JAR_PREFIX = "jvpp-registry"


class TestJVppConnection(VppTestCase):

    def full_jar_name(self, install_dir, jar_name, version):
        return os.path.join(install_dir, API_FILES_PATH,
                            "{0}-{1}.jar".format(jar_name, version))

    def jvpp_connection_test(self, api_jar_name, test_class_name, timeout):
        install_dir = os.getenv('VPP_TEST_BUILD_DIR')
        print("Install directory : {0}".format(install_dir))

        version_reply = self.vapi.show_version()
        version = version_reply.version.split("-")[0]
        registry_jar_path = self.full_jar_name(install_dir,
                                               REGISTRY_JAR_PREFIX, version)
        print("JVpp Registry jar path : {0}".format(registry_jar_path))

        api_jar_path = self.full_jar_name(install_dir, api_jar_name, version)
        print("Api jar path : {0}".format(api_jar_path))

        # passes shm prefix as parameter to create connection with same value
        command = ["java", "-cp",
                   "{0}:{1}".format(registry_jar_path, api_jar_path),
                   test_class_name, "/{0}-vpe-api".format(self.shm_prefix)]
        print("Test Command : {0}, Timeout : {1}".format(command, timeout))

        self.process = subprocess.Popen(command, shell=False,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, bufsize=1,
                                        universal_newlines=True)

        out, err = self.process.communicate()
        print("Process output : {0}{1}".format(os.linesep, out))
        print("Process error output : {0}{1}".format(os.linesep, err))
        self.assert_equal(self.process.returncode, 0, "process return code")

    def tearDown(self):
        print("Tearing down jvpp test")
        if self.process.poll() is None:
            self.process.kill()
