#!/usr/bin/env python
import os
import subprocess
from threading import Timer

from framework import VppTestCase

# Api files path
API_FILES_PATH = "build-vpp-native/vpp/vpp-api/java"

# Registry jar file name prefix
REGISTRY_JAR_PREFIX = "jvpp-registry"

# Current version
# TODO - can be read from some constant ?
VERSION = "17.07"

class TestJVpp(VppTestCase):

    def full_jar_name(self, install_dir, jar_name):
        return os.path.join(install_dir, API_FILES_PATH, "{0}-{1}.jar".format(jar_name, VERSION))

    def jvpp_connection_test(self, api_jar_name, test_class_name, timeout):
        install_dir = os.path.dirname(os.path.dirname(os.getenv('VPP_TEST_INSTALL_PATH')))
        print("Install directory : {0}".format(install_dir))

        registry_jar_path = self.full_jar_name(install_dir, REGISTRY_JAR_PREFIX)
        print("JVpp Registry jar path : {0}".format(registry_jar_path))

        api_jar_path = self.full_jar_name(install_dir, api_jar_name)
        print("Api jar path : {0}".format(api_jar_path))

        # passes shm prefix as parameter to create connection with same value
        command = ["java", "-cp", "{0}:{1}".format(registry_jar_path, api_jar_path), test_class_name,
                   "/{0}-vpe-api".format(self.shm_prefix)]
        print("Test Command : {0}, Timeout : {1}".format(command, timeout))

        self.process = subprocess.Popen(command, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=1,
                                   universal_newlines=True)

        out, err = self.process.communicate()
        print("Process output : {0}{1}".format(os.linesep, out))
        print("Process error output : {0}{1}".format(os.linesep, err))
        self.assert_equal(0, self.process.returncode, "process return code")

    def tearDown(self):
        print("Tearing down jvpp test")
        if self.process.poll() is None:
            self.process.kill()