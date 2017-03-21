#!/usr/bin/env python
import os
import subprocess
from threading import Timer

from framework import VppTestCase


class TestJVpp(VppTestCase):
    # Api files path
    API_FILES_PATH = "build-vpp-native/vpp/vpp-api/java"

    # Registry jar file name prefix
    REGISTRY_JAR_PREFIX = "jvpp-registry"

    # Current version
    # TODO - can be read from some constant ?
    VERSION = "17.04"

    def kill_process(self, process):
        try:
            process.kill()
            self.fail("Process timed out")
        except OSError:
            pass  # ignore

    def full_jar_name(self, install_dir, jar_name):
        return os.path.join(install_dir, self.API_FILES_PATH, "{0}-{1}.jar".format(jar_name, self.VERSION))

    def jvpp_connection_test(self, api_jar_name, test_class_name, timeout):
        install_dir = os.path.dirname(os.path.dirname(os.getenv('VPP_TEST_INSTALL_PATH')))
        print("Install directory : {0}".format(install_dir))

        registry_jar_path = self.full_jar_name(install_dir, self.REGISTRY_JAR_PREFIX)
        print("JVpp Registry jar path : {0}".format(registry_jar_path))

        api_jar_path = self.full_jar_name(install_dir, api_jar_name)
        print("Api jar path : {0}".format(api_jar_path))

        command = ["java", "-cp", "{0}:{1}".format(registry_jar_path, api_jar_path), test_class_name]
        print("Test Command : {0}, Timeout : {1}".format(command, timeout))

        process = subprocess.Popen(command, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=1,
                                   universal_newlines=True)

        shutdown_timer = Timer(timeout, self.kill_process, [process])
        shutdown_timer.start()
        process.wait()
        shutdown_timer.cancel()

        out, err = process.communicate()
        print("Process output : {0}{1}".format(os.linesep, out))
        print("Process error output : {0}{1}".format(os.linesep, err))
        self.assert_equal(0, process.returncode, "process return code")
