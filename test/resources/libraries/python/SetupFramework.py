# Copyright (c) 2015 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import shlex
from ssh import SSH
from subprocess import Popen, PIPE, call
from tempfile import NamedTemporaryFile
from os.path import basename
from constants import Constants as con
from robot.api import logger

__all__ = ["SetupFramework"]

class SetupFramework(object):
    """Setup suite run on topology nodes.
    
    Many VAT/CLI based tests need the scripts at remote hosts before executing
    them. This class packs the whole testing directory and copies it over
    to all nodes in topology under /tmp/
    
    """

    def __init__(self):
        pass

    def __pack_framework_dir(self):
        """Pack the testing WS into temp file, return its name."""

        tmpfile = NamedTemporaryFile(suffix=".tgz", prefix="openvpp-testing-")
        file_name = tmpfile.name
        tmpfile.close()

        proc = Popen(shlex.split("tar -zcf {0} .".format(file_name)),
                stdout=PIPE, stderr=PIPE)
        (stdout, stderr) = proc.communicate()

        logger.debug(stdout)
        logger.debug(stderr)

        return_code = proc.wait()
        if 0 != return_code:
            raise Exception("Could not pack testing framework.")

        return file_name

    def __copy_tarball_to_node(self, tarball, node):
        logger.console('Copying tarball to {0}'.format(node['host']))
        ssh = SSH()
        ssh.connect(node)

        ssh.scp(tarball, "/tmp/")

    def __extract_tarball_at_node(self, tarball, node):
        logger.console('Extracting tarball to {0} on {1}'.format(
            con.REMOTE_FW_DIR, node['host'])) 
        ssh = SSH()
        ssh.connect(node)

        cmd = 'rm -rf {1}; mkdir {1} ; sudo -Sn tar -zxf {0} -C {1};'.format(
                tarball, con.REMOTE_FW_DIR)
        (ret_code, stdout, stderr) = ssh.exec_command(cmd, timeout=30)
        if 0 != ret_code:
            logger.error('Unpack error: {0}'.format(stderr))
            raise Exception('Failed to unpack {0} at node {1}'.format(
                tarball, node['host']))

    def __delete_local_tarball(self, tarball):
        call(shlex.split('sh -c "rm {0} > /dev/null 2>&1"'.format(tarball)))

    def setup_framework(self, nodes):
        """Pack the whole directory and extract in temp on each node."""

        tarball = self.__pack_framework_dir()
        logger.console('Framework packed to {0}'.format(tarball))
        remote_tarball = "/tmp/{0}".format(basename(tarball))

        for node in nodes.values():
            self.__copy_tarball_to_node(tarball, node)
            self.__extract_tarball_at_node(remote_tarball, node)

        logger.trace('Test framework copied to all topology nodes')
        self.__delete_local_tarball(tarball)

