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
import paramiko
from scp import SCPClient
from time import time
from robot.api import logger

__all__ = ["exec_cmd"]

# TODO: Attempt to recycle SSH connections
# TODO: load priv key

class SSH(object):

    __MAX_RECV_BUF = 10*1024*1024
    __existing_connections = {}

    def __init__(self):
        self._ssh = paramiko.SSHClient()
        self._ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self._hostname = None

    def _node_hash(self, node):
        return hash(frozenset([node['host'], node['port']]))

    def connect(self, node):
        """Connect to node prior to running exec_command or scp.

        If there already is a connection to the node, this method reuses it.
        """
        self._hostname = node['host']
        node_hash = self._node_hash(node)
        if node_hash in self.__existing_connections:
            self._ssh = self.__existing_connections[node_hash]
        else:
            start = time()
            self._ssh.connect(node['host'], username=node['username'],
                    password=node['password'])
            self.__existing_connections[node_hash] = self._ssh
            logger.trace('connect took {} seconds'.format(time() - start))

    def exec_command(self, cmd, timeout=10):
        """Execute SSH command on a new channel on the connected Node.

        Returns (return_code, stdout, stderr).
        """
        start = time()
        chan = self._ssh.get_transport().open_session()
        if timeout is not None:
            chan.settimeout(int(timeout))
        chan.exec_command(cmd)
        end = time()
        logger.trace('exec_command "{0}" on {1} took {2} seconds'.format(cmd,
            self._hostname, end-start))


        stdout = ""
        while True:
            buf = chan.recv(self.__MAX_RECV_BUF)
            stdout += buf
            if not buf:
                break

        stderr = ""
        while True:
            buf = chan.recv_stderr(self.__MAX_RECV_BUF)
            stderr += buf
            if not buf:
                break

        return_code = chan.recv_exit_status()
        logger.trace('chan_recv/_stderr took {} seconds'.format(time()-end))

        return (return_code, stdout, stderr)

    def scp(self, local_path, remote_path):
        """Copy files from local_path to remote_path.

        connect() method has to be called first!
        """
        logger.trace('SCP {0} to {1}:{2}'.format(
            local_path, self._hostname, remote_path))
        # SCPCLient takes a paramiko transport as its only argument
        scp = SCPClient(self._ssh.get_transport())
        start = time()
        scp.put(local_path, remote_path)
        scp.close()
        end = time()
        logger.trace('SCP took {0} seconds'.format(end-start))

def exec_cmd(node, cmd, timeout=None):
    """Convenience function to ssh/exec/return rc & out.

    Returns (rc, stdout).
    """
    if node is None:
        raise TypeError('Node parameter is None')
    if cmd is None:
        raise TypeError('Command parameter is None')
    if len(cmd) == 0:
        raise ValueError('Empty command parameter')

    ssh = SSH()
    try:
        ssh.connect(node)
    except Exception, e:
        logger.error("Failed to connect to node" + e)
        return None

    try:
        (ret_code, stdout, stderr) = ssh.exec_command(cmd, timeout=timeout)
    except Exception, e:
        logger.error(e)
        return None

    return (ret_code, stdout, stderr)

