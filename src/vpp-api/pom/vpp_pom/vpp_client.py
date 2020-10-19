# Copyright (c) 2020 Cisco and/or its affiliates.
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

import logging
import os
import fnmatch
import subprocess
import time

from vpp_papi.vpp_stats import VPPStats
from .vpp_papi_provider import VppPapiProvider
from .vpp_object import VppObjectRegistry
from .log import RED, GREEN, YELLOW, double_line_delim, single_line_delim, \
    get_logger, colorize
from .hook import PollHook, StepHook, VppDiedError


class BaseVppStartupConf:
    """ Base class for VPP startup configuration """

    def __init__(self, vpp_bin=None):
        self.vpp_bin = vpp_bin

    def format_config(self, human_readable=False):
        if human_readable:
            return self._format_readable()
        else:
            return self._format_subprocess()

    def _format_subprocess(self):
        """Return formatting for use in subprocess"""
        pass

    def _format_readable(self):
        """Return formatted starup config"""
        pass


class VppStartupConfFile(BaseVppStartupConf):
    """VPP startup config file"""

    def __init__(self, path, vpp_bin=None):
        """Init"""
        super(VppStartupConfFile, self).__init__(vpp_bin)
        # FIXME: check if file exists
        self.path = path

    def _format_subprocess(self):
        """Return formatting for use in subprocess"""
        return self._format_readable()

    def _format_readable(self):
        """Return formatted starup config"""
        with open(self.path, "r") as f:
            return f.read()


class VppStartupConf(BaseVppStartupConf):
    """VPP startup config"""

    def __init__(self, vpp_bin=None):
        """Init"""
        super(VppStartupConf, self).__init__(vpp_bin)
        self._config_dict = {}

    @property
    def config_dict(self):
        """Return configuration dictionary"""
        return self._config_dict

    def _format_subprocess(self):
        """Return formatting for use in subprocess"""
        out = []
        if self.vpp_bin:
            out.append(self.vpp_bin)
        for key in self.config_dict:
            out += [key, "{"]
            for param in self.config_dict[key]:
                out += param.split(" ")
            out += ["}"]
        return out

    def _format_readable(self):
        """Return formatted starup config"""
        out = ""
        for key in self.config_dict:
            out += key + " {\n"
            for param in self.config_dict[key]:
                out += "\t" + param + "\n"
            out += "}\n"
        return out

    def add_parameter(self, group, parameter):
        """Add the parameter to the configuration"""
        if not isinstance(parameter, str):
            raise TypeError("\'parameter\' must be string type")
        if group in self._config_dict:
            self._config_dict[group].append(parameter)
        else:
            self._config_dict[group] = [parameter]

    def remove_parameter(self, group, parameter):
        """Add the parameter from the configuration"""
        if not isinstance(parameter, str):
            raise TypeError("\'parameter\' must be string type")
        if group in self._config_dict:
            if parameter in self._config_dict[group]:
                self._config_dict[group].remove(parameter)


# FIXME: crashes if constructed in classmethod
class VppClient(VppPapiProvider):

    debug_gdbserver = False
    debug_gdb = False
    gdbserver_port = 7777
    tempdir = "/tmp/vpp/"

    def __init__(
            self,
            name,
            shm_prefix,
            logger=None,
            read_timeout=5,
            api_socket=None,
            vpp_install_path=os.getenv('VPP_INSTALL_PATH'),
            stats_socket=None):
        if not logger:
            logger = logging.getLogger('VppClient')
        super(
            VppClient,
            self).__init__(
            name,
            shm_prefix,
            logger,
            read_timeout,
            vpp_install_path,
            api_socket=api_socket)
        self._registry = VppObjectRegistry(self.logger)
        self._captures = []
        if stats_socket:
            self.statistics = VPPStats(socketname=stats_socket)
        else:
            self.statistics = VPPStats()

    @property
    def registry(self):
        return self._registry

    def register_capture(self, cap_name):
        """ Register a capture in the testclass """
        # add to the list of captures with current timestamp
        self._captures.append((time.time(), cap_name))

    def pg_start(self):
        """ Enable the PG, wait till it is done, then clean up """
        self.cli("trace add pg-input 1000")
        self.cli('packet-generator enable')
        # PG, when starts, runs to completion -
        # so let's avoid a race condition,
        # and wait a little till it's done.
        # Then clean it up  - and then be gone.
        deadline = time.time() + 300
        while self.cli('show packet-generator').find("Yes") != -1:
            self.sleep(0.01)  # yield
            if time.time() > deadline:
                self.logger.error("Timeout waiting for pg to stop")
                break
        for stamp, cap_name in self._captures:
            self.cli('packet-generator delete %s' % cap_name)
        self._captures = []

    def sleep(self, timeout, remark=None):

        # /* Allow sleep(0) to maintain win32 semantics, and as decreed
        #  * by Guido, only the main thread can be interrupted.
        # */
        # https://github.com/python/cpython/blob/6673decfa0fb078f60587f5cb5e98460eea137c2/Modules/timemodule.c#L1892  # noqa
        if timeout == 0:
            # yield quantum
            if hasattr(os, 'sched_yield'):
                os.sched_yield()
            else:
                time.sleep(0)
            return

        self.logger.debug("Starting sleep for %es (%s)", timeout, remark)
        before = time.time()
        time.sleep(timeout)
        after = time.time()
        if after - before > 2 * timeout:
            self.logger.error("unexpected self.sleep() result - "
                              "slept for %es instead of ~%es!",
                              after - before, timeout)

        self.logger.debug(
            "Finished sleep (%s) - slept %es (wanted %es)",
            remark, after - before, timeout)

    def run_vpp(self, startup_cnf, step=False):
        cmdline = startup_cnf.format_config()

        if self.debug_gdbserver:
            gdbserver = '/usr/bin/gdbserver'
            if not os.path.isfile(gdbserver) or \
                    not os.access(gdbserver, os.X_OK):
                raise Exception("gdbserver binary '%s' does not exist or is "
                                "not executable" % gdbserver)

            cmdline = [gdbserver, 'localhost:{port}'
                       .format(port=self.gdbserver_port)] + self.vpp_cmdline
            self.logger.info("Gdbserver cmdline is %s", " ".join(cmdline))
        try:
            self.vpp_process = subprocess.Popen(cmdline,
                                                stdout=subprocess.PIPE,
                                                stderr=subprocess.PIPE)
        except subprocess.CalledProcessError as e:
            self.logger.critical(
                "Subprocess returned with non-0 return code: ("
                "%s)", e.returncode)
            raise
        except OSError as e:
            self.logger.critical("Subprocess returned with OS error: "
                                 "(%s) %s", e.errno, e.strerror)
            raise
        except Exception as e:
            self.logger.exception("Subprocess returned unexpected from "
                                  "%s:", cmdline)
            raise
        self.wait_for_enter()
        # register step/poll hook
        if step:
            hook = StepHook(self)
        else:
            hook = PollHook(self)
        self.register_hook(hook)
        # poll VPP process
        try:
            hook.poll_vpp()
        except VppDiedError:
            self.logger.critical(
                "VPP died shortly after startup, check the"
                " output to standard error for possible cause")
            raise

    def wait_for_enter(self):
        if self.debug_gdbserver:
            print(double_line_delim)
            print("Spawned GDB server with PID: %d" % self.vpp_process.pid)
        elif self.debug_gdb:
            print(double_line_delim)
            print("Spawned VPP with PID: %d" % self.vpp_process.pid)
        else:
            self.logger.debug("Spawned VPP with PID: %d" %
                              self.vpp_process.pid)
            return
        print(single_line_delim)
        print("You can debug VPP using:")
        if self.debug_gdbserver:
            print("sudo gdb " + self.vpp_bin +
                  " -ex 'target remote localhost:{port}'"
                  .format(port=self.gdbserver_port))
            print("Now is the time to attach gdb by running the above "
                  "command, set up breakpoints etc., then resume VPP from "
                  "within gdb by issuing the 'continue' command")
            self.gdbserver_port += 1
        elif self.debug_gdb:
            print("sudo gdb " + self.vpp_bin + " -ex 'attach %s'" %
                  self.vpp_process.pid)
            print("Now is the time to attach gdb by running the above "
                  "command and set up breakpoints etc., then resume VPP from"
                  " within gdb by issuing the 'continue' command")
        print(single_line_delim)
        input("Press ENTER to continue...")

    def disconnect(self):
        if not hasattr(self, "papi"):
            return
        self.logger.debug(self.vpp.get_stats())
        self.logger.debug("Disconnecting class vapi client on %s",
                          self.__name__)
        super(VppClient, self).disconnect()
        self.logger.debug("Deleting class vapi attribute on %s",
                          self.__name__)
        del self.papi

    def quit_vpp(self):
        self.disconnect()
        if hasattr(self, 'vpp_process'):
            self.vpp_process.poll()
            if self.vpp_process.returncode is None:
                self.wait_for_coredump()
                self.logger.debug("Sending TERM to vpp")
                self.vpp_process.terminate()
                self.logger.debug("Waiting for vpp to die")
                self.vpp_process.communicate()
            self.logger.debug("Deleting class vpp attribute on %s",
                              self.__name__)
            del self.vpp_process

    def wait_for_coredump(self):
        corefile = self.tempdir + "/core"
        if os.path.isfile(corefile):
            self.logger.error("Waiting for coredump to complete: %s", corefile)
            curr_size = os.path.getsize(corefile)
            deadline = time.time() + 60
            ok = False
            while time.time() < deadline:
                self.sleep(1)
                size = curr_size
                curr_size = os.path.getsize(corefile)
                if size == curr_size:
                    ok = True
                    break
            if not ok:
                self.logger.error("Timed out waiting for coredump to complete:"
                                  " %s", corefile)
            else:
                self.logger.error("Coredump complete: %s, size %d",
                                  corefile, curr_size)

    def _debug_quit(self):
        if (self.debug_gdbserver or self.debug_gdb):
            try:
                self.vpp_process.poll()

                if self.vpp_process.returncode is None:
                    print()
                    print(double_line_delim)
                    print("VPP or GDB server is still running")
                    print(single_line_delim)
                    input("When done debugging, press ENTER to kill the "
                          "process and finish running the testcase...")
            except AttributeError:
                pass

    def quit_vpp_class(self):
        """
        Disconnect vpp-api, kill vpp and cleanup shared memory files
        """
        self._debug_quit()

        # first signal that we want to stop the pump thread, then wake it up
        if hasattr(self, 'pump_thread_stop_flag'):
            self.pump_thread_stop_flag.set()
        if hasattr(self, 'pump_thread_wakeup_pipe'):
            os.write(self.pump_thread_wakeup_pipe[1], b'ding dong wake up')
        if hasattr(self, 'pump_thread'):
            self.logger.debug("Waiting for pump thread to stop")
            self.pump_thread.join()
        if hasattr(self, 'vpp_stderr_reader_thread'):
            self.logger.debug("Waiting for stderr pump to stop")
            self.vpp_stderr_reader_thread.join()

        if self.vpp_startup_failed:
            stdout_log = self.logger.info
            stderr_log = self.logger.critical
        else:
            stdout_log = self.logger.info
            stderr_log = self.logger.info

        if hasattr(self, 'vpp_stdout_deque'):
            stdout_log(single_line_delim)
            stdout_log('VPP output to stdout while running %s:', self.__name__)
            stdout_log(single_line_delim)
            vpp_output = "".join(self.vpp_stdout_deque)
            with open(self.tempdir + '/vpp_stdout.txt', 'w') as f:
                f.write(vpp_output)
            stdout_log('\n%s', vpp_output)
            stdout_log(single_line_delim)

        if hasattr(self, 'vpp_stderr_deque'):
            stderr_log(single_line_delim)
            stderr_log('VPP output to stderr while running %s:', self.__name__)
            stderr_log(single_line_delim)
            vpp_output = "".join(self.vpp_stderr_deque)
            with open(self.tempdir + '/vpp_stderr.txt', 'w') as f:
                f.write(vpp_output)
            stderr_log('\n%s', vpp_output)
            stderr_log(single_line_delim)
