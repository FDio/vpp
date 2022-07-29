#!/usr/bin/env python3

from __future__ import print_function
import logging
import sys
import os
import select
import signal
import subprocess
import unittest
import re
import time
import faulthandler
import random
import copy
import platform
import shutil
from collections import deque
from threading import Thread, Event
from inspect import getdoc, isclass
from traceback import format_exception
from logging import FileHandler, DEBUG, Formatter
from enum import Enum
from abc import ABC, abstractmethod
from struct import pack, unpack

import scapy.compat
from scapy.packet import Raw, Packet
from config import config, available_cpus, num_cpus, max_vpp_cpus
import hook as hookmodule
from vpp_pg_interface import VppPGInterface
from vpp_sub_interface import VppSubInterface
from vpp_lo_interface import VppLoInterface
from vpp_bvi_interface import VppBviInterface
from vpp_papi_provider import VppPapiProvider
from vpp_papi import VppEnum
import vpp_papi
from vpp_papi.vpp_stats import VPPStats
from vpp_papi.vpp_transport_socket import VppTransportSocketIOError
from log import (
    RED,
    GREEN,
    YELLOW,
    double_line_delim,
    single_line_delim,
    get_logger,
    colorize,
)
from vpp_object import VppObjectRegistry
from util import ppp, is_core_present
from scapy.layers.inet import IPerror, TCPerror, UDPerror, ICMPerror
from scapy.layers.inet6 import ICMPv6DestUnreach, ICMPv6EchoRequest
from scapy.layers.inet6 import ICMPv6EchoReply


logger = logging.getLogger(__name__)

# Set up an empty logger for the testcase that can be overridden as necessary
null_logger = logging.getLogger("VppTestCase")
null_logger.addHandler(logging.NullHandler())

PASS = 0
FAIL = 1
ERROR = 2
SKIP = 3
TEST_RUN = 4
SKIP_CPU_SHORTAGE = 5


if config.debug_framework:
    import debug_internal

"""
  Test framework module.

  The module provides a set of tools for constructing and running tests and
  representing the results.
"""


class VppDiedError(Exception):
    """exception for reporting that the subprocess has died."""

    signals_by_value = {
        v: k
        for k, v in signal.__dict__.items()
        if k.startswith("SIG") and not k.startswith("SIG_")
    }

    def __init__(self, rv=None, testcase=None, method_name=None):
        self.rv = rv
        self.signal_name = None
        self.testcase = testcase
        self.method_name = method_name

        try:
            self.signal_name = VppDiedError.signals_by_value[-rv]
        except (KeyError, TypeError):
            pass

        if testcase is None and method_name is None:
            in_msg = ""
        else:
            in_msg = " while running %s.%s" % (testcase, method_name)

        if self.rv:
            msg = "VPP subprocess died unexpectedly%s with return code: %d%s." % (
                in_msg,
                self.rv,
                " [%s]" % (self.signal_name if self.signal_name is not None else ""),
            )
        else:
            msg = "VPP subprocess died unexpectedly%s." % in_msg

        super(VppDiedError, self).__init__(msg)


class _PacketInfo(object):
    """Private class to create packet info object.

    Help process information about the next packet.
    Set variables to default values.
    """

    #: Store the index of the packet.
    index = -1
    #: Store the index of the source packet generator interface of the packet.
    src = -1
    #: Store the index of the destination packet generator interface
    #: of the packet.
    dst = -1
    #: Store expected ip version
    ip = -1
    #: Store expected upper protocol
    proto = -1
    #: Store the copy of the former packet.
    data = None

    def __eq__(self, other):
        index = self.index == other.index
        src = self.src == other.src
        dst = self.dst == other.dst
        data = self.data == other.data
        return index and src and dst and data


def pump_output(testclass):
    """pump output from vpp stdout/stderr to proper queues"""
    stdout_fragment = ""
    stderr_fragment = ""
    while not testclass.pump_thread_stop_flag.is_set():
        readable = select.select(
            [
                testclass.vpp.stdout.fileno(),
                testclass.vpp.stderr.fileno(),
                testclass.pump_thread_wakeup_pipe[0],
            ],
            [],
            [],
        )[0]
        if testclass.vpp.stdout.fileno() in readable:
            read = os.read(testclass.vpp.stdout.fileno(), 102400)
            if len(read) > 0:
                split = read.decode("ascii", errors="backslashreplace").splitlines(True)
                if len(stdout_fragment) > 0:
                    split[0] = "%s%s" % (stdout_fragment, split[0])
                if len(split) > 0 and split[-1].endswith("\n"):
                    limit = None
                else:
                    limit = -1
                    stdout_fragment = split[-1]
                testclass.vpp_stdout_deque.extend(split[:limit])
                if not config.cache_vpp_output:
                    for line in split[:limit]:
                        testclass.logger.info("VPP STDOUT: %s" % line.rstrip("\n"))
        if testclass.vpp.stderr.fileno() in readable:
            read = os.read(testclass.vpp.stderr.fileno(), 102400)
            if len(read) > 0:
                split = read.decode("ascii", errors="backslashreplace").splitlines(True)
                if len(stderr_fragment) > 0:
                    split[0] = "%s%s" % (stderr_fragment, split[0])
                if len(split) > 0 and split[-1].endswith("\n"):
                    limit = None
                else:
                    limit = -1
                    stderr_fragment = split[-1]

                testclass.vpp_stderr_deque.extend(split[:limit])
                if not config.cache_vpp_output:
                    for line in split[:limit]:
                        testclass.logger.error("VPP STDERR: %s" % line.rstrip("\n"))
                        # ignoring the dummy pipe here intentionally - the
                        # flag will take care of properly terminating the loop


def _is_platform_aarch64():
    return platform.machine() == "aarch64"


is_platform_aarch64 = _is_platform_aarch64()


class KeepAliveReporter(object):
    """
    Singleton object which reports test start to parent process
    """

    _shared_state = {}

    def __init__(self):
        self.__dict__ = self._shared_state
        self._pipe = None

    @property
    def pipe(self):
        return self._pipe

    @pipe.setter
    def pipe(self, pipe):
        if self._pipe is not None:
            raise Exception("Internal error - pipe should only be set once.")
        self._pipe = pipe

    def send_keep_alive(self, test, desc=None):
        """
        Write current test tmpdir & desc to keep-alive pipe to signal liveness
        """
        if self.pipe is None:
            # if not running forked..
            return

        if isclass(test):
            desc = "%s (%s)" % (desc, unittest.util.strclass(test))
        else:
            desc = test.id()

        self.pipe.send((desc, config.vpp, test.tempdir, test.vpp.pid))


class TestCaseTag(Enum):
    # marks the suites that must run at the end
    # using only a single test runner
    RUN_SOLO = 1
    # marks the suites broken on VPP multi-worker
    FIXME_VPP_WORKERS = 2
    # marks the suites broken when ASan is enabled
    FIXME_ASAN = 3


def create_tag_decorator(e):
    def decorator(cls):
        try:
            cls.test_tags.append(e)
        except AttributeError:
            cls.test_tags = [e]
        return cls

    return decorator


tag_run_solo = create_tag_decorator(TestCaseTag.RUN_SOLO)
tag_fixme_vpp_workers = create_tag_decorator(TestCaseTag.FIXME_VPP_WORKERS)
tag_fixme_asan = create_tag_decorator(TestCaseTag.FIXME_ASAN)


class DummyVpp:
    returncode = None
    pid = 0xCAFEBAFE

    def poll(self):
        pass

    def terminate(self):
        pass


class CPUInterface(ABC):
    cpus = []
    skipped_due_to_cpu_lack = False

    @classmethod
    @abstractmethod
    def get_cpus_required(cls):
        pass

    @classmethod
    def assign_cpus(cls, cpus):
        cls.cpus = cpus


class VppTestCase(CPUInterface, unittest.TestCase):
    """This subclass is a base class for VPP test cases that are implemented as
    classes. It provides methods to create and run test case.
    """

    extra_vpp_statseg_config = ""
    extra_vpp_punt_config = []
    extra_vpp_plugin_config = []
    logger = null_logger
    vapi_response_timeout = 5
    remove_configured_vpp_objects_on_tear_down = True

    @property
    def packet_infos(self):
        """List of packet infos"""
        return self._packet_infos

    @classmethod
    def get_packet_count_for_if_idx(cls, dst_if_index):
        """Get the number of packet info for specified destination if index"""
        if dst_if_index in cls._packet_count_for_dst_if_idx:
            return cls._packet_count_for_dst_if_idx[dst_if_index]
        else:
            return 0

    @classmethod
    def has_tag(cls, tag):
        """if the test case has a given tag - return true"""
        try:
            return tag in cls.test_tags
        except AttributeError:
            pass
        return False

    @classmethod
    def is_tagged_run_solo(cls):
        """if the test case class is timing-sensitive - return true"""
        return cls.has_tag(TestCaseTag.RUN_SOLO)

    @classmethod
    def skip_fixme_asan(cls):
        """if @tag_fixme_asan & ASan is enabled - mark for skip"""
        if cls.has_tag(TestCaseTag.FIXME_ASAN):
            vpp_extra_cmake_args = os.environ.get("VPP_EXTRA_CMAKE_ARGS", "")
            if "DVPP_ENABLE_SANITIZE_ADDR=ON" in vpp_extra_cmake_args:
                cls = unittest.skip("Skipping @tag_fixme_asan tests")(cls)

    @classmethod
    def instance(cls):
        """Return the instance of this testcase"""
        return cls.test_instance

    @classmethod
    def set_debug_flags(cls, d):
        cls.gdbserver_port = 7777
        cls.debug_core = False
        cls.debug_gdb = False
        cls.debug_gdbserver = False
        cls.debug_all = False
        cls.debug_attach = False
        if d is None:
            return
        dl = d.lower()
        if dl == "core":
            cls.debug_core = True
        elif dl == "gdb" or dl == "gdb-all":
            cls.debug_gdb = True
        elif dl == "gdbserver" or dl == "gdbserver-all":
            cls.debug_gdbserver = True
        elif dl == "attach":
            cls.debug_attach = True
        else:
            raise Exception("Unrecognized DEBUG option: '%s'" % d)
        if dl == "gdb-all" or dl == "gdbserver-all":
            cls.debug_all = True

    @classmethod
    def get_vpp_worker_count(cls):
        if not hasattr(cls, "vpp_worker_count"):
            if cls.has_tag(TestCaseTag.FIXME_VPP_WORKERS):
                cls.vpp_worker_count = 0
            else:
                cls.vpp_worker_count = config.vpp_worker_count
        return cls.vpp_worker_count

    @classmethod
    def get_cpus_required(cls):
        return 1 + cls.get_vpp_worker_count()

    @classmethod
    def setUpConstants(cls):
        """Set-up the test case class based on environment variables"""
        cls.step = config.step
        cls.plugin_path = ":".join(config.vpp_plugin_dir)
        cls.test_plugin_path = ":".join(config.vpp_test_plugin_dir)
        cls.extern_plugin_path = ":".join(config.extern_plugin_dir)
        debug_cli = ""
        if cls.step or cls.debug_gdb or cls.debug_gdbserver:
            debug_cli = "cli-listen localhost:5002"
        size = re.search(r"\d+[gG]", config.coredump_size)
        if size:
            coredump_size = f"coredump-size {config.coredump_size}".lower()
        else:
            coredump_size = "coredump-size unlimited"
        default_variant = config.variant
        if default_variant is not None:
            default_variant = "default { variant %s 100 }" % default_variant
        else:
            default_variant = ""

        api_fuzzing = config.api_fuzz
        if api_fuzzing is None:
            api_fuzzing = "off"

        cls.vpp_cmdline = [
            config.vpp,
            "unix",
            "{",
            "nodaemon",
            debug_cli,
            "full-coredump",
            coredump_size,
            "runtime-dir",
            cls.tempdir,
            "}",
            "api-trace",
            "{",
            "on",
            "}",
            "api-segment",
            "{",
            "prefix",
            cls.get_api_segment_prefix(),
            "}",
            "cpu",
            "{",
            "main-core",
            str(cls.cpus[0]),
        ]
        if cls.extern_plugin_path not in (None, ""):
            cls.extra_vpp_plugin_config.append("add-path %s" % cls.extern_plugin_path)
        if cls.get_vpp_worker_count():
            cls.vpp_cmdline.extend(
                ["corelist-workers", ",".join([str(x) for x in cls.cpus[1:]])]
            )
        cls.vpp_cmdline.extend(
            [
                "}",
                "physmem",
                "{",
                "max-size",
                "32m",
                "}",
                "statseg",
                "{",
                "socket-name",
                cls.get_stats_sock_path(),
                cls.extra_vpp_statseg_config,
                "}",
                "socksvr",
                "{",
                "socket-name",
                cls.get_api_sock_path(),
                "}",
                "node { ",
                default_variant,
                "}",
                "api-fuzz {",
                api_fuzzing,
                "}",
                "plugins",
                "{",
                "plugin",
                "dpdk_plugin.so",
                "{",
                "disable",
                "}",
                "plugin",
                "rdma_plugin.so",
                "{",
                "disable",
                "}",
                "plugin",
                "lisp_unittest_plugin.so",
                "{",
                "enable",
                "}",
                "plugin",
                "unittest_plugin.so",
                "{",
                "enable",
                "}",
            ]
            + cls.extra_vpp_plugin_config
            + [
                "}",
            ]
        )

        if cls.extra_vpp_punt_config is not None:
            cls.vpp_cmdline.extend(cls.extra_vpp_punt_config)

        if not cls.debug_attach:
            cls.logger.info("vpp_cmdline args: %s" % cls.vpp_cmdline)
            cls.logger.info("vpp_cmdline: %s" % " ".join(cls.vpp_cmdline))

    @classmethod
    def wait_for_enter(cls):
        if cls.debug_gdbserver:
            print(double_line_delim)
            print("Spawned GDB server with PID: %d" % cls.vpp.pid)
        elif cls.debug_gdb:
            print(double_line_delim)
            print("Spawned VPP with PID: %d" % cls.vpp.pid)
        else:
            cls.logger.debug("Spawned VPP with PID: %d" % cls.vpp.pid)
            return
        print(single_line_delim)
        print("You can debug VPP using:")
        if cls.debug_gdbserver:
            print(
                f"sudo gdb {config.vpp} "
                f"-ex 'target remote localhost:{cls.gdbserver_port}'"
            )
            print(
                "Now is the time to attach gdb by running the above "
                "command, set up breakpoints etc., then resume VPP from "
                "within gdb by issuing the 'continue' command"
            )
            cls.gdbserver_port += 1
        elif cls.debug_gdb:
            print(f"sudo gdb {config.vpp} -ex 'attach {cls.vpp.pid}'")
            print(
                "Now is the time to attach gdb by running the above "
                "command and set up breakpoints etc., then resume VPP from"
                " within gdb by issuing the 'continue' command"
            )
        print(single_line_delim)
        input("Press ENTER to continue running the testcase...")

    @classmethod
    def attach_vpp(cls):
        cls.vpp = DummyVpp()

    @classmethod
    def run_vpp(cls):
        cls.logger.debug(f"Assigned cpus: {cls.cpus}")
        cmdline = cls.vpp_cmdline

        if cls.debug_gdbserver:
            gdbserver = "/usr/bin/gdbserver"
            if not os.path.isfile(gdbserver) or not os.access(gdbserver, os.X_OK):
                raise Exception(
                    "gdbserver binary '%s' does not exist or is "
                    "not executable" % gdbserver
                )

            cmdline = [
                gdbserver,
                "localhost:{port}".format(port=cls.gdbserver_port),
            ] + cls.vpp_cmdline
            cls.logger.info("Gdbserver cmdline is %s", " ".join(cmdline))

        try:
            cls.vpp = subprocess.Popen(
                cmdline, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
        except subprocess.CalledProcessError as e:
            cls.logger.critical(
                "Subprocess returned with non-0 return code: (%s)", e.returncode
            )
            raise
        except OSError as e:
            cls.logger.critical(
                "Subprocess returned with OS error: (%s) %s", e.errno, e.strerror
            )
            raise
        except Exception as e:
            cls.logger.exception("Subprocess returned unexpected from %s:", cmdline)
            raise

        cls.wait_for_enter()

    @classmethod
    def wait_for_coredump(cls):
        corefile = cls.tempdir + "/core"
        if os.path.isfile(corefile):
            cls.logger.error("Waiting for coredump to complete: %s", corefile)
            curr_size = os.path.getsize(corefile)
            deadline = time.time() + 60
            ok = False
            while time.time() < deadline:
                cls.sleep(1)
                size = curr_size
                curr_size = os.path.getsize(corefile)
                if size == curr_size:
                    ok = True
                    break
            if not ok:
                cls.logger.error(
                    "Timed out waiting for coredump to complete: %s", corefile
                )
            else:
                cls.logger.error("Coredump complete: %s, size %d", corefile, curr_size)

    @classmethod
    def get_stats_sock_path(cls):
        return "%s/stats.sock" % cls.tempdir

    @classmethod
    def get_api_sock_path(cls):
        return "%s/api.sock" % cls.tempdir

    @classmethod
    def get_api_segment_prefix(cls):
        return os.path.basename(cls.tempdir)  # Only used for VAPI

    @classmethod
    def get_tempdir(cls):
        if cls.debug_attach:
            tmpdir = f"{config.tmp_dir}/unittest-attach-gdb"
        else:
            tmpdir = f"{config.tmp_dir}/vpp-unittest-{cls.__name__}"
            if config.wipe_tmp_dir:
                shutil.rmtree(tmpdir, ignore_errors=True)
            os.mkdir(tmpdir)
        return tmpdir

    @classmethod
    def create_file_handler(cls):
        if config.log_dir is None:
            cls.file_handler = FileHandler(f"{cls.tempdir}/log.txt")
            return

        logdir = f"{config.log_dir}/vpp-unittest-{cls.__name__}"
        if config.wipe_tmp_dir:
            shutil.rmtree(logdir, ignore_errors=True)
        os.mkdir(logdir)
        cls.file_handler = FileHandler(f"{logdir}/log.txt")

    @classmethod
    def setUpClass(cls):
        """
        Perform class setup before running the testcase
        Remove shared memory files, start vpp and connect the vpp-api
        """
        super(VppTestCase, cls).setUpClass()
        cls.logger = get_logger(cls.__name__)
        random.seed(config.rnd_seed)
        if hasattr(cls, "parallel_handler"):
            cls.logger.addHandler(cls.parallel_handler)
            cls.logger.propagate = False
        cls.set_debug_flags(config.debug)
        cls.tempdir = cls.get_tempdir()
        cls.create_file_handler()
        cls.file_handler.setFormatter(
            Formatter(fmt="%(asctime)s,%(msecs)03d %(message)s", datefmt="%H:%M:%S")
        )
        cls.file_handler.setLevel(DEBUG)
        cls.logger.addHandler(cls.file_handler)
        cls.logger.debug("--- setUpClass() for %s called ---" % cls.__name__)
        os.chdir(cls.tempdir)
        cls.logger.info(
            "Temporary dir is %s, api socket is %s",
            cls.tempdir,
            cls.get_api_sock_path(),
        )
        cls.logger.debug("Random seed is %s", config.rnd_seed)
        cls.setUpConstants()
        cls.reset_packet_infos()
        cls._pcaps = []
        cls._old_pcaps = []
        cls.verbose = 0
        cls.vpp_dead = False
        cls.registry = VppObjectRegistry()
        cls.vpp_startup_failed = False
        cls.reporter = KeepAliveReporter()
        # need to catch exceptions here because if we raise, then the cleanup
        # doesn't get called and we might end with a zombie vpp
        try:
            if cls.debug_attach:
                cls.attach_vpp()
            else:
                cls.run_vpp()
            cls.reporter.send_keep_alive(cls, "setUpClass")
            VppTestResult.current_test_case_info = TestCaseInfo(
                cls.logger, cls.tempdir, cls.vpp.pid, config.vpp
            )
            cls.vpp_stdout_deque = deque()
            cls.vpp_stderr_deque = deque()
            if not cls.debug_attach:
                cls.pump_thread_stop_flag = Event()
                cls.pump_thread_wakeup_pipe = os.pipe()
                cls.pump_thread = Thread(target=pump_output, args=(cls,))
                cls.pump_thread.daemon = True
                cls.pump_thread.start()
            if cls.debug_gdb or cls.debug_gdbserver or cls.debug_attach:
                cls.vapi_response_timeout = 0
            cls.vapi = VppPapiProvider(cls.__name__, cls, cls.vapi_response_timeout)
            if cls.step:
                hook = hookmodule.StepHook(cls)
            else:
                hook = hookmodule.PollHook(cls)
            cls.vapi.register_hook(hook)
            cls.statistics = VPPStats(socketname=cls.get_stats_sock_path())
            try:
                hook.poll_vpp()
            except VppDiedError:
                cls.vpp_startup_failed = True
                cls.logger.critical(
                    "VPP died shortly after startup, check the"
                    " output to standard error for possible cause"
                )
                raise
            try:
                cls.vapi.connect()
            except (vpp_papi.VPPIOError, Exception) as e:
                cls.logger.debug("Exception connecting to vapi: %s" % e)
                cls.vapi.disconnect()

                if cls.debug_gdbserver:
                    print(
                        colorize(
                            "You're running VPP inside gdbserver but "
                            "VPP-API connection failed, did you forget "
                            "to 'continue' VPP from within gdb?",
                            RED,
                        )
                    )
                raise e
            if cls.debug_attach:
                last_line = cls.vapi.cli("show thread").split("\n")[-2]
                cls.vpp_worker_count = int(last_line.split(" ")[0])
                print("Detected VPP with %s workers." % cls.vpp_worker_count)
        except vpp_papi.VPPRuntimeError as e:
            cls.logger.debug("%s" % e)
            cls.quit()
            raise e
        except Exception as e:
            cls.logger.debug("Exception connecting to VPP: %s" % e)
            cls.quit()
            raise e

    @classmethod
    def _debug_quit(cls):
        if cls.debug_gdbserver or cls.debug_gdb:
            try:
                cls.vpp.poll()

                if cls.vpp.returncode is None:
                    print()
                    print(double_line_delim)
                    print("VPP or GDB server is still running")
                    print(single_line_delim)
                    input(
                        "When done debugging, press ENTER to kill the "
                        "process and finish running the testcase..."
                    )
            except AttributeError:
                pass

    @classmethod
    def quit(cls):
        """
        Disconnect vpp-api, kill vpp and cleanup shared memory files
        """
        cls._debug_quit()

        # first signal that we want to stop the pump thread, then wake it up
        if hasattr(cls, "pump_thread_stop_flag"):
            cls.pump_thread_stop_flag.set()
        if hasattr(cls, "pump_thread_wakeup_pipe"):
            os.write(cls.pump_thread_wakeup_pipe[1], b"ding dong wake up")
        if hasattr(cls, "pump_thread"):
            cls.logger.debug("Waiting for pump thread to stop")
            cls.pump_thread.join()
        if hasattr(cls, "vpp_stderr_reader_thread"):
            cls.logger.debug("Waiting for stderr pump to stop")
            cls.vpp_stderr_reader_thread.join()

        if hasattr(cls, "vpp"):
            if hasattr(cls, "vapi"):
                cls.logger.debug(cls.vapi.vpp.get_stats())
                cls.logger.debug("Disconnecting class vapi client on %s", cls.__name__)
                cls.vapi.disconnect()
                cls.logger.debug("Deleting class vapi attribute on %s", cls.__name__)
                del cls.vapi
            cls.vpp.poll()
            if not cls.debug_attach and cls.vpp.returncode is None:
                cls.wait_for_coredump()
                cls.logger.debug("Sending TERM to vpp")
                cls.vpp.terminate()
                cls.logger.debug("Waiting for vpp to die")
                try:
                    outs, errs = cls.vpp.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    cls.vpp.kill()
                    outs, errs = cls.vpp.communicate()
            cls.logger.debug("Deleting class vpp attribute on %s", cls.__name__)
            if not cls.debug_attach:
                cls.vpp.stdout.close()
                cls.vpp.stderr.close()
            del cls.vpp

        if cls.vpp_startup_failed:
            stdout_log = cls.logger.info
            stderr_log = cls.logger.critical
        else:
            stdout_log = cls.logger.info
            stderr_log = cls.logger.info

        if hasattr(cls, "vpp_stdout_deque"):
            stdout_log(single_line_delim)
            stdout_log("VPP output to stdout while running %s:", cls.__name__)
            stdout_log(single_line_delim)
            vpp_output = "".join(cls.vpp_stdout_deque)
            with open(cls.tempdir + "/vpp_stdout.txt", "w") as f:
                f.write(vpp_output)
            stdout_log("\n%s", vpp_output)
            stdout_log(single_line_delim)

        if hasattr(cls, "vpp_stderr_deque"):
            stderr_log(single_line_delim)
            stderr_log("VPP output to stderr while running %s:", cls.__name__)
            stderr_log(single_line_delim)
            vpp_output = "".join(cls.vpp_stderr_deque)
            with open(cls.tempdir + "/vpp_stderr.txt", "w") as f:
                f.write(vpp_output)
            stderr_log("\n%s", vpp_output)
            stderr_log(single_line_delim)

    @classmethod
    def tearDownClass(cls):
        """Perform final cleanup after running all tests in this test-case"""
        cls.logger.debug("--- tearDownClass() for %s called ---" % cls.__name__)
        cls.reporter.send_keep_alive(cls, "tearDownClass")
        cls.quit()
        cls.file_handler.close()
        cls.reset_packet_infos()
        if config.debug_framework:
            debug_internal.on_tear_down_class(cls)

    def show_commands_at_teardown(self):
        """Allow subclass specific teardown logging additions."""
        self.logger.info("--- No test specific show commands provided. ---")

    def tearDown(self):
        """Show various debug prints after each test"""
        self.logger.debug(
            "--- tearDown() for %s.%s(%s) called ---"
            % (self.__class__.__name__, self._testMethodName, self._testMethodDoc)
        )

        try:
            if not self.vpp_dead:
                self.logger.debug(self.vapi.cli("show trace max 1000"))
                self.logger.info(self.vapi.ppcli("show interface"))
                self.logger.info(self.vapi.ppcli("show hardware"))
                self.logger.info(self.statistics.set_errors_str())
                self.logger.info(self.vapi.ppcli("show run"))
                self.logger.info(self.vapi.ppcli("show log"))
                self.logger.info(self.vapi.ppcli("show bihash"))
                self.logger.info("Logging testcase specific show commands.")
                self.show_commands_at_teardown()
                if self.remove_configured_vpp_objects_on_tear_down:
                    self.registry.remove_vpp_config(self.logger)
            # Save/Dump VPP api trace log
            m = self._testMethodName
            api_trace = "vpp_api_trace.%s.%d.log" % (m, self.vpp.pid)
            tmp_api_trace = "/tmp/%s" % api_trace
            vpp_api_trace_log = "%s/%s" % (self.tempdir, api_trace)
            self.logger.info(self.vapi.ppcli("api trace save %s" % api_trace))
            self.logger.info("Moving %s to %s\n" % (tmp_api_trace, vpp_api_trace_log))
            os.rename(tmp_api_trace, vpp_api_trace_log)
        except VppTransportSocketIOError:
            self.logger.debug(
                "VppTransportSocketIOError: Vpp dead. Cannot log show commands."
            )
            self.vpp_dead = True
        else:
            self.registry.unregister_all(self.logger)

    def setUp(self):
        """Clear trace before running each test"""
        super(VppTestCase, self).setUp()
        self.reporter.send_keep_alive(self)
        if self.vpp_dead:
            raise VppDiedError(
                rv=None,
                testcase=self.__class__.__name__,
                method_name=self._testMethodName,
            )
        self.sleep(0.1, "during setUp")
        self.vpp_stdout_deque.append(
            "--- test setUp() for %s.%s(%s) starts here ---\n"
            % (self.__class__.__name__, self._testMethodName, self._testMethodDoc)
        )
        self.vpp_stderr_deque.append(
            "--- test setUp() for %s.%s(%s) starts here ---\n"
            % (self.__class__.__name__, self._testMethodName, self._testMethodDoc)
        )
        self.vapi.cli("clear trace")
        # store the test instance inside the test class - so that objects
        # holding the class can access instance methods (like assertEqual)
        type(self).test_instance = self

    @classmethod
    def pg_enable_capture(cls, interfaces=None):
        """
        Enable capture on packet-generator interfaces

        :param interfaces: iterable interface indexes (if None,
                           use self.pg_interfaces)

        """
        if interfaces is None:
            interfaces = cls.pg_interfaces
        for i in interfaces:
            i.enable_capture()

    @classmethod
    def register_pcap(cls, intf, worker):
        """Register a pcap in the testclass"""
        # add to the list of captures with current timestamp
        cls._pcaps.append((intf, worker))

    @classmethod
    def get_vpp_time(cls):
        # processes e.g. "Time now 2.190522, Wed, 11 Mar 2020 17:29:54 GMT"
        # returns float("2.190522")
        timestr = cls.vapi.cli("show clock")
        head, sep, tail = timestr.partition(",")
        head, sep, tail = head.partition("Time now")
        return float(tail)

    @classmethod
    def sleep_on_vpp_time(cls, sec):
        """Sleep according to time in VPP world"""
        # On a busy system with many processes
        # we might end up with VPP time being slower than real world
        # So take that into account when waiting for VPP to do something
        start_time = cls.get_vpp_time()
        while cls.get_vpp_time() - start_time < sec:
            cls.sleep(0.1)

    @classmethod
    def pg_start(cls, trace=True):
        """Enable the PG, wait till it is done, then clean up"""
        for (intf, worker) in cls._old_pcaps:
            intf.handle_old_pcap_file(intf.get_in_path(worker), intf.in_history_counter)
        cls._old_pcaps = []
        if trace:
            cls.vapi.cli("clear trace")
            cls.vapi.cli("trace add pg-input 1000")
        cls.vapi.cli("packet-generator enable")
        # PG, when starts, runs to completion -
        # so let's avoid a race condition,
        # and wait a little till it's done.
        # Then clean it up  - and then be gone.
        deadline = time.time() + 300
        while cls.vapi.cli("show packet-generator").find("Yes") != -1:
            cls.sleep(0.01)  # yield
            if time.time() > deadline:
                cls.logger.error("Timeout waiting for pg to stop")
                break
        for intf, worker in cls._pcaps:
            cls.vapi.cli("packet-generator delete %s" % intf.get_cap_name(worker))
        cls._old_pcaps = cls._pcaps
        cls._pcaps = []

    @classmethod
    def create_pg_interfaces_internal(cls, interfaces, gso=0, gso_size=0, mode=None):
        """
        Create packet-generator interfaces.

        :param interfaces: iterable indexes of the interfaces.
        :returns: List of created interfaces.

        """
        result = []
        for i in interfaces:
            intf = VppPGInterface(cls, i, gso, gso_size, mode)
            setattr(cls, intf.name, intf)
            result.append(intf)
        cls.pg_interfaces = result
        return result

    @classmethod
    def create_pg_ip4_interfaces(cls, interfaces, gso=0, gso_size=0):
        pgmode = VppEnum.vl_api_pg_interface_mode_t
        return cls.create_pg_interfaces_internal(
            interfaces, gso, gso_size, pgmode.PG_API_MODE_IP4
        )

    @classmethod
    def create_pg_ip6_interfaces(cls, interfaces, gso=0, gso_size=0):
        pgmode = VppEnum.vl_api_pg_interface_mode_t
        return cls.create_pg_interfaces_internal(
            interfaces, gso, gso_size, pgmode.PG_API_MODE_IP6
        )

    @classmethod
    def create_pg_interfaces(cls, interfaces, gso=0, gso_size=0):
        pgmode = VppEnum.vl_api_pg_interface_mode_t
        return cls.create_pg_interfaces_internal(
            interfaces, gso, gso_size, pgmode.PG_API_MODE_ETHERNET
        )

    @classmethod
    def create_pg_ethernet_interfaces(cls, interfaces, gso=0, gso_size=0):
        pgmode = VppEnum.vl_api_pg_interface_mode_t
        return cls.create_pg_interfaces_internal(
            interfaces, gso, gso_size, pgmode.PG_API_MODE_ETHERNET
        )

    @classmethod
    def create_loopback_interfaces(cls, count):
        """
        Create loopback interfaces.

        :param count: number of interfaces created.
        :returns: List of created interfaces.
        """
        result = [VppLoInterface(cls) for i in range(count)]
        for intf in result:
            setattr(cls, intf.name, intf)
        cls.lo_interfaces = result
        return result

    @classmethod
    def create_bvi_interfaces(cls, count):
        """
        Create BVI interfaces.

        :param count: number of interfaces created.
        :returns: List of created interfaces.
        """
        result = [VppBviInterface(cls) for i in range(count)]
        for intf in result:
            setattr(cls, intf.name, intf)
        cls.bvi_interfaces = result
        return result

    @staticmethod
    def extend_packet(packet, size, padding=" "):
        """
        Extend packet to given size by padding with spaces or custom padding
        NOTE: Currently works only when Raw layer is present.

        :param packet: packet
        :param size: target size
        :param padding: padding used to extend the payload

        """
        packet_len = len(packet) + 4
        extend = size - packet_len
        if extend > 0:
            num = (extend // len(padding)) + 1
            packet[Raw].load += (padding * num)[:extend].encode("ascii")

    @classmethod
    def reset_packet_infos(cls):
        """Reset the list of packet info objects and packet counts to zero"""
        cls._packet_infos = {}
        cls._packet_count_for_dst_if_idx = {}

    @classmethod
    def create_packet_info(cls, src_if, dst_if):
        """
        Create packet info object containing the source and destination indexes
        and add it to the testcase's packet info list

        :param VppInterface src_if: source interface
        :param VppInterface dst_if: destination interface

        :returns: _PacketInfo object

        """
        info = _PacketInfo()
        info.index = len(cls._packet_infos)
        info.src = src_if.sw_if_index
        info.dst = dst_if.sw_if_index
        if isinstance(dst_if, VppSubInterface):
            dst_idx = dst_if.parent.sw_if_index
        else:
            dst_idx = dst_if.sw_if_index
        if dst_idx in cls._packet_count_for_dst_if_idx:
            cls._packet_count_for_dst_if_idx[dst_idx] += 1
        else:
            cls._packet_count_for_dst_if_idx[dst_idx] = 1
        cls._packet_infos[info.index] = info
        return info

    @staticmethod
    def info_to_payload(info):
        """
        Convert _PacketInfo object to packet payload

        :param info: _PacketInfo object

        :returns: string containing serialized data from packet info
        """

        # retrieve payload, currently 18 bytes (4 x ints + 1 short)
        return pack("iiiih", info.index, info.src, info.dst, info.ip, info.proto)

    @staticmethod
    def payload_to_info(payload, payload_field="load"):
        """
        Convert packet payload to _PacketInfo object

        :param payload: packet payload
        :type payload:  <class 'scapy.packet.Raw'>
        :param payload_field: packet fieldname of payload "load" for
                <class 'scapy.packet.Raw'>
        :type payload_field: str
        :returns: _PacketInfo object containing de-serialized data from payload

        """

        # retrieve payload, currently 18 bytes (4 x ints + 1 short)
        payload_b = getattr(payload, payload_field)[:18]

        info = _PacketInfo()
        info.index, info.src, info.dst, info.ip, info.proto = unpack("iiiih", payload_b)

        # some SRv6 TCs depend on get an exception if bad values are detected
        if info.index > 0x4000:
            raise ValueError("Index value is invalid")

        return info

    def get_next_packet_info(self, info):
        """
        Iterate over the packet info list stored in the testcase
        Start iteration with first element if info is None
        Continue based on index in info if info is specified

        :param info: info or None
        :returns: next info in list or None if no more infos
        """
        if info is None:
            next_index = 0
        else:
            next_index = info.index + 1
        if next_index == len(self._packet_infos):
            return None
        else:
            return self._packet_infos[next_index]

    def get_next_packet_info_for_interface(self, src_index, info):
        """
        Search the packet info list for the next packet info with same source
        interface index

        :param src_index: source interface index to search for
        :param info: packet info - where to start the search
        :returns: packet info or None

        """
        while True:
            info = self.get_next_packet_info(info)
            if info is None:
                return None
            if info.src == src_index:
                return info

    def get_next_packet_info_for_interface2(self, src_index, dst_index, info):
        """
        Search the packet info list for the next packet info with same source
        and destination interface indexes

        :param src_index: source interface index to search for
        :param dst_index: destination interface index to search for
        :param info: packet info - where to start the search
        :returns: packet info or None

        """
        while True:
            info = self.get_next_packet_info_for_interface(src_index, info)
            if info is None:
                return None
            if info.dst == dst_index:
                return info

    def assert_equal(self, real_value, expected_value, name_or_class=None):
        if name_or_class is None:
            self.assertEqual(real_value, expected_value)
            return
        try:
            msg = "Invalid %s: %d('%s') does not match expected value %d('%s')"
            msg = msg % (
                getdoc(name_or_class).strip(),
                real_value,
                str(name_or_class(real_value)),
                expected_value,
                str(name_or_class(expected_value)),
            )
        except Exception:
            msg = "Invalid %s: %s does not match expected value %s" % (
                name_or_class,
                real_value,
                expected_value,
            )

        self.assertEqual(real_value, expected_value, msg)

    def assert_in_range(self, real_value, expected_min, expected_max, name=None):
        if name is None:
            msg = None
        else:
            msg = "Invalid %s: %s out of range <%s,%s>" % (
                name,
                real_value,
                expected_min,
                expected_max,
            )
        self.assertTrue(expected_min <= real_value <= expected_max, msg)

    def assert_packet_checksums_valid(self, packet, ignore_zero_udp_checksums=True):
        received = packet.__class__(scapy.compat.raw(packet))
        udp_layers = ["UDP", "UDPerror"]
        checksum_fields = ["cksum", "chksum"]
        checksums = []
        counter = 0
        temp = received.__class__(scapy.compat.raw(received))
        while True:
            layer = temp.getlayer(counter)
            if layer:
                layer = layer.copy()
                layer.remove_payload()
                for cf in checksum_fields:
                    if hasattr(layer, cf):
                        if (
                            ignore_zero_udp_checksums
                            and 0 == getattr(layer, cf)
                            and layer.name in udp_layers
                        ):
                            continue
                        delattr(temp.getlayer(counter), cf)
                        checksums.append((counter, cf))
            else:
                break
            counter = counter + 1
        if 0 == len(checksums):
            return
        temp = temp.__class__(scapy.compat.raw(temp))
        for layer, cf in checksums:
            calc_sum = getattr(temp[layer], cf)
            self.assert_equal(
                getattr(received[layer], cf),
                calc_sum,
                "packet checksum on layer #%d: %s" % (layer, temp[layer].name),
            )
            self.logger.debug(
                "Checksum field `%s` on `%s` layer has correct value `%s`"
                % (cf, temp[layer].name, calc_sum)
            )

    def assert_checksum_valid(
        self, received_packet, layer, field_name="chksum", ignore_zero_checksum=False
    ):
        """Check checksum of received packet on given layer"""
        received_packet_checksum = getattr(received_packet[layer], field_name)
        if ignore_zero_checksum and 0 == received_packet_checksum:
            return
        recalculated = received_packet.__class__(scapy.compat.raw(received_packet))
        delattr(recalculated[layer], field_name)
        recalculated = recalculated.__class__(scapy.compat.raw(recalculated))
        self.assert_equal(
            received_packet_checksum,
            getattr(recalculated[layer], field_name),
            "packet checksum on layer: %s" % layer,
        )

    def assert_ip_checksum_valid(self, received_packet, ignore_zero_checksum=False):
        self.assert_checksum_valid(
            received_packet, "IP", ignore_zero_checksum=ignore_zero_checksum
        )

    def assert_tcp_checksum_valid(self, received_packet, ignore_zero_checksum=False):
        self.assert_checksum_valid(
            received_packet, "TCP", ignore_zero_checksum=ignore_zero_checksum
        )

    def assert_udp_checksum_valid(self, received_packet, ignore_zero_checksum=True):
        self.assert_checksum_valid(
            received_packet, "UDP", ignore_zero_checksum=ignore_zero_checksum
        )

    def assert_embedded_icmp_checksum_valid(self, received_packet):
        if received_packet.haslayer(IPerror):
            self.assert_checksum_valid(received_packet, "IPerror")
        if received_packet.haslayer(TCPerror):
            self.assert_checksum_valid(received_packet, "TCPerror")
        if received_packet.haslayer(UDPerror):
            self.assert_checksum_valid(
                received_packet, "UDPerror", ignore_zero_checksum=True
            )
        if received_packet.haslayer(ICMPerror):
            self.assert_checksum_valid(received_packet, "ICMPerror")

    def assert_icmp_checksum_valid(self, received_packet):
        self.assert_checksum_valid(received_packet, "ICMP")
        self.assert_embedded_icmp_checksum_valid(received_packet)

    def assert_icmpv6_checksum_valid(self, pkt):
        if pkt.haslayer(ICMPv6DestUnreach):
            self.assert_checksum_valid(pkt, "ICMPv6DestUnreach", "cksum")
            self.assert_embedded_icmp_checksum_valid(pkt)
        if pkt.haslayer(ICMPv6EchoRequest):
            self.assert_checksum_valid(pkt, "ICMPv6EchoRequest", "cksum")
        if pkt.haslayer(ICMPv6EchoReply):
            self.assert_checksum_valid(pkt, "ICMPv6EchoReply", "cksum")

    def get_counter(self, counter):
        if counter.startswith("/"):
            counter_value = self.statistics.get_counter(counter)
        else:
            counters = self.vapi.cli("sh errors").split("\n")
            counter_value = 0
            for i in range(1, len(counters) - 1):
                results = counters[i].split()
                if results[1] == counter:
                    counter_value = int(results[0])
                    break
        return counter_value

    def assert_counter_equal(self, counter, expected_value, thread=None, index=0):
        c = self.get_counter(counter)
        if thread is not None:
            c = c[thread][index]
        else:
            c = sum(x[index] for x in c)
        self.assert_equal(c, expected_value, "counter `%s'" % counter)

    def assert_packet_counter_equal(self, counter, expected_value):
        counter_value = self.get_counter(counter)
        self.assert_equal(
            counter_value, expected_value, "packet counter `%s'" % counter
        )

    def assert_error_counter_equal(self, counter, expected_value):
        counter_value = self.statistics[counter].sum()
        self.assert_equal(counter_value, expected_value, "error counter `%s'" % counter)

    @classmethod
    def sleep(cls, timeout, remark=None):

        # /* Allow sleep(0) to maintain win32 semantics, and as decreed
        #  * by Guido, only the main thread can be interrupted.
        # */
        # https://github.com/python/cpython/blob/6673decfa0fb078f60587f5cb5e98460eea137c2/Modules/timemodule.c#L1892  # noqa
        if timeout == 0:
            # yield quantum
            if hasattr(os, "sched_yield"):
                os.sched_yield()
            else:
                time.sleep(0)
            return

        cls.logger.debug("Starting sleep for %es (%s)", timeout, remark)
        before = time.time()
        time.sleep(timeout)
        after = time.time()
        if after - before > 2 * timeout:
            cls.logger.error(
                "unexpected self.sleep() result - slept for %es instead of ~%es!",
                after - before,
                timeout,
            )

        cls.logger.debug(
            "Finished sleep (%s) - slept %es (wanted %es)",
            remark,
            after - before,
            timeout,
        )

    def virtual_sleep(self, timeout, remark=None):
        self.logger.debug("Moving VPP time by %s (%s)", timeout, remark)
        self.vapi.cli("set clock adjust %s" % timeout)

    def pg_send(self, intf, pkts, worker=None, trace=True):
        intf.add_stream(pkts, worker=worker)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start(trace=trace)

    def snapshot_stats(self, stats_diff):
        """Return snapshot of interesting stats based on diff dictionary."""
        stats_snapshot = {}
        for sw_if_index in stats_diff:
            for counter in stats_diff[sw_if_index]:
                stats_snapshot[counter] = self.statistics[counter]
        self.logger.debug(f"Took statistics stats_snapshot: {stats_snapshot}")
        return stats_snapshot

    def compare_stats_with_snapshot(self, stats_diff, stats_snapshot):
        """Assert appropriate difference between current stats and snapshot."""
        for sw_if_index in stats_diff:
            for cntr, diff in stats_diff[sw_if_index].items():
                if sw_if_index == "err":
                    self.assert_equal(
                        self.statistics[cntr].sum(),
                        stats_snapshot[cntr].sum() + diff,
                        f"'{cntr}' counter value (previous value: "
                        f"{stats_snapshot[cntr].sum()}, "
                        f"expected diff: {diff})",
                    )
                else:
                    try:
                        self.assert_equal(
                            self.statistics[cntr][:, sw_if_index].sum(),
                            stats_snapshot[cntr][:, sw_if_index].sum() + diff,
                            f"'{cntr}' counter value (previous value: "
                            f"{stats_snapshot[cntr][:, sw_if_index].sum()}, "
                            f"expected diff: {diff})",
                        )
                    except IndexError:
                        # if diff is 0, then this most probably a case where
                        # test declares multiple interfaces but traffic hasn't
                        # passed through this one yet - which means the counter
                        # value is 0 and can be ignored
                        if 0 != diff:
                            raise

    def send_and_assert_no_replies(
        self, intf, pkts, remark="", timeout=None, stats_diff=None, trace=True, msg=None
    ):
        if stats_diff:
            stats_snapshot = self.snapshot_stats(stats_diff)

        self.pg_send(intf, pkts)

        try:
            if not timeout:
                timeout = 1
            for i in self.pg_interfaces:
                i.assert_nothing_captured(timeout=timeout, remark=remark)
                timeout = 0.1
        finally:
            if trace:
                if msg:
                    self.logger.debug(f"send_and_assert_no_replies: {msg}")
                self.logger.debug(self.vapi.cli("show trace"))

        if stats_diff:
            self.compare_stats_with_snapshot(stats_diff, stats_snapshot)

    def send_and_expect(
        self,
        intf,
        pkts,
        output,
        n_rx=None,
        worker=None,
        trace=True,
        msg=None,
        stats_diff=None,
    ):
        if stats_diff:
            stats_snapshot = self.snapshot_stats(stats_diff)

        if not n_rx:
            n_rx = 1 if isinstance(pkts, Packet) else len(pkts)
        self.pg_send(intf, pkts, worker=worker, trace=trace)
        rx = output.get_capture(n_rx)
        if trace:
            if msg:
                self.logger.debug(f"send_and_expect: {msg}")
            self.logger.debug(self.vapi.cli("show trace"))

        if stats_diff:
            self.compare_stats_with_snapshot(stats_diff, stats_snapshot)

        return rx

    def send_and_expect_load_balancing(
        self, input, pkts, outputs, worker=None, trace=True
    ):
        self.pg_send(input, pkts, worker=worker, trace=trace)
        rxs = []
        for oo in outputs:
            rx = oo._get_capture(1)
            self.assertNotEqual(0, len(rx))
            rxs.append(rx)
        if trace:
            self.logger.debug(self.vapi.cli("show trace"))
        return rxs

    def send_and_expect_some(self, intf, pkts, output, worker=None, trace=True):
        self.pg_send(intf, pkts, worker=worker, trace=trace)
        rx = output._get_capture(1)
        if trace:
            self.logger.debug(self.vapi.cli("show trace"))
        self.assertTrue(len(rx) > 0)
        self.assertTrue(len(rx) < len(pkts))
        return rx

    def send_and_expect_only(self, intf, pkts, output, timeout=None, stats_diff=None):
        if stats_diff:
            stats_snapshot = self.snapshot_stats(stats_diff)

        self.pg_send(intf, pkts)
        rx = output.get_capture(len(pkts))
        outputs = [output]
        if not timeout:
            timeout = 1
        for i in self.pg_interfaces:
            if i not in outputs:
                i.assert_nothing_captured(timeout=timeout)
                timeout = 0.1

        if stats_diff:
            self.compare_stats_with_snapshot(stats_diff, stats_snapshot)

        return rx


def get_testcase_doc_name(test):
    return getdoc(test.__class__).splitlines()[0]


def get_test_description(descriptions, test):
    short_description = test.shortDescription()
    if descriptions and short_description:
        return short_description
    else:
        return str(test)


class TestCaseInfo(object):
    def __init__(self, logger, tempdir, vpp_pid, vpp_bin_path):
        self.logger = logger
        self.tempdir = tempdir
        self.vpp_pid = vpp_pid
        self.vpp_bin_path = vpp_bin_path
        self.core_crash_test = None


class VppTestResult(unittest.TestResult):
    """
    @property result_string
     String variable to store the test case result string.
    @property errors
     List variable containing 2-tuples of TestCase instances and strings
     holding formatted tracebacks. Each tuple represents a test which
     raised an unexpected exception.
    @property failures
     List variable containing 2-tuples of TestCase instances and strings
     holding formatted tracebacks. Each tuple represents a test where
     a failure was explicitly signalled using the TestCase.assert*()
     methods.
    """

    failed_test_cases_info = set()
    core_crash_test_cases_info = set()
    current_test_case_info = None

    def __init__(self, stream=None, descriptions=None, verbosity=None, runner=None):
        """
        :param stream File descriptor to store where to report test results.
            Set to the standard error stream by default.
        :param descriptions Boolean variable to store information if to use
            test case descriptions.
        :param verbosity Integer variable to store required verbosity level.
        """
        super(VppTestResult, self).__init__(stream, descriptions, verbosity)
        self.stream = stream
        self.descriptions = descriptions
        self.verbosity = verbosity
        self.result_string = None
        self.runner = runner
        self.printed = []

    def addSuccess(self, test):
        """
        Record a test succeeded result

        :param test:

        """
        if self.current_test_case_info:
            self.current_test_case_info.logger.debug(
                "--- addSuccess() %s.%s(%s) called"
                % (test.__class__.__name__, test._testMethodName, test._testMethodDoc)
            )
        unittest.TestResult.addSuccess(self, test)
        self.result_string = colorize("OK", GREEN)

        self.send_result_through_pipe(test, PASS)

    def addSkip(self, test, reason):
        """
        Record a test skipped.

        :param test:
        :param reason:

        """
        if self.current_test_case_info:
            self.current_test_case_info.logger.debug(
                "--- addSkip() %s.%s(%s) called, reason is %s"
                % (
                    test.__class__.__name__,
                    test._testMethodName,
                    test._testMethodDoc,
                    reason,
                )
            )
        unittest.TestResult.addSkip(self, test, reason)
        self.result_string = colorize("SKIP", YELLOW)

        if reason == "not enough cpus":
            self.send_result_through_pipe(test, SKIP_CPU_SHORTAGE)
        else:
            self.send_result_through_pipe(test, SKIP)

    def symlink_failed(self):
        if self.current_test_case_info:
            try:
                failed_dir = config.failed_dir
                link_path = os.path.join(
                    failed_dir,
                    "%s-FAILED" % os.path.basename(self.current_test_case_info.tempdir),
                )

                self.current_test_case_info.logger.debug(
                    "creating a link to the failed test"
                )
                self.current_test_case_info.logger.debug(
                    "os.symlink(%s, %s)"
                    % (self.current_test_case_info.tempdir, link_path)
                )
                if os.path.exists(link_path):
                    self.current_test_case_info.logger.debug("symlink already exists")
                else:
                    os.symlink(self.current_test_case_info.tempdir, link_path)

            except Exception as e:
                self.current_test_case_info.logger.error(e)

    def send_result_through_pipe(self, test, result):
        if hasattr(self, "test_framework_result_pipe"):
            pipe = self.test_framework_result_pipe
            if pipe:
                pipe.send((test.id(), result))

    def log_error(self, test, err, fn_name):
        if self.current_test_case_info:
            if isinstance(test, unittest.suite._ErrorHolder):
                test_name = test.description
            else:
                test_name = "%s.%s(%s)" % (
                    test.__class__.__name__,
                    test._testMethodName,
                    test._testMethodDoc,
                )
            self.current_test_case_info.logger.debug(
                "--- %s() %s called, err is %s" % (fn_name, test_name, err)
            )
            self.current_test_case_info.logger.debug(
                "formatted exception is:\n%s" % "".join(format_exception(*err))
            )

    def add_error(self, test, err, unittest_fn, error_type):
        if error_type == FAIL:
            self.log_error(test, err, "addFailure")
            error_type_str = colorize("FAIL", RED)
        elif error_type == ERROR:
            self.log_error(test, err, "addError")
            error_type_str = colorize("ERROR", RED)
        else:
            raise Exception(
                "Error type %s cannot be used to record an "
                "error or a failure" % error_type
            )

        unittest_fn(self, test, err)
        if self.current_test_case_info:
            self.result_string = "%s [ temp dir used by test case: %s ]" % (
                error_type_str,
                self.current_test_case_info.tempdir,
            )
            self.symlink_failed()
            self.failed_test_cases_info.add(self.current_test_case_info)
            if is_core_present(self.current_test_case_info.tempdir):
                if not self.current_test_case_info.core_crash_test:
                    if isinstance(test, unittest.suite._ErrorHolder):
                        test_name = str(test)
                    else:
                        test_name = "'{!s}' ({!s})".format(
                            get_testcase_doc_name(test), test.id()
                        )
                    self.current_test_case_info.core_crash_test = test_name
                self.core_crash_test_cases_info.add(self.current_test_case_info)
        else:
            self.result_string = "%s [no temp dir]" % error_type_str

        self.send_result_through_pipe(test, error_type)

    def addFailure(self, test, err):
        """
        Record a test failed result

        :param test:
        :param err: error message

        """
        self.add_error(test, err, unittest.TestResult.addFailure, FAIL)

    def addError(self, test, err):
        """
        Record a test error result

        :param test:
        :param err: error message

        """
        self.add_error(test, err, unittest.TestResult.addError, ERROR)

    def getDescription(self, test):
        """
        Get test description

        :param test:
        :returns: test description

        """
        return get_test_description(self.descriptions, test)

    def startTest(self, test):
        """
        Start a test

        :param test:

        """

        def print_header(test):
            if test.__class__ in self.printed:
                return

            test_doc = getdoc(test)
            if not test_doc:
                raise Exception("No doc string for test '%s'" % test.id())

            test_title = test_doc.splitlines()[0].rstrip()
            test_title = colorize(test_title, GREEN)
            if test.is_tagged_run_solo():
                test_title = colorize(f"SOLO RUN: {test_title}", YELLOW)

            # This block may overwrite the colorized title above,
            # but we want this to stand out and be fixed
            if test.has_tag(TestCaseTag.FIXME_VPP_WORKERS):
                test_title = colorize(f"FIXME with VPP workers: {test_title}", RED)

            if test.has_tag(TestCaseTag.FIXME_ASAN):
                test_title = colorize(f"FIXME with ASAN: {test_title}", RED)
                test.skip_fixme_asan()

            if hasattr(test, "vpp_worker_count"):
                if test.vpp_worker_count == 0:
                    test_title += " [main thread only]"
                elif test.vpp_worker_count == 1:
                    test_title += " [1 worker thread]"
                else:
                    test_title += f" [{test.vpp_worker_count} worker threads]"

            if test.__class__.skipped_due_to_cpu_lack:
                test_title = colorize(
                    f"{test_title} [skipped - not enough cpus, "
                    f"required={test.__class__.get_cpus_required()}, "
                    f"available={max_vpp_cpus}]",
                    YELLOW,
                )

            print(double_line_delim)
            print(test_title)
            print(double_line_delim)
            self.printed.append(test.__class__)

        print_header(test)
        self.start_test = time.time()
        unittest.TestResult.startTest(self, test)
        if self.verbosity > 0:
            self.stream.writeln("Starting " + self.getDescription(test) + " ...")
            self.stream.writeln(single_line_delim)

    def stopTest(self, test):
        """
        Called when the given test has been run

        :param test:

        """
        unittest.TestResult.stopTest(self, test)

        if self.verbosity > 0:
            self.stream.writeln(single_line_delim)
            self.stream.writeln(
                "%-73s%s" % (self.getDescription(test), self.result_string)
            )
            self.stream.writeln(single_line_delim)
        else:
            self.stream.writeln(
                "%-68s %4.2f %s"
                % (
                    self.getDescription(test),
                    time.time() - self.start_test,
                    self.result_string,
                )
            )

        self.send_result_through_pipe(test, TEST_RUN)

    def printErrors(self):
        """
        Print errors from running the test case
        """
        if len(self.errors) > 0 or len(self.failures) > 0:
            self.stream.writeln()
            self.printErrorList("ERROR", self.errors)
            self.printErrorList("FAIL", self.failures)

        # ^^ that is the last output from unittest before summary
        if not self.runner.print_summary:
            devnull = unittest.runner._WritelnDecorator(open(os.devnull, "w"))
            self.stream = devnull
            self.runner.stream = devnull

    def printErrorList(self, flavour, errors):
        """
        Print error list to the output stream together with error type
        and test case description.

        :param flavour: error type
        :param errors: iterable errors

        """
        for test, err in errors:
            self.stream.writeln(double_line_delim)
            self.stream.writeln("%s: %s" % (flavour, self.getDescription(test)))
            self.stream.writeln(single_line_delim)
            self.stream.writeln("%s" % err)


class VppTestRunner(unittest.TextTestRunner):
    """
    A basic test runner implementation which prints results to standard error.
    """

    @property
    def resultclass(self):
        """Class maintaining the results of the tests"""
        return VppTestResult

    def __init__(
        self,
        keep_alive_pipe=None,
        descriptions=True,
        verbosity=1,
        result_pipe=None,
        failfast=False,
        buffer=False,
        resultclass=None,
        print_summary=True,
        **kwargs,
    ):
        # ignore stream setting here, use hard-coded stdout to be in sync
        # with prints from VppTestCase methods ...
        super(VppTestRunner, self).__init__(
            sys.stdout, descriptions, verbosity, failfast, buffer, resultclass, **kwargs
        )
        KeepAliveReporter.pipe = keep_alive_pipe

        self.orig_stream = self.stream
        self.resultclass.test_framework_result_pipe = result_pipe

        self.print_summary = print_summary

    def _makeResult(self):
        return self.resultclass(self.stream, self.descriptions, self.verbosity, self)

    def run(self, test):
        """
        Run the tests

        :param test:

        """
        faulthandler.enable()  # emit stack trace to stderr if killed by signal

        result = super(VppTestRunner, self).run(test)
        if not self.print_summary:
            self.stream = self.orig_stream
            result.stream = self.orig_stream
        return result


class Worker(Thread):
    def __init__(self, executable_args, logger, env=None, *args, **kwargs):
        super(Worker, self).__init__(*args, **kwargs)
        self.logger = logger
        self.args = executable_args
        if hasattr(self, "testcase") and self.testcase.debug_all:
            if self.testcase.debug_gdbserver:
                self.args = [
                    "/usr/bin/gdbserver",
                    "localhost:{port}".format(port=self.testcase.gdbserver_port),
                ] + args
            elif self.testcase.debug_gdb and hasattr(self, "wait_for_gdb"):
                self.args.append(self.wait_for_gdb)
        self.app_bin = executable_args[0]
        self.app_name = os.path.basename(self.app_bin)
        if hasattr(self, "role"):
            self.app_name += " {role}".format(role=self.role)
        self.process = None
        self.result = None
        env = {} if env is None else env
        self.env = copy.deepcopy(env)

    def wait_for_enter(self):
        if not hasattr(self, "testcase"):
            return
        if self.testcase.debug_all and self.testcase.debug_gdbserver:
            print()
            print(double_line_delim)
            print(
                "Spawned GDB Server for '{app}' with PID: {pid}".format(
                    app=self.app_name, pid=self.process.pid
                )
            )
        elif self.testcase.debug_all and self.testcase.debug_gdb:
            print()
            print(double_line_delim)
            print(
                "Spawned '{app}' with PID: {pid}".format(
                    app=self.app_name, pid=self.process.pid
                )
            )
        else:
            return
        print(single_line_delim)
        print("You can debug '{app}' using:".format(app=self.app_name))
        if self.testcase.debug_gdbserver:
            print(
                "sudo gdb "
                + self.app_bin
                + " -ex 'target remote localhost:{port}'".format(
                    port=self.testcase.gdbserver_port
                )
            )
            print(
                "Now is the time to attach gdb by running the above "
                "command, set up breakpoints etc., then resume from "
                "within gdb by issuing the 'continue' command"
            )
            self.testcase.gdbserver_port += 1
        elif self.testcase.debug_gdb:
            print(
                "sudo gdb "
                + self.app_bin
                + " -ex 'attach {pid}'".format(pid=self.process.pid)
            )
            print(
                "Now is the time to attach gdb by running the above "
                "command and set up breakpoints etc., then resume from"
                " within gdb by issuing the 'continue' command"
            )
        print(single_line_delim)
        input("Press ENTER to continue running the testcase...")

    def run(self):
        executable = self.args[0]
        if not os.path.exists(executable) or not os.access(
            executable, os.F_OK | os.X_OK
        ):
            # Exit code that means some system file did not exist,
            # could not be opened, or had some other kind of error.
            self.result = os.EX_OSFILE
            raise EnvironmentError(
                "executable '%s' is not found or executable." % executable
            )
        self.logger.debug(
            "Running executable '{app}': '{cmd}'".format(
                app=self.app_name, cmd=" ".join(self.args)
            )
        )
        env = os.environ.copy()
        env.update(self.env)
        env["CK_LOG_FILE_NAME"] = "-"
        self.process = subprocess.Popen(
            ["stdbuf", "-o0", "-e0"] + self.args,
            shell=False,
            env=env,
            preexec_fn=os.setpgrp,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.wait_for_enter()
        out, err = self.process.communicate()
        self.logger.debug("Finished running `{app}'".format(app=self.app_name))
        self.logger.info("Return code is `%s'" % self.process.returncode)
        self.logger.info(single_line_delim)
        self.logger.info(
            "Executable `{app}' wrote to stdout:".format(app=self.app_name)
        )
        self.logger.info(single_line_delim)
        self.logger.info(out.decode("utf-8"))
        self.logger.info(single_line_delim)
        self.logger.info(
            "Executable `{app}' wrote to stderr:".format(app=self.app_name)
        )
        self.logger.info(single_line_delim)
        self.logger.info(err.decode("utf-8"))
        self.logger.info(single_line_delim)
        self.result = self.process.returncode


if __name__ == "__main__":
    pass
