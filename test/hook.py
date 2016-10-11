import signal
import os
import pexpect
from logging import *


class Hook(object):
    """
    Generic hooks before/after API/CLI calls
    """

    def before_api(self, api_name, api_args):
        """
        Function called before API call
        Emit a debug message describing the API name and arguments

        @param api_name: name of the API
        @param api_args: tuple containing the API arguments
        """
        debug("API: %s (%s)" % (api_name, api_args))

    def after_api(self, api_name, api_args):
        """
        Function called after API call

        @param api_name: name of the API
        @param api_args: tuple containing the API arguments
        """
        pass

    def before_cli(self, cli):
        """
        Function called before CLI call
        Emit a debug message describing the CLI

        @param cli: CLI string
        """
        debug("CLI: %s" % (cli))

    def after_cli(self, cli):
        """
        Function called after CLI call
        """
        pass


class VppDiedError(Exception):
    pass


class PollHook(Hook):
    """ Hook which checks if the vpp subprocess is alive """

    def __init__(self, testcase):
        self.vpp_dead = False
        self.testcase = testcase

    def spawn_gdb(self, gdb_path, core_path):
        gdb_cmdline = gdb_path + ' ' + self.testcase.vpp_bin + ' ' + core_path
        gdb = pexpect.spawn(gdb_cmdline)
        gdb.interact()
        try:
            gdb.terminate(True)
        except:
            pass
        if gdb.isalive():
            raise Exception("GDB refused to die...")

    def on_crash(self, core_path):
        if self.testcase.interactive:
            gdb_path = '/usr/bin/gdb'
            if os.path.isfile(gdb_path) and os.access(gdb_path, os.X_OK):
                # automatically attach gdb
                self.spawn_gdb(gdb_path, core_path)
                return
            else:
                error("Debugger '%s' does not exist or is not an executable.." %
                      gdb_path)

        critical('core file present, debug with: gdb ' +
                 self.testcase.vpp_bin + ' ' + core_path)

    def poll_vpp(self):
        """
        Poll the vpp status and throw an exception if it's not running
        :raises VppDiedError: exception if VPP is not running anymore
        """
        if self.vpp_dead:
            # already dead, nothing to do
            return

        self.testcase.vpp.poll()
        if self.testcase.vpp.returncode is not None:
            signaldict = dict(
                (k, v) for v, k in reversed(sorted(signal.__dict__.items()))
                if v.startswith('SIG') and not v.startswith('SIG_'))
            msg = "VPP subprocess died unexpectedly with returncode %d [%s]" % (
                self.testcase.vpp.returncode,
                signaldict[abs(self.testcase.vpp.returncode)])
            critical(msg)
            core_path = self.testcase.tempdir + '/core'
            if os.path.isfile(core_path):
                self.on_crash(core_path)
            self.testcase.vpp_dead = True
            raise VppDiedError(msg)

    def after_api(self, api_name, api_args):
        """
        Check if VPP died after executing an API

        :param api_name: name of the API
        :param api_args: tuple containing the API arguments
        :raises VppDiedError: exception if VPP is not running anymore

        """
        super(PollHook, self).after_api(api_name, api_args)
        self.poll_vpp()

    def after_cli(self, cli):
        """
        Check if VPP died after executing a CLI

        :param cli: CLI string
        :raises Exception: exception if VPP is not running anymore

        """
        super(PollHook, self).after_cli(cli)
        self.poll_vpp()
