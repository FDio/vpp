""" debug utilities """

import os
import pexpect
import sys

from sanity_run_vpp import SanityTestCase
from shutil import rmtree
from config import available_cpus

gdb_path = '/usr/bin/gdb'


def spawn_gdb(binary_path, core_path):
    if os.path.isfile(gdb_path) and os.access(gdb_path, os.X_OK):
        # automatically attach gdb
        gdb_cmdline = "%s %s %s" % (gdb_path, binary_path, core_path)
        gdb = pexpect.spawn(gdb_cmdline)
        gdb.interact()
        try:
            gdb.terminate(True)
        except:
            pass
        if gdb.isalive():
            raise Exception("GDB refused to die...")
    else:
        sys.stderr.write("Debugger '%s' does not exist or is not "
                         "an executable..\n" % gdb_path)


def start_vpp_in_gdb():
    # here we use SanityTestCase as a dummy to inherit functionality,
    # but any test case class could be used ...
    SanityTestCase.set_debug_flags("attach")
    SanityTestCase.tempdir = SanityTestCase.get_tempdir()
    SanityTestCase.assign_cpus(
        available_cpus[:SanityTestCase.get_cpus_required()])
    SanityTestCase.setUpConstants()
    vpp_cmdline = SanityTestCase.vpp_cmdline
    print("Hacking cmdline to make VPP interactive.")
    vpp_cmdline.insert(vpp_cmdline.index("nodaemon"), "interactive")
    print("VPP cmdline is %s" % " ".join(vpp_cmdline))
    print("Running GDB.")

    if os.path.isfile(gdb_path) and os.access(gdb_path, os.X_OK):
        gdb_cmdline = "%s --args %s " % (gdb_path, " ".join(vpp_cmdline))
        print("GDB cmdline is %s" % gdb_cmdline)
        gdb = pexpect.spawn(gdb_cmdline)
        gdb.interact()
        try:
            gdb.terminate(True)
        except:
            pass
        if gdb.isalive():
            raise Exception("GDB refused to die...")
    else:
        sys.stderr.write("Debugger '%s' does not exist or is not "
                         "an executable..\n" % gdb_path)
