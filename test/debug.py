"""debug utilities"""

import os
import pexpect
import sys

from subprocess import run, PIPE, STDOUT, TimeoutExpired
from shutil import rmtree

gdb_path = "/usr/bin/gdb"


def log_core_backtrace(logger, binary_path, core_path, timeout=30):
    """Run gdb in batch mode against a core file and log the backtrace.

    Emits `thread apply all bt full` so the log alone is sufficient evidence
    for post-mortem analysis (frame args + locals for every thread).
    """
    if not (os.path.isfile(gdb_path) and os.access(gdb_path, os.X_OK)):
        logger.error("Cannot decode core: '%s' not available", gdb_path)
        return
    cmd = [
        gdb_path,
        "-batch",
        "-nx",
        "-ex",
        "set pagination off",
        "-ex",
        "set print pretty on",
        "-ex",
        "thread apply all bt full",
        binary_path,
        core_path,
    ]
    try:
        proc = run(cmd, stdout=PIPE, stderr=STDOUT, timeout=timeout)
    except TimeoutExpired:
        logger.error("gdb timed out after %ds decoding core %s", timeout, core_path)
        return
    except OSError as e:
        logger.error("Failed to spawn gdb to decode core: (%s) %s", e.errno, e.strerror)
        return
    logger.error("Decoded backtrace from %s (gdb rc=%d):", core_path, proc.returncode)
    for line in proc.stdout.decode(errors="replace").splitlines():
        logger.error("  %s", line)


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
        sys.stderr.write(
            "Debugger '%s' does not exist or is not an executable..\n" % gdb_path
        )


def start_vpp_in_gdb():
    from sanity_run_vpp import SanityTestCase
    from config import physical_cores

    # here we use SanityTestCase as a dummy to inherit functionality,
    # but any test case class could be used ...
    SanityTestCase.set_debug_flags("attach")
    SanityTestCase.tempdir = SanityTestCase.get_tempdir()
    SanityTestCase.assign_cores(physical_cores[: SanityTestCase.get_cores_required()])
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
        sys.stderr.write(
            "Debugger '%s' does not exist or is not an executable..\n" % gdb_path
        )
